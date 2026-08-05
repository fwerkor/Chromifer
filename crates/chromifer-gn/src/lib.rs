#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use chromifer_manifest::{
    Boundary, CompatibilityGate, Dependency, InventoryMetadata, Manifest, MigrationState, Module,
    Project, Target, ValidationErrors,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GnProject {
    pub build_settings: GnBuildSettings,
    pub targets: BTreeMap<String, GnTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GnBuildSettings {
    #[serde(default)]
    pub root_path: String,
    pub build_dir: String,
    pub default_toolchain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GnTarget {
    #[serde(rename = "type")]
    pub target_type: String,
    #[serde(default)]
    pub toolchain: String,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub deps: Vec<String>,
    #[serde(default, alias = "test_only")]
    pub testonly: bool,
    #[serde(default)]
    pub crate_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOptions {
    pub project_name: String,
    pub upstream: String,
    pub baseline: String,
    pub roots: Vec<String>,
    pub include_all_toolchains: bool,
    pub include_testonly: bool,
    pub include_meta_targets: bool,
    pub infer_state: bool,
    pub gate: Option<GateOptions>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateOptions {
    pub id: String,
    pub command: String,
    pub target_id: String,
    pub target_description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportSummary {
    pub total_targets: usize,
    pub selected_targets: usize,
    pub imported_modules: usize,
    pub skipped_meta_targets: usize,
    pub skipped_testonly_targets: usize,
    pub skipped_other_toolchain_targets: usize,
    pub omitted_dependencies: Vec<OmittedDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OmittedDependency {
    pub target: String,
    pub dependency: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportOutput {
    pub manifest: Manifest,
    pub summary: ImportSummary,
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("failed to read GN project JSON `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse GN project JSON `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("GN label `{0}` is not present in the exported target graph")]
    UnknownLabel(String),
    #[error("GN label `{0}` resolves to more than one exported target")]
    AmbiguousLabel(String),
    #[error("root target `{label}` is excluded by {reason}")]
    ExcludedRoot { label: String, reason: &'static str },
    #[error("target `{target}` references dependency `{dependency}` missing from the GN export")]
    UnknownDependency { target: String, dependency: String },
    #[error(
        "state inference produced bridged or Rust-owned modules, but no compatibility gate was supplied"
    )]
    MissingGateForInferredState,
    #[error(transparent)]
    ManifestValidation(#[from] ValidationErrors),
}

impl GnProject {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ImportError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let source = fs::read_to_string(path).map_err(|source| ImportError::Read {
            path: display.clone(),
            source,
        })?;
        serde_json::from_str(&source).map_err(|source| ImportError::Parse {
            path: display,
            source,
        })
    }
}

pub fn import_gn_file(
    path: impl AsRef<Path>,
    options: &ImportOptions,
) -> Result<ImportOutput, ImportError> {
    let project = GnProject::load(path)?;
    import_gn_project(&project, options)
}

pub fn import_gn_project(
    project: &GnProject,
    options: &ImportOptions,
) -> Result<ImportOutput, ImportError> {
    let aliases = build_aliases(project);
    let mut eligible = BTreeSet::new();
    let mut skipped_testonly_targets = 0;
    let mut skipped_other_toolchain_targets = 0;

    for (label, target) in &project.targets {
        if !options.include_all_toolchains && !is_default_toolchain_target(project, label, target) {
            skipped_other_toolchain_targets += 1;
        } else if !options.include_testonly && target.testonly {
            skipped_testonly_targets += 1;
        } else {
            eligible.insert(label.clone());
        }
    }

    let selected = if options.roots.is_empty() {
        eligible.clone()
    } else {
        select_root_closure(project, options, &aliases, &eligible)?
    };

    let omitted_dependencies = collect_omitted_dependencies(project, &aliases, &selected)?;
    let imported: BTreeSet<_> = selected
        .iter()
        .filter(|label| options.include_meta_targets || is_source_target(&project.targets[*label]))
        .cloned()
        .collect();

    let skipped_meta_targets = selected.len() - imported.len();
    let ids = assign_module_ids(project, &imported);
    let states: BTreeMap<_, _> = imported
        .iter()
        .map(|label| {
            let state = if options.infer_state {
                infer_state(&project.targets[label])
            } else {
                MigrationState::LegacyCpp
            };
            (label.clone(), state)
        })
        .collect();

    if options.infer_state
        && options.gate.is_none()
        && states
            .values()
            .any(|state| *state != MigrationState::LegacyCpp)
    {
        return Err(ImportError::MissingGateForInferredState);
    }

    let mut modules = Vec::with_capacity(imported.len());
    for label in &imported {
        let target = &project.targets[label];
        let mut effective_dependencies = BTreeSet::new();
        let mut visited_meta = BTreeSet::new();
        for dependency in &target.deps {
            let dependency = resolve_dependency(project, &aliases, label, dependency)?;
            collect_effective_dependencies(
                project,
                &aliases,
                &selected,
                &imported,
                &dependency,
                &mut visited_meta,
                &mut effective_dependencies,
            )?;
        }
        effective_dependencies.remove(label);

        let state = states[label];
        let mut dependencies: Vec<_> = effective_dependencies
            .into_iter()
            .map(|dependency_label| Dependency {
                module: ids[&dependency_label].clone(),
                boundary: infer_boundary(state, states[&dependency_label], options.infer_state),
                evidence: Vec::new(),
                reviews: Vec::new(),
            })
            .collect();
        dependencies.sort_by(|left, right| left.module.cmp(&right.module));

        modules.push(Module {
            id: ids[label].clone(),
            path: label_path(label),
            owner: inferred_owner(label),
            ownership: None,
            source_label: Some(label.clone()),
            source_type: Some(target.target_type.clone()),
            sources: normalized_sources(label, target),
            state,
            gates: options
                .gate
                .as_ref()
                .map(|gate| vec![gate.id.clone()])
                .unwrap_or_default(),
            reviews: Vec::new(),
            dependencies,
        });
    }
    modules.sort_by(|left, right| left.id.cmp(&right.id));

    let (targets, gates) = options.gate.as_ref().map_or_else(
        || (Vec::new(), Vec::new()),
        |gate| {
            (
                vec![Target {
                    id: gate.target_id.clone(),
                    description: gate.target_description.clone(),
                    required: true,
                }],
                vec![CompatibilityGate {
                    id: gate.id.clone(),
                    command: gate.command.clone(),
                    targets: vec![gate.target_id.clone()],
                }],
            )
        },
    );

    let manifest = Manifest {
        schema_version: chromifer_manifest::SUPPORTED_SCHEMA_VERSION,
        project: Project {
            name: options.project_name.clone(),
            upstream: options.upstream.clone(),
            baseline: options.baseline.clone(),
        },
        inventory: Some(InventoryMetadata {
            source_format: "gn-project-json".into(),
            build_dir: project.build_settings.build_dir.clone(),
            default_toolchain: project.build_settings.default_toolchain.clone(),
            roots: options.roots.clone(),
            include_all_toolchains: options.include_all_toolchains,
            include_testonly: options.include_testonly,
            include_meta_targets: options.include_meta_targets,
            infer_state: options.infer_state,
            omitted_dependency_count: omitted_dependencies.len(),
        }),
        targets,
        gates,
        modules,
    };
    manifest.validate()?;

    Ok(ImportOutput {
        summary: ImportSummary {
            total_targets: project.targets.len(),
            selected_targets: selected.len(),
            imported_modules: imported.len(),
            skipped_meta_targets,
            skipped_testonly_targets,
            skipped_other_toolchain_targets,
            omitted_dependencies,
        },
        manifest,
    })
}

fn build_aliases(project: &GnProject) -> BTreeMap<String, Option<String>> {
    let mut aliases = BTreeMap::new();
    for (label, target) in &project.targets {
        insert_alias(&mut aliases, label.clone(), label);
        if is_default_toolchain_target(project, label, target) {
            let (base, _) = split_toolchain(label);
            insert_alias(&mut aliases, base.to_owned(), label);
            insert_alias(
                &mut aliases,
                format!("{base}({})", project.build_settings.default_toolchain),
                label,
            );
        }
    }
    aliases
}

fn insert_alias(aliases: &mut BTreeMap<String, Option<String>>, alias: String, label: &str) {
    match aliases.get_mut(&alias) {
        Some(slot) if slot.as_deref() != Some(label) => *slot = None,
        Some(_) => {}
        None => {
            aliases.insert(alias, Some(label.to_owned()));
        }
    }
}

fn resolve_label(
    project: &GnProject,
    aliases: &BTreeMap<String, Option<String>>,
    label: &str,
) -> Result<String, ImportError> {
    if project.targets.contains_key(label) {
        return Ok(label.to_owned());
    }
    match aliases.get(label) {
        Some(Some(resolved)) => Ok(resolved.clone()),
        Some(None) => Err(ImportError::AmbiguousLabel(label.to_owned())),
        None => Err(ImportError::UnknownLabel(label.to_owned())),
    }
}

fn resolve_dependency(
    project: &GnProject,
    aliases: &BTreeMap<String, Option<String>>,
    target: &str,
    dependency: &str,
) -> Result<String, ImportError> {
    resolve_label(project, aliases, dependency).map_err(|error| match error {
        ImportError::UnknownLabel(_) => ImportError::UnknownDependency {
            target: target.to_owned(),
            dependency: dependency.to_owned(),
        },
        other => other,
    })
}

fn select_root_closure(
    project: &GnProject,
    options: &ImportOptions,
    aliases: &BTreeMap<String, Option<String>>,
    eligible: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ImportError> {
    let mut pending = Vec::new();
    for root in &options.roots {
        let resolved = resolve_label(project, aliases, root)?;
        if !eligible.contains(&resolved) {
            let target = &project.targets[&resolved];
            let reason = if !options.include_all_toolchains
                && !is_default_toolchain_target(project, &resolved, target)
            {
                "the default-toolchain-only policy"
            } else {
                "the test-only target policy"
            };
            return Err(ImportError::ExcludedRoot {
                label: root.clone(),
                reason,
            });
        }
        pending.push(resolved);
    }

    let mut selected = BTreeSet::new();
    while let Some(label) = pending.pop() {
        if !selected.insert(label.clone()) {
            continue;
        }
        for dependency in &project.targets[&label].deps {
            let dependency = resolve_dependency(project, aliases, &label, dependency)?;
            if eligible.contains(&dependency) {
                pending.push(dependency);
            }
        }
    }
    Ok(selected)
}

fn collect_omitted_dependencies(
    project: &GnProject,
    aliases: &BTreeMap<String, Option<String>>,
    selected: &BTreeSet<String>,
) -> Result<Vec<OmittedDependency>, ImportError> {
    let mut omitted = Vec::new();
    for label in selected {
        for dependency in &project.targets[label].deps {
            let dependency = resolve_dependency(project, aliases, label, dependency)?;
            if !selected.contains(&dependency) {
                let target = &project.targets[&dependency];
                omitted.push(OmittedDependency {
                    target: label.clone(),
                    dependency,
                    reason: if target.testonly {
                        "test_only"
                    } else {
                        "other_toolchain"
                    },
                });
            }
        }
    }
    Ok(omitted)
}

#[allow(clippy::too_many_arguments)]
fn collect_effective_dependencies(
    project: &GnProject,
    aliases: &BTreeMap<String, Option<String>>,
    selected: &BTreeSet<String>,
    imported: &BTreeSet<String>,
    label: &str,
    visited_meta: &mut BTreeSet<String>,
    result: &mut BTreeSet<String>,
) -> Result<(), ImportError> {
    if !selected.contains(label) {
        return Ok(());
    }
    if imported.contains(label) {
        result.insert(label.to_owned());
        return Ok(());
    }
    if !visited_meta.insert(label.to_owned()) {
        return Ok(());
    }

    for dependency in &project.targets[label].deps {
        let dependency = resolve_dependency(project, aliases, label, dependency)?;
        collect_effective_dependencies(
            project,
            aliases,
            selected,
            imported,
            &dependency,
            visited_meta,
            result,
        )?;
    }
    Ok(())
}

fn is_default_toolchain_target(project: &GnProject, label: &str, target: &GnTarget) -> bool {
    if !target.toolchain.is_empty() {
        return target.toolchain == project.build_settings.default_toolchain;
    }
    split_toolchain(label)
        .1
        .is_none_or(|toolchain| toolchain == project.build_settings.default_toolchain)
}

fn split_toolchain(label: &str) -> (&str, Option<&str>) {
    if let Some(open) = label.rfind('(')
        && label.ends_with(')')
    {
        return (&label[..open], Some(&label[open + 1..label.len() - 1]));
    }
    (label, None)
}

fn is_source_target(target: &GnTarget) -> bool {
    target.crate_root.is_some()
        || target.sources.iter().any(|source| {
            source_extension(source).is_some_and(|extension| {
                matches!(
                    extension.as_str(),
                    "c" | "cc" | "cpp" | "cxx" | "m" | "mm" | "s" | "asm" | "rs"
                )
            })
        })
}

fn infer_state(target: &GnTarget) -> MigrationState {
    let mut has_rust = target.crate_root.is_some() || target.target_type.starts_with("rust_");
    let mut has_cpp = false;

    for source in &target.sources {
        match source_extension(source).as_deref() {
            Some("rs") => has_rust = true,
            Some("c" | "cc" | "cpp" | "cxx" | "m" | "mm" | "s" | "asm") => {
                has_cpp = true;
            }
            _ => {}
        }
    }

    match (has_cpp, has_rust) {
        (true, true) => MigrationState::Bridged,
        (false, true) => MigrationState::RustOwned,
        _ => MigrationState::LegacyCpp,
    }
}

fn source_extension(source: &str) -> Option<String> {
    Path::new(source)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
}

fn normalized_sources(label: &str, target: &GnTarget) -> Vec<String> {
    let mut sources = BTreeSet::new();
    for source in target.sources.iter().chain(target.crate_root.iter()) {
        sources.insert(normalize_source(label, source));
    }
    sources.into_iter().collect()
}

fn normalize_source(label: &str, source: &str) -> String {
    let source = source.replace('\\', "/");
    if source.starts_with("//") {
        return source.trim_start_matches("//").to_owned();
    }
    if source.starts_with('/') {
        return source.trim_start_matches('/').to_owned();
    }
    let path = label_path(label);
    if path == "." || source.starts_with(&format!("{path}/")) {
        source
    } else {
        format!("{path}/{source}")
    }
}

fn infer_boundary(
    source: MigrationState,
    dependency: MigrationState,
    inference_enabled: bool,
) -> Boundary {
    if !inference_enabled {
        return Boundary::CppInternal;
    }
    match (source, dependency) {
        (MigrationState::LegacyCpp, MigrationState::LegacyCpp) => Boundary::CppInternal,
        (MigrationState::RustOwned, MigrationState::RustOwned) => Boundary::Rust,
        _ => Boundary::Unclassified,
    }
}

fn assign_module_ids(project: &GnProject, labels: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut assigned = BTreeMap::new();
    let mut used = BTreeSet::new();
    for label in labels {
        let identity = identity_label(project, label);
        let base = sanitize_id(identity);
        let mut candidate = base.clone();
        if used.contains(&candidate) {
            candidate = format!("{base}_{:08x}", fnv1a_32(label.as_bytes()));
            let mut sequence = 2;
            while used.contains(&candidate) {
                candidate = format!("{base}_{:08x}_{sequence}", fnv1a_32(label.as_bytes()));
                sequence += 1;
            }
        }
        used.insert(candidate.clone());
        assigned.insert(label.clone(), candidate);
    }
    assigned
}

fn identity_label<'a>(project: &GnProject, label: &'a str) -> &'a str {
    let (base, toolchain) = split_toolchain(label);
    if toolchain.is_none_or(|toolchain| toolchain == project.build_settings.default_toolchain) {
        base
    } else {
        label
    }
}

fn sanitize_id(label: &str) -> String {
    let mut result = String::new();
    let mut previous_separator = false;
    for character in label.trim_start_matches("//").chars() {
        if character.is_ascii_alphanumeric() {
            result.push(character.to_ascii_lowercase());
            previous_separator = false;
        } else if !previous_separator && !result.is_empty() {
            result.push('_');
            previous_separator = true;
        }
    }
    while result.ends_with('_') {
        result.pop();
    }
    if result.is_empty() {
        result.push_str("root");
    } else if result.as_bytes()[0].is_ascii_digit() {
        result.insert_str(0, "module_");
    }
    result
}

fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn label_path(label: &str) -> String {
    let (base, _) = split_toolchain(label);
    let path = base
        .trim_start_matches("//")
        .split_once(':')
        .map_or(base.trim_start_matches("//"), |(path, _)| path);
    if path.is_empty() {
        ".".to_owned()
    } else {
        path.to_owned()
    }
}

fn inferred_owner(label: &str) -> String {
    label_path(label)
        .split('/')
        .next()
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .unwrap_or("root")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> GnProject {
        serde_json::from_str(include_str!("../../../examples/gn-project.json")).unwrap()
    }

    fn options() -> ImportOptions {
        ImportOptions {
            project_name: "Chromifer test inventory".into(),
            upstream: "chromium/src".into(),
            baseline: "fixture".into(),
            roots: vec!["//app:browser".into()],
            include_all_toolchains: false,
            include_testonly: false,
            include_meta_targets: false,
            infer_state: false,
            gate: None,
        }
    }

    #[test]
    fn imports_source_targets_and_flattens_meta_targets() {
        let output = import_gn_project(&fixture(), &options()).unwrap();
        let ids: Vec<_> = output
            .manifest
            .modules
            .iter()
            .map(|module| module.id.as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "app_browser",
                "base_base",
                "rust_parser",
                "services_network_network_service"
            ]
        );

        let browser = output.manifest.module("app_browser").unwrap();
        assert_eq!(browser.sources, vec!["app/main.cc"]);
        let dependencies: Vec<_> = browser
            .dependencies
            .iter()
            .map(|dependency| dependency.module.as_str())
            .collect();
        assert_eq!(
            dependencies,
            vec!["base_base", "services_network_network_service"]
        );
        assert_eq!(output.summary.skipped_meta_targets, 1);
        assert_eq!(output.summary.omitted_dependencies.len(), 1);
        let inventory = output.manifest.inventory.as_ref().unwrap();
        assert_eq!(inventory.roots, vec!["//app:browser"]);
        assert_eq!(inventory.omitted_dependency_count, 1);
    }

    #[test]
    fn accepts_an_explicit_default_toolchain_root_alias() {
        let mut options = options();
        options.roots = vec!["//app:browser(//build/toolchain/linux:clang_x64)".into()];
        assert_eq!(
            import_gn_project(&fixture(), &options)
                .unwrap()
                .summary
                .imported_modules,
            4
        );
    }

    #[test]
    fn inference_marks_mixed_targets_and_unknown_crossings() {
        let mut options = options();
        options.infer_state = true;
        options.gate = Some(GateOptions {
            id: "fixture-gate".into(),
            command: "autoninja -C out/Default browser_tests".into(),
            target_id: "linux-x64".into(),
            target_description: "Linux fixture".into(),
        });

        let output = import_gn_project(&fixture(), &options).unwrap();
        let network = output
            .manifest
            .module("services_network_network_service")
            .unwrap();
        let parser = output.manifest.module("rust_parser").unwrap();
        assert_eq!(parser.sources, vec!["rust/parser.rs"]);
        assert_eq!(network.state, MigrationState::Bridged);
        assert_eq!(parser.state, MigrationState::RustOwned);
        assert!(network.dependencies.iter().any(|dependency| {
            dependency.module == "rust_parser" && dependency.boundary == Boundary::Unclassified
        }));
    }

    #[test]
    fn inferred_nonlegacy_state_requires_a_gate() {
        let mut options = options();
        options.infer_state = true;
        assert!(matches!(
            import_gn_project(&fixture(), &options),
            Err(ImportError::MissingGateForInferredState)
        ));
    }

    #[test]
    fn generated_toml_roundtrips_through_manifest_validation() {
        let output = import_gn_project(&fixture(), &options()).unwrap();
        let encoded = output.manifest.to_toml_pretty().unwrap();
        let decoded: Manifest = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.validate(), Ok(()));
        assert_eq!(decoded, output.manifest);
    }
}
