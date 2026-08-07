#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use chromifer_manifest::{
    Manifest, ModuleOwnership, OwnershipInclude, SourceOwnership, ValidationErrors,
    normalize_repo_relative_path,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnershipScanSummary {
    pub scanned_modules: usize,
    pub scanned_sources: usize,
    pub owner_files_read: usize,
    pub resolved_sources: usize,
    pub unresolved_sources: usize,
    pub unresolved_includes: usize,
    pub split_ownership_modules: usize,
    pub modules_without_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipScanOutput {
    pub manifest: Manifest,
    pub summary: OwnershipScanSummary,
}

#[derive(Debug, Error)]
pub enum OwnershipError {
    #[error("source root `{path}` is not an accessible directory: {source}")]
    InvalidSourceRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("source path `{path}` for module `{module}` escapes the source root")]
    InvalidSourcePath { module: String, path: String },
    #[error("failed to read OWNERS file `{path}`: {source}")]
    ReadOwners {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}:{line}: {message}")]
    Syntax {
        path: String,
        line: usize,
        message: String,
    },
    #[error("OWNERS include `{include}` from `{path}` does not exist")]
    MissingInclude { path: String, include: String },
    #[error("OWNERS include cycle detected: {cycle}")]
    IncludeCycle { cycle: String },
    #[error(transparent)]
    ManifestValidation(#[from] ValidationErrors),
}

#[derive(Debug, Clone)]
struct ParsedOwners {
    global: Vec<Directive>,
    per_file: Vec<PerFileRule>,
    global_noparent: bool,
}

#[derive(Debug, Clone)]
struct PerFileRule {
    pattern: String,
    directive: Directive,
}

#[derive(Debug, Clone)]
enum Directive {
    Owner(String),
    Include(String),
    NoParent,
}

#[derive(Debug, Clone, Default)]
struct LayerOwnership {
    owners: BTreeSet<String>,
    owner_files: BTreeSet<String>,
    unresolved_includes: BTreeSet<OwnershipInclude>,
    stop_inheritance: bool,
}

struct Resolver {
    root: PathBuf,
    parsed: BTreeMap<PathBuf, ParsedOwners>,
    files_read: BTreeSet<PathBuf>,
}

pub fn scan_ownership(
    manifest: &Manifest,
    source_root: &Path,
) -> Result<OwnershipScanOutput, OwnershipError> {
    let root = source_root
        .canonicalize()
        .map_err(|source| OwnershipError::InvalidSourceRoot {
            path: source_root.display().to_string(),
            source,
        })?;
    if !root.is_dir() {
        return Err(OwnershipError::InvalidSourceRoot {
            path: source_root.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "path is not a directory",
            ),
        });
    }
    let mut resolver = Resolver {
        root,
        parsed: BTreeMap::new(),
        files_read: BTreeSet::new(),
    };
    let mut annotated = manifest.clone();
    let mut scanned_sources = 0;
    let mut resolved_sources = 0;
    let mut unresolved_sources = 0;
    let mut split_ownership_modules = 0;
    let mut modules_without_sources = 0;
    let mut unresolved_includes = BTreeSet::new();

    for module in &mut annotated.modules {
        if module.sources.is_empty() {
            module.ownership = None;
            modules_without_sources += 1;
            continue;
        }

        let mut sources = Vec::with_capacity(module.sources.len());
        for source in &module.sources {
            let relative = normalize_repo_relative_path(source).ok_or_else(|| {
                OwnershipError::InvalidSourcePath {
                    module: module.id.clone(),
                    path: source.clone(),
                }
            })?;
            scanned_sources += 1;
            let ownership = resolver.resolve_source(&relative)?;
            if ownership.effective_owners.is_empty() {
                unresolved_sources += 1;
            } else {
                resolved_sources += 1;
            }
            sources.push(ownership);
        }
        sources.sort_by(|left, right| left.source.cmp(&right.source));

        let ownership = summarize_module_ownership(sources);
        unresolved_includes.extend(ownership.unresolved_includes.iter().cloned());
        if ownership.split_ownership {
            split_ownership_modules += 1;
        }
        module.ownership = Some(ownership);
    }

    annotated.validate()?;
    Ok(OwnershipScanOutput {
        summary: OwnershipScanSummary {
            scanned_modules: manifest.modules.len(),
            scanned_sources,
            owner_files_read: resolver.files_read.len(),
            resolved_sources,
            unresolved_sources,
            unresolved_includes: unresolved_includes.len(),
            split_ownership_modules,
            modules_without_sources,
        },
        manifest: annotated,
    })
}

impl Resolver {
    fn resolve_source(&mut self, source: &str) -> Result<SourceOwnership, OwnershipError> {
        let relative = PathBuf::from(source);
        let mut directory = relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        let mut primary_owners = BTreeSet::new();
        let mut effective_owners = BTreeSet::new();
        let mut owner_files = BTreeSet::new();
        let mut unresolved_includes = BTreeSet::new();
        let mut inheritance_stopped_at = None;
        let mut found_primary = false;

        loop {
            let owner_file = directory.join("OWNERS");
            if self.root.join(&owner_file).is_file() {
                let scoped_source = if directory.as_os_str().is_empty() {
                    relative.as_path()
                } else {
                    relative.strip_prefix(&directory).map_err(|_| {
                        OwnershipError::InvalidSourcePath {
                            module: "OWNERS resolution".into(),
                            path: source.into(),
                        }
                    })?
                };
                let layer = self.evaluate_owner_file(&owner_file, &path_string(scoped_source))?;
                if !found_primary && !layer.owners.is_empty() {
                    primary_owners.extend(layer.owners.iter().cloned());
                    found_primary = true;
                }
                effective_owners.extend(layer.owners);
                owner_files.extend(layer.owner_files);
                unresolved_includes.extend(layer.unresolved_includes);
                if layer.stop_inheritance {
                    inheritance_stopped_at = Some(path_string(&owner_file));
                    break;
                }
            }

            if directory.as_os_str().is_empty() {
                break;
            }
            directory.pop();
        }

        Ok(SourceOwnership {
            source: source.to_owned(),
            primary_owners: primary_owners.into_iter().collect(),
            effective_owners: effective_owners.into_iter().collect(),
            owner_files: owner_files.into_iter().collect(),
            unresolved_includes: unresolved_includes.into_iter().collect(),
            inheritance_stopped_at,
        })
    }

    fn evaluate_owner_file(
        &mut self,
        path: &Path,
        scoped_source: &str,
    ) -> Result<LayerOwnership, OwnershipError> {
        let parsed = self.parse_file(path)?;
        let matched: Vec<_> = parsed
            .per_file
            .iter()
            .filter(|rule| glob_matches(&rule.pattern, scoped_source))
            .map(|rule| rule.directive.clone())
            .collect();
        let per_file_noparent = matched
            .iter()
            .any(|directive| matches!(directive, Directive::NoParent));

        let mut directives = Vec::new();
        if !per_file_noparent {
            directives.extend(parsed.global);
        }
        directives.extend(
            matched
                .into_iter()
                .filter(|directive| !matches!(directive, Directive::NoParent)),
        );

        let mut stack = vec![path.to_path_buf()];
        let mut layer = self.resolve_directives(path, &directives, &mut stack)?;
        layer.stop_inheritance = parsed.global_noparent || per_file_noparent;
        layer.owner_files.insert(path_string(path));
        Ok(layer)
    }

    fn resolve_directives(
        &mut self,
        owner_file: &Path,
        directives: &[Directive],
        stack: &mut Vec<PathBuf>,
    ) -> Result<LayerOwnership, OwnershipError> {
        let mut result = LayerOwnership::default();
        for directive in directives {
            match directive {
                Directive::Owner(owner) => {
                    result.owners.insert(owner.clone());
                }
                Directive::Include(include) => {
                    if is_external_include(include) {
                        result.unresolved_includes.insert(OwnershipInclude {
                            owner_file: path_string(owner_file),
                            include: include.clone(),
                        });
                        continue;
                    }
                    let included = self.resolve_include(owner_file, include)?;
                    if let Some(position) = stack.iter().position(|item| item == &included) {
                        let mut cycle: Vec<_> = stack[position..]
                            .iter()
                            .map(|item| path_string(item))
                            .collect();
                        cycle.push(path_string(&included));
                        return Err(OwnershipError::IncludeCycle {
                            cycle: cycle.join(" -> "),
                        });
                    }
                    stack.push(included.clone());
                    let parsed = self.parse_file(&included)?;
                    let nested = self.resolve_directives(&included, &parsed.global, stack)?;
                    stack.pop();
                    result.owners.extend(nested.owners);
                    result.owner_files.extend(nested.owner_files);
                    result
                        .unresolved_includes
                        .extend(nested.unresolved_includes);
                    result.owner_files.insert(path_string(&included));
                }
                Directive::NoParent => {}
            }
        }
        Ok(result)
    }

    fn resolve_include(&self, owner_file: &Path, include: &str) -> Result<PathBuf, OwnershipError> {
        let root_relative = include.trim_start_matches('/');
        let normalized = if root_relative.len() != include.len() {
            normalize_join(Path::new(""), Path::new(root_relative))
        } else {
            normalize_join(
                owner_file.parent().unwrap_or_else(|| Path::new("")),
                Path::new(include),
            )
        }
        .ok_or_else(|| OwnershipError::MissingInclude {
            path: path_string(owner_file),
            include: include.to_owned(),
        })?;
        if !self.root.join(&normalized).is_file() {
            return Err(OwnershipError::MissingInclude {
                path: path_string(owner_file),
                include: include.to_owned(),
            });
        }
        Ok(normalized)
    }

    fn parse_file(&mut self, path: &Path) -> Result<ParsedOwners, OwnershipError> {
        if let Some(parsed) = self.parsed.get(path) {
            return Ok(parsed.clone());
        }
        let full = self.root.join(path);
        let content = fs::read_to_string(&full).map_err(|source| OwnershipError::ReadOwners {
            path: full.display().to_string(),
            source,
        })?;
        let parsed = parse_owners(path, &content)?;
        self.files_read.insert(path.to_path_buf());
        self.parsed.insert(path.to_path_buf(), parsed.clone());
        Ok(parsed)
    }
}

fn parse_owners(path: &Path, content: &str) -> Result<ParsedOwners, OwnershipError> {
    let mut global = Vec::new();
    let mut per_file = Vec::new();
    let mut global_noparent = false;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "set noparent" {
            global_noparent = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("per-file ") {
            let Some((pattern, directive)) = rest.split_once('=') else {
                return syntax(path, line_number, "per-file rule must contain `=`");
            };
            let pattern = pattern.trim();
            if pattern.is_empty() {
                return syntax(
                    path,
                    line_number,
                    "per-file path expression must not be empty",
                );
            }
            let directives = parse_directives(path, line_number, directive.trim())?;
            for expression in pattern.split(',') {
                validate_path_expression(path, line_number, expression)?;
                for directive in &directives {
                    per_file.push(PerFileRule {
                        pattern: expression.to_owned(),
                        directive: directive.clone(),
                    });
                }
            }
            continue;
        }
        if line.starts_with("set ") {
            return syntax(path, line_number, "unknown `set` directive");
        }
        if let Some(include) = line.strip_prefix("include ") {
            let include = include.trim();
            if include.is_empty() {
                return syntax(path, line_number, "include must name an OWNERS file");
            }
            global.push(Directive::Include(include.to_owned()));
            continue;
        }
        global.extend(parse_directives(path, line_number, line)?);
    }

    Ok(ParsedOwners {
        global,
        per_file,
        global_noparent,
    })
}

fn parse_directives(
    path: &Path,
    line: usize,
    directive: &str,
) -> Result<Vec<Directive>, OwnershipError> {
    if directive == "set noparent" {
        return Ok(vec![Directive::NoParent]);
    }
    if let Some(include) = directive.strip_prefix("file:") {
        let include = include.trim();
        if include.is_empty() {
            return syntax(path, line, "file include must name an OWNERS file");
        }
        return Ok(vec![Directive::Include(include.to_owned())]);
    }
    let mut owners = Vec::new();
    for owner in directive.split(',') {
        let owner = owner.trim();
        if owner != "*" && !valid_owner(owner) {
            return syntax(
                path,
                line,
                "expected comma-separated emails, `*`, `file:`, or `set noparent` directive",
            );
        }
        owners.push(Directive::Owner(owner.to_owned()));
    }
    if !owners.is_empty() {
        return Ok(owners);
    }
    syntax(
        path,
        line,
        "expected comma-separated emails, `*`, `file:`, or `set noparent` directive",
    )
}

fn validate_path_expression(
    path: &Path,
    line: usize,
    expression: &str,
) -> Result<(), OwnershipError> {
    if expression.is_empty()
        || expression.starts_with('/')
        || expression.contains('\\')
        || expression.split('/').any(|component| component == "..")
        || expression
            .chars()
            .any(|character| character.is_control() || character == '=')
    {
        return syntax(
            path,
            line,
            "per-file path expression must be relative and may not escape its OWNERS directory",
        );
    }
    Ok(())
}

fn valid_owner(value: &str) -> bool {
    let Some((left, right)) = value.split_once('@') else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && !right.contains('@')
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '+' | '%' | '.' | '@')
        })
}

fn summarize_module_ownership(sources: Vec<SourceOwnership>) -> ModuleOwnership {
    let mut primary_owners = BTreeSet::new();
    let mut effective_owners = BTreeSet::new();
    let mut owner_files = BTreeSet::new();
    let mut unresolved_includes = BTreeSet::new();
    let mut unresolved_sources = Vec::new();
    let mut distinct_primary = BTreeSet::new();
    let mut common: Option<BTreeSet<String>> = None;

    for source in &sources {
        primary_owners.extend(source.primary_owners.iter().cloned());
        effective_owners.extend(source.effective_owners.iter().cloned());
        owner_files.extend(source.owner_files.iter().cloned());
        unresolved_includes.extend(source.unresolved_includes.iter().cloned());
        if source.effective_owners.is_empty() {
            unresolved_sources.push(source.source.clone());
        } else {
            let current: BTreeSet<_> = source.effective_owners.iter().cloned().collect();
            common = Some(match common {
                None => current,
                Some(previous) => previous.intersection(&current).cloned().collect(),
            });
        }
        distinct_primary.insert(source.primary_owners.clone());
    }

    ModuleOwnership {
        primary_owners: primary_owners.into_iter().collect(),
        effective_owners: effective_owners.into_iter().collect(),
        common_effective_owners: common.unwrap_or_default().into_iter().collect(),
        owner_files: owner_files.into_iter().collect(),
        unresolved_sources,
        unresolved_includes: unresolved_includes.into_iter().collect(),
        split_ownership: distinct_primary.len() > 1,
        sources,
    }
}

fn is_external_include(include: &str) -> bool {
    include.rsplit_once(":/").is_some_and(|(project, path)| {
        !project.is_empty() && !project.starts_with('/') && !path.is_empty()
    })
}

fn normalize_repo_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn normalize_join(base: &Path, relative: &Path) -> Option<PathBuf> {
    let mut normalized = normalize_repo_path(base)?;
    for component in relative.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut current = vec![false; value.len() + 1];
    let mut next = vec![false; value.len() + 1];
    current[0] = true;
    let mut pattern_index = 0;
    while pattern_index < pattern.len() {
        next.fill(false);
        if pattern[pattern_index..].starts_with(b"...") {
            next[0] = current[0];
            for index in 1..=value.len() {
                next[index] = current[index] || next[index - 1];
            }
            pattern_index += 3;
            std::mem::swap(&mut current, &mut next);
            continue;
        }
        match pattern[pattern_index] {
            b'*' => {
                next[0] = current[0];
                for index in 1..=value.len() {
                    next[index] = current[index] || (value[index - 1] != b'/' && next[index - 1]);
                }
            }
            b'?' => {
                for index in 1..=value.len() {
                    next[index] = value[index - 1] != b'/' && current[index - 1];
                }
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = current[index - 1] && literal == value[index - 1];
                }
            }
        }
        std::mem::swap(&mut current, &mut next);
        pattern_index += 1;
    }
    current[value.len()]
}

fn syntax<T>(path: &Path, line: usize, message: &str) -> Result<T, OwnershipError> {
    Err(OwnershipError::Syntax {
        path: path_string(path),
        line,
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chromifer_manifest::{MigrationState, Module, Project};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-owners-{}-{id}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, path: &str, content: &str) {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn manifest(sources: &[&str]) -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "owners fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![Module {
                id: "module".into(),
                path: "services/network".into(),
                owner: "services".into(),
                ownership: None,
                source_label: None,
                source_type: None,
                sources: sources.iter().map(|source| (*source).into()).collect(),
                state: MigrationState::LegacyCpp,
                gates: vec![],
                reviews: vec![],
                dependencies: vec![],
            }],
        }
    }

    #[test]
    fn inherits_parent_owners_and_preserves_nearest_primary_owners() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write("services/OWNERS", "services@chromium.org\n");
        tree.write("services/network/OWNERS", "network@chromium.org\n");

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        assert_eq!(ownership.primary_owners, vec!["network@chromium.org"]);
        assert_eq!(
            ownership.effective_owners,
            vec![
                "network@chromium.org",
                "root@chromium.org",
                "services@chromium.org"
            ]
        );
        assert_eq!(output.summary.owner_files_read, 3);
    }

    #[test]
    fn global_noparent_stops_parent_inheritance() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            "set noparent\nnetwork@chromium.org\n",
        );

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let source = &output.manifest.modules[0]
            .ownership
            .as_ref()
            .unwrap()
            .sources[0];
        assert_eq!(source.effective_owners, vec!["network@chromium.org"]);
        assert_eq!(
            source.inheritance_stopped_at.as_deref(),
            Some("services/network/OWNERS")
        );
    }

    #[test]
    fn per_file_noparent_ignores_global_entries_in_the_same_file() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            "general@chromium.org\nper-file *.mojom=set noparent\nper-file *.mojom=ipc@chromium.org\n",
        );

        let output = scan_ownership(
            &manifest(&[
                "services/network/service.mojom",
                "services/network/context.cc",
            ]),
            &tree.root,
        )
        .unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        let mojom = ownership
            .sources
            .iter()
            .find(|source| source.source.ends_with(".mojom"))
            .unwrap();
        assert_eq!(mojom.effective_owners, vec!["ipc@chromium.org"]);
        let cpp = ownership
            .sources
            .iter()
            .find(|source| source.source.ends_with(".cc"))
            .unwrap();
        assert_eq!(
            cpp.effective_owners,
            vec!["general@chromium.org", "root@chromium.org"]
        );
        assert!(ownership.split_ownership);
    }

    #[test]
    fn resolves_relative_and_repository_root_includes() {
        let tree = TempTree::new();
        tree.write("SECURITY_OWNERS", "security@chromium.org\n");
        tree.write("services/SHARED_OWNERS", "shared@chromium.org\n");
        tree.write("services/GLOBAL_OWNERS", "global@chromium.org\n");
        tree.write("ROOT_OWNERS", "root-include@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            concat!(
                "file:../SHARED_OWNERS\n",
                "file://SECURITY_OWNERS\n",
                "file:///ROOT_OWNERS\n",
                "include ../GLOBAL_OWNERS\n",
                "include /SECURITY_OWNERS\n",
            ),
        );

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        assert_eq!(
            output.manifest.modules[0]
                .ownership
                .as_ref()
                .unwrap()
                .effective_owners,
            vec![
                "global@chromium.org",
                "root-include@chromium.org",
                "security@chromium.org",
                "shared@chromium.org"
            ]
        );
    }

    #[test]
    fn records_external_gerrit_project_includes_without_resolving_them() {
        let tree = TempTree::new();
        tree.write(
            "services/network/OWNERS",
            "network@chromium.org\ninclude platform/system/core:main:/janitors/OWNERS\n",
        );
        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        assert_eq!(ownership.effective_owners, vec!["network@chromium.org"]);
        assert_eq!(
            ownership.unresolved_includes,
            vec![OwnershipInclude {
                owner_file: "services/network/OWNERS".into(),
                include: "platform/system/core:main:/janitors/OWNERS".into(),
            }]
        );
        assert_eq!(output.summary.unresolved_includes, 1);
    }

    #[test]
    fn reports_missing_include_and_include_cycles() {
        let tree = TempTree::new();
        tree.write("services/network/OWNERS", "file://MISSING_OWNERS\n");
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::MissingInclude { .. })
        ));

        tree.write("services/network/OWNERS", "file://A_OWNERS\n");
        tree.write("A_OWNERS", "file://B_OWNERS\n");
        tree.write("B_OWNERS", "file://A_OWNERS\n");
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::IncludeCycle { .. })
        ));
    }

    #[test]
    fn unresolved_sources_are_recorded_without_failing() {
        let tree = TempTree::new();
        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        assert_eq!(
            ownership.unresolved_sources,
            vec!["services/network/context.cc"]
        );
        assert_eq!(output.summary.unresolved_sources, 1);
    }

    #[test]
    fn simple_path_matching_respects_directory_boundaries_and_recursive_ellipsis() {
        assert!(glob_matches("*_messages?.h", "network_messages1.h"));
        assert!(!glob_matches("*_messages?.h", "network_messages.h"));
        assert!(glob_matches("*.mojom", "service.mojom"));
        assert!(!glob_matches("*.mojom", "public/service.mojom"));
        assert!(glob_matches("public/*.mojom", "public/service.mojom"));
        assert!(!glob_matches(
            "public/*.mojom",
            "public/nested/service.mojom"
        ));
        assert!(glob_matches(
            ".../service.mojom",
            "public/nested/service.mojom"
        ));
        assert!(glob_matches("..._win*", "platform/widget_win.cc"));
    }

    #[test]
    fn supports_relative_paths_recursive_patterns_and_comma_lists() {
        let tree = TempTree::new();
        tree.write(
            "services/network/OWNERS",
            concat!(
                "general@chromium.org\n",
                "per-file subdir/*.cc=path@chromium.org\n",
                "per-file .../SECURITY_OWNERS=set noparent\n",
                "per-file .../SECURITY_OWNERS=security@chromium.org\n",
                "per-file alpha.h,beta.h=first@chromium.org,second@chromium.org\n",
            ),
        );
        let output = scan_ownership(
            &manifest(&[
                "services/network/subdir/impl.cc",
                "services/network/subdir/nested/impl.cc",
                "services/network/deep/SECURITY_OWNERS",
                "services/network/alpha.h",
            ]),
            &tree.root,
        )
        .unwrap();
        let sources = &output.manifest.modules[0]
            .ownership
            .as_ref()
            .unwrap()
            .sources;
        let owners = |suffix: &str| {
            sources
                .iter()
                .find(|source| source.source.ends_with(suffix))
                .unwrap()
                .effective_owners
                .clone()
        };
        assert_eq!(
            owners("subdir/impl.cc"),
            vec!["general@chromium.org", "path@chromium.org"]
        );
        assert_eq!(
            owners("subdir/nested/impl.cc"),
            vec!["general@chromium.org"]
        );
        assert_eq!(
            owners("deep/SECURITY_OWNERS"),
            vec!["security@chromium.org"]
        );
        assert_eq!(
            owners("alpha.h"),
            vec![
                "first@chromium.org",
                "general@chromium.org",
                "second@chromium.org"
            ]
        );
    }

    #[test]
    fn rejects_escaping_per_file_path_expressions() {
        let tree = TempTree::new();
        tree.write(
            "services/network/OWNERS",
            "per-file ../outside.cc=owner@chromium.org\n",
        );
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::Syntax { .. })
        ));
    }

    #[test]
    fn rejects_missing_or_non_directory_source_roots() {
        let tree = TempTree::new();
        let missing = tree.root.join("missing");
        assert!(matches!(
            scan_ownership(&manifest(&["context.cc"]), &missing),
            Err(OwnershipError::InvalidSourceRoot { .. })
        ));

        let file = tree.root.join("not-a-directory");
        fs::write(&file, "fixture").unwrap();
        assert!(matches!(
            scan_ownership(&manifest(&["context.cc"]), &file),
            Err(OwnershipError::InvalidSourceRoot { .. })
        ));
    }
}
