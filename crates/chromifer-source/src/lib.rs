#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chromifer_manifest::{
    Boundary, BoundaryEvidence, BoundaryEvidenceKind, BoundaryReview, BoundaryReviewKind, Manifest,
    Module, ValidationErrors, normalize_repo_relative_path,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutput {
    pub manifest: Manifest,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    pub scanned_modules: usize,
    pub scanned_files: usize,
    pub missing_sources: Vec<MissingSource>,
    pub updated_boundaries: Vec<BoundaryUpdate>,
    pub conflicts: Vec<BoundaryConflict>,
    pub edge_reviews: usize,
    pub module_reviews: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MissingSource {
    pub module: String,
    pub file: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundaryUpdate {
    pub module: String,
    pub dependency: String,
    pub from: Boundary,
    pub to: Boundary,
    pub evidence_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundaryConflict {
    pub module: String,
    pub dependency: String,
    pub current: Boundary,
    pub detected: Vec<Boundary>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("source path `{path}` for module `{module}` escapes the source root")]
    InvalidSourcePath { module: String, path: String },
    #[error("failed to read source `{path}` for module `{module}`: {source}")]
    ReadSource {
        module: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    ManifestValidation(#[from] ValidationErrors),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceLocation {
    file: String,
    line: usize,
}

#[derive(Debug, Clone)]
struct IncludeUse {
    path: String,
    file: String,
    line: usize,
    in_cxx_bridge: bool,
}

#[derive(Debug, Clone)]
struct FileScan {
    includes: Vec<IncludeUse>,
    reviews: Vec<BoundaryReview>,
}

#[derive(Debug, Clone, Default)]
struct ModuleScan {
    files: Vec<FileScan>,
    c_abi_declarations: BTreeMap<String, SourceLocation>,
    c_abi_definitions: BTreeMap<String, SourceLocation>,
}

pub fn scan_manifest(manifest: &Manifest, source_root: &Path) -> Result<ScanOutput, ScanError> {
    let mut annotated = manifest.clone();
    let mut scans = BTreeMap::new();
    let mut missing_sources = Vec::new();
    let mut scanned_files = 0;

    for module in &manifest.modules {
        let scan = scan_module(
            module,
            source_root,
            &mut missing_sources,
            &mut scanned_files,
        )?;
        scans.insert(module.id.clone(), scan);
    }

    let mut edge_evidence: BTreeMap<(String, String), BTreeSet<BoundaryEvidence>> = BTreeMap::new();
    let mut edge_reviews: BTreeMap<(String, String), BTreeSet<BoundaryReview>> = BTreeMap::new();
    let mut module_reviews: BTreeMap<String, BTreeSet<BoundaryReview>> = BTreeMap::new();

    for module in &manifest.modules {
        let Some(scan) = scans.get(&module.id) else {
            continue;
        };
        collect_include_evidence(
            manifest,
            module,
            scan,
            &mut edge_evidence,
            &mut edge_reviews,
            &mut module_reviews,
        );
        collect_c_abi_evidence(module, &scans, &mut edge_evidence);
    }

    let mut updated_boundaries = Vec::new();
    let mut conflicts = Vec::new();
    let mut edge_review_count = 0;
    let mut module_review_count = 0;

    for module in &mut annotated.modules {
        if let Some(reviews) = module_reviews.remove(&module.id) {
            merge_reviews(&mut module.reviews, reviews);
        }
        module_review_count += module
            .reviews
            .iter()
            .filter(|review| !review.resolved)
            .count();

        for dependency in &mut module.dependencies {
            let key = (module.id.clone(), dependency.module.clone());
            let detected = edge_evidence.remove(&key).unwrap_or_default();
            let detected_boundaries: BTreeSet<_> = detected
                .iter()
                .map(|evidence| evidence.kind.boundary())
                .collect();
            merge_evidence(&mut dependency.evidence, detected);

            if let Some(reviews) = edge_reviews.remove(&key) {
                merge_reviews(&mut dependency.reviews, reviews);
            }
            edge_review_count += dependency
                .reviews
                .iter()
                .filter(|review| !review.resolved)
                .count();

            if detected_boundaries.len() == 1 {
                let detected_boundary = *detected_boundaries.iter().next().expect("one boundary");
                if dependency.boundary == detected_boundary {
                    continue;
                }
                if matches!(
                    dependency.boundary,
                    Boundary::Unclassified | Boundary::CppInternal
                ) {
                    let from = dependency.boundary;
                    dependency.boundary = detected_boundary;
                    updated_boundaries.push(BoundaryUpdate {
                        module: module.id.clone(),
                        dependency: dependency.module.clone(),
                        from,
                        to: detected_boundary,
                        evidence_count: dependency
                            .evidence
                            .iter()
                            .filter(|evidence| evidence.kind.boundary() == detected_boundary)
                            .count(),
                    });
                } else {
                    conflicts.push(BoundaryConflict {
                        module: module.id.clone(),
                        dependency: dependency.module.clone(),
                        current: dependency.boundary,
                        detected: vec![detected_boundary],
                    });
                }
            } else if !detected_boundaries.is_empty() {
                conflicts.push(BoundaryConflict {
                    module: module.id.clone(),
                    dependency: dependency.module.clone(),
                    current: dependency.boundary,
                    detected: detected_boundaries.into_iter().collect(),
                });
            }
        }
    }

    missing_sources.sort();
    updated_boundaries.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then(left.dependency.cmp(&right.dependency))
    });
    conflicts.sort_by(|left, right| {
        left.module
            .cmp(&right.module)
            .then(left.dependency.cmp(&right.dependency))
    });
    annotated.validate()?;

    Ok(ScanOutput {
        summary: ScanSummary {
            scanned_modules: manifest.modules.len(),
            scanned_files,
            missing_sources,
            updated_boundaries,
            conflicts,
            edge_reviews: edge_review_count,
            module_reviews: module_review_count,
        },
        manifest: annotated,
    })
}

fn scan_module(
    module: &Module,
    source_root: &Path,
    missing_sources: &mut Vec<MissingSource>,
    scanned_files: &mut usize,
) -> Result<ModuleScan, ScanError> {
    let mut result = ModuleScan::default();
    for source in &module.sources {
        let relative =
            normalize_repo_relative_path(source).ok_or_else(|| ScanError::InvalidSourcePath {
                module: module.id.clone(),
                path: source.clone(),
            })?;
        let path = resolve_source_path(source_root, module, &relative);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_sources.push(MissingSource {
                    module: module.id.clone(),
                    file: relative,
                });
                continue;
            }
            Err(source) => {
                return Err(ScanError::ReadSource {
                    module: module.id.clone(),
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        *scanned_files += 1;
        let content = String::from_utf8_lossy(&bytes);
        let file_scan = scan_file(
            &relative,
            &content,
            &mut result.c_abi_declarations,
            &mut result.c_abi_definitions,
        );
        result.files.push(file_scan);
    }
    Ok(result)
}

fn resolve_source_path(source_root: &Path, module: &Module, source: &str) -> PathBuf {
    let direct = source_root.join(source);
    if direct.exists() || module.path == "." || source.starts_with(&format!("{}/", module.path)) {
        return direct;
    }
    source_root.join(&module.path).join(source)
}

fn scan_file(
    file: &str,
    content: &str,
    declarations: &mut BTreeMap<String, SourceLocation>,
    definitions: &mut BTreeMap<String, SourceLocation>,
) -> FileScan {
    let in_cxx_bridge = content.lines().any(|line| line.contains("cxx::bridge"));
    let mut includes = Vec::new();
    let mut reviews = Vec::new();
    let mut cpp_extern_depth = 0_i32;
    let mut rust_extern_depth = 0_i32;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if let Some(path) = extract_cpp_include(line).or_else(|| extract_rust_include(line)) {
            includes.push(IncludeUse {
                path: normalize_include_path(path),
                file: file.to_owned(),
                line: line_number,
                in_cxx_bridge,
            });
        }

        for (kind, detail) in detect_reviews(line) {
            reviews.push(BoundaryReview {
                kind,
                file: file.to_owned(),
                line: line_number,
                detail,
                resolved: false,
            });
        }

        scan_c_abi_line(
            line,
            file,
            line_number,
            &mut cpp_extern_depth,
            &mut rust_extern_depth,
            declarations,
            definitions,
        );
    }

    FileScan { includes, reviews }
}

#[allow(clippy::too_many_arguments)]
fn scan_c_abi_line(
    line: &str,
    file: &str,
    line_number: usize,
    cpp_extern_depth: &mut i32,
    rust_extern_depth: &mut i32,
    declarations: &mut BTreeMap<String, SourceLocation>,
    definitions: &mut BTreeMap<String, SourceLocation>,
) {
    let trimmed = line.trim();
    if trimmed.starts_with("//") || trimmed.starts_with('#') && !trimmed.contains("extern") {
        return;
    }

    let cpp_extern = trimmed.contains("extern \"C\"") && !trimmed.contains("extern \"C\" fn");
    let rust_function = trimmed.contains("extern \"C\" fn");
    let rust_block = trimmed.contains("extern \"C\"") && trimmed.contains('{') && !rust_function;

    if cpp_extern || *cpp_extern_depth > 0 {
        if let Some(symbol) = extract_function_name(trimmed) {
            let location = SourceLocation {
                file: file.to_owned(),
                line: line_number,
            };
            if looks_like_definition(trimmed) {
                definitions.entry(symbol).or_insert(location);
            } else {
                declarations.entry(symbol).or_insert(location);
            }
        }
        *cpp_extern_depth += brace_delta(trimmed);
        if *cpp_extern_depth < 0 {
            *cpp_extern_depth = 0;
        }
    }

    if rust_function {
        if let Some(symbol) = extract_rust_function_name(trimmed) {
            let location = SourceLocation {
                file: file.to_owned(),
                line: line_number,
            };
            if *rust_extern_depth > 0 || trimmed.trim_end().ends_with(';') {
                declarations.entry(symbol).or_insert(location);
            } else {
                definitions.entry(symbol).or_insert(location);
            }
        }
    } else if rust_block || *rust_extern_depth > 0 {
        if let Some(symbol) = extract_rust_function_name(trimmed) {
            declarations.entry(symbol).or_insert(SourceLocation {
                file: file.to_owned(),
                line: line_number,
            });
        }
        *rust_extern_depth += brace_delta(trimmed);
        if *rust_extern_depth < 0 {
            *rust_extern_depth = 0;
        }
    }
}

fn brace_delta(line: &str) -> i32 {
    let opens = line.bytes().filter(|byte| *byte == b'{').count() as i32;
    let closes = line.bytes().filter(|byte| *byte == b'}').count() as i32;
    opens - closes
}

fn looks_like_definition(line: &str) -> bool {
    let Some(open) = line.find('(') else {
        return false;
    };
    line[open..].contains('{') && !line.trim_end().ends_with(';')
}

fn extract_function_name(line: &str) -> Option<String> {
    let open = line.find('(')?;
    let prefix = line[..open].trim_end();
    let token = prefix
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .next_back()?;
    if matches!(
        token,
        "if" | "for" | "while" | "switch" | "return" | "sizeof"
    ) {
        None
    } else {
        Some(token.to_owned())
    }
}

fn extract_rust_function_name(line: &str) -> Option<String> {
    let marker = line.find("fn ")? + 3;
    let suffix = &line[marker..];
    let end = suffix
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(suffix.len());
    (end > 0).then(|| suffix[..end].to_owned())
}

fn extract_cpp_include(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let suffix = trimmed.strip_prefix("#include")?.trim_start();
    quoted_or_angled(suffix)
}

fn extract_rust_include(line: &str) -> Option<&str> {
    let marker = line.find("include!(")? + "include!(".len();
    quoted_or_angled(line[marker..].trim_start())
}

fn quoted_or_angled(value: &str) -> Option<&str> {
    let (start, end) = match value.as_bytes().first()? {
        b'"' => ('"', '"'),
        b'<' => ('<', '>'),
        _ => return None,
    };
    let inner = &value[start.len_utf8()..];
    let end_index = inner.find(end)?;
    Some(&inner[..end_index])
}

fn normalize_include_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("//")
        .trim_start_matches("./")
        .trim_start_matches("gen/")
        .to_owned()
}

fn detect_reviews(line: &str) -> Vec<(BoundaryReviewKind, String)> {
    let mut result = Vec::new();
    let callback_patterns = [
        "base::OnceCallback",
        "base::RepeatingCallback",
        "base::OnceClosure",
        "base::RepeatingClosure",
        "std::function<",
        "FunctionRef<",
        "FnOnce(",
        "FnMut(",
        "Box<dyn Fn",
    ];
    if callback_patterns
        .iter()
        .any(|pattern| line.contains(pattern))
    {
        result.push((BoundaryReviewKind::Callback, compact_line(line)));
    }

    let observer_pattern = line.contains("ObserverList<")
        || line.contains("ScopedObservation<")
        || line.contains("AddObserver(")
        || line.contains("RemoveObserver(")
        || line.contains("public ") && line.contains("Observer")
        || line.contains("trait ") && line.contains("Observer");
    if observer_pattern {
        result.push((BoundaryReviewKind::Observer, compact_line(line)));
    }
    result
}

fn compact_line(line: &str) -> String {
    let mut compact = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() > 180 {
        compact = compact.chars().take(177).collect::<String>() + "...";
    }
    compact
}

fn collect_include_evidence(
    manifest: &Manifest,
    module: &Module,
    scan: &ModuleScan,
    edge_evidence: &mut BTreeMap<(String, String), BTreeSet<BoundaryEvidence>>,
    edge_reviews: &mut BTreeMap<(String, String), BTreeSet<BoundaryReview>>,
    module_reviews: &mut BTreeMap<String, BTreeSet<BoundaryReview>>,
) {
    for file in &scan.files {
        let mut referenced_dependencies = BTreeSet::new();
        for include in &file.includes {
            let matches = matching_dependencies(manifest, module, &include.path);
            if matches.len() != 1 {
                continue;
            }
            let dependency = matches.into_iter().next().expect("one dependency");
            referenced_dependencies.insert(dependency.clone());

            let kind = if is_mojo_generated_header(&include.path) {
                Some(BoundaryEvidenceKind::MojoGeneratedHeader)
            } else if is_cxx_generated_header(&include.path) {
                Some(BoundaryEvidenceKind::CxxGeneratedHeader)
            } else if include.in_cxx_bridge {
                Some(BoundaryEvidenceKind::CxxBridgeInclude)
            } else {
                None
            };
            if let Some(kind) = kind {
                edge_evidence
                    .entry((module.id.clone(), dependency.clone()))
                    .or_default()
                    .insert(BoundaryEvidence {
                        kind,
                        file: include.file.clone(),
                        line: include.line,
                        detail: format!("include `{}` resolves to `{dependency}`", include.path),
                    });
            }
        }

        if referenced_dependencies.len() == 1 {
            let dependency = referenced_dependencies
                .into_iter()
                .next()
                .expect("one referenced dependency");
            edge_reviews
                .entry((module.id.clone(), dependency))
                .or_default()
                .extend(file.reviews.iter().cloned());
        } else {
            module_reviews
                .entry(module.id.clone())
                .or_default()
                .extend(file.reviews.iter().cloned());
        }
    }
}

fn collect_c_abi_evidence(
    module: &Module,
    scans: &BTreeMap<String, ModuleScan>,
    edge_evidence: &mut BTreeMap<(String, String), BTreeSet<BoundaryEvidence>>,
) {
    let Some(source_scan) = scans.get(&module.id) else {
        return;
    };
    for dependency in &module.dependencies {
        let Some(target_scan) = scans.get(&dependency.module) else {
            continue;
        };
        for (symbol, location) in &source_scan.c_abi_declarations {
            if target_scan.c_abi_definitions.contains_key(symbol) {
                insert_c_abi_evidence(
                    edge_evidence,
                    module,
                    &dependency.module,
                    symbol,
                    location,
                    "declared here and defined by",
                );
            }
        }
        for (symbol, location) in &source_scan.c_abi_definitions {
            if target_scan.c_abi_declarations.contains_key(symbol) {
                insert_c_abi_evidence(
                    edge_evidence,
                    module,
                    &dependency.module,
                    symbol,
                    location,
                    "defined here and declared by",
                );
            }
        }
    }
}

fn insert_c_abi_evidence(
    evidence: &mut BTreeMap<(String, String), BTreeSet<BoundaryEvidence>>,
    module: &Module,
    dependency: &str,
    symbol: &str,
    location: &SourceLocation,
    relation: &str,
) {
    evidence
        .entry((module.id.clone(), dependency.to_owned()))
        .or_default()
        .insert(BoundaryEvidence {
            kind: BoundaryEvidenceKind::CAbiSymbol,
            file: location.file.clone(),
            line: location.line,
            detail: format!("C ABI symbol `{symbol}` is {relation} `{dependency}`"),
        });
}

fn matching_dependencies(manifest: &Manifest, module: &Module, include: &str) -> Vec<String> {
    module
        .dependencies
        .iter()
        .filter_map(|dependency| {
            manifest
                .module(&dependency.module)
                .filter(|target| module_matches_include(target, include))
                .map(|_| dependency.module.clone())
        })
        .collect()
}

fn module_matches_include(module: &Module, include: &str) -> bool {
    let include = normalize_include_path(include);
    let include_without_gen = include
        .split_once("/gen/")
        .map_or(include.as_str(), |(_, suffix)| suffix);

    if module.path != "."
        && (include.starts_with(&format!("{}/", module.path))
            || include_without_gen.starts_with(&format!("{}/", module.path)))
    {
        return true;
    }

    module.sources.iter().any(|source| {
        let Some(source) = normalize_repo_relative_path(source) else {
            return false;
        };
        let source_without_gen = source
            .split_once("/gen/")
            .map_or(source.as_str(), |(_, suffix)| suffix);
        path_matches_source(&include, &source)
            || path_matches_source(include_without_gen, &source)
            || path_matches_source(&include, source_without_gen)
            || path_matches_source(include_without_gen, source_without_gen)
    })
}

fn path_matches_source(include: &str, source: &str) -> bool {
    if include == source || include == format!("{source}.h") {
        return true;
    }
    if source.ends_with(".mojom")
        && include.starts_with(source)
        && matches!(
            include.strip_prefix(source),
            Some(".h" | "-forward.h" | "-shared.h" | "-shared-internal.h")
        )
    {
        return true;
    }
    let include_name = Path::new(include)
        .file_name()
        .and_then(|name| name.to_str());
    let source_name = Path::new(source).file_name().and_then(|name| name.to_str());
    include_name == source_name
}

fn is_cxx_generated_header(include: &str) -> bool {
    include.ends_with(".rs.h") || include.contains("/cxxbridge/")
}

fn is_mojo_generated_header(include: &str) -> bool {
    include.contains(".mojom")
        && matches!(
            Path::new(include)
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("h")
        )
}

fn merge_evidence(target: &mut Vec<BoundaryEvidence>, incoming: BTreeSet<BoundaryEvidence>) {
    let mut merged: BTreeSet<_> = target.drain(..).collect();
    merged.extend(incoming);
    *target = merged.into_iter().collect();
}

fn merge_reviews(target: &mut Vec<BoundaryReview>, incoming: BTreeSet<BoundaryReview>) {
    let mut merged: BTreeMap<_, _> = target
        .drain(..)
        .map(|review| {
            (
                (
                    review.kind,
                    review.file.clone(),
                    review.line,
                    review.detail.clone(),
                ),
                review,
            )
        })
        .collect();
    for review in incoming {
        let key = (
            review.kind,
            review.file.clone(),
            review.line,
            review.detail.clone(),
        );
        merged
            .entry(key)
            .and_modify(|existing| existing.resolved |= review.resolved)
            .or_insert(review);
    }
    *target = merged.into_values().collect();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chromifer_manifest::{Dependency, MigrationState, Project};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-source-{}-{id}", std::process::id()));
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

    fn dependency(module: &str) -> Dependency {
        Dependency {
            module: module.into(),
            boundary: Boundary::CppInternal,
            evidence: vec![],
            reviews: vec![],
        }
    }

    fn module(id: &str, path: &str, sources: &[&str], dependencies: Vec<Dependency>) -> Module {
        Module {
            id: id.into(),
            path: path.into(),
            owner: "fixture".into(),
            ownership: None,
            source_label: None,
            source_type: None,
            sources: sources.iter().map(|source| (*source).into()).collect(),
            state: MigrationState::LegacyCpp,
            gates: vec![],
            reviews: vec![],
            dependencies,
        }
    }

    fn fixture_manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "source scanner fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![
                module(
                    "app",
                    "app",
                    &[
                        "app/parser_client.cc",
                        "app/service_client.cc",
                        "app/legacy_client.cc",
                        "app/model_client.cc",
                    ],
                    vec![
                        dependency("parser"),
                        dependency("service"),
                        dependency("legacy"),
                        dependency("model"),
                    ],
                ),
                module("parser", "rust", &["rust/parser.rs"], vec![]),
                module("service", "ipc", &["ipc/service.mojom"], vec![]),
                module("legacy", "legacy", &["legacy/api.cc"], vec![]),
                module("model", "model", &["model/model.h"], vec![]),
            ],
        }
    }

    fn write_fixture(tree: &TempTree) {
        tree.write(
            "app/parser_client.cc",
            "#include \"rust/parser.rs.h\"\nint Parse() { return 0; }\n",
        );
        tree.write(
            "app/service_client.cc",
            "#include \"ipc/service.mojom.h\"\nvoid Connect() {}\n",
        );
        tree.write(
            "app/legacy_client.cc",
            "extern \"C\" int legacy_parse(const char* input);\nint Call() { return legacy_parse(\"x\"); }\n",
        );
        tree.write(
            "app/model_client.cc",
            "#include \"model/model.h\"\nbase::OnceCallback<void()> done;\nbase::ScopedObservation<Model, ModelObserver> observation;\n",
        );
        tree.write("rust/parser.rs", "pub fn parse() {}\n");
        tree.write("ipc/service.mojom", "interface Service {};\n");
        tree.write(
            "legacy/api.cc",
            "extern \"C\" int legacy_parse(const char* input) { return input ? 1 : 0; }\n",
        );
        tree.write("model/model.h", "class Model {};\n");
    }

    #[test]
    fn classifies_high_confidence_boundaries_and_records_reviews() {
        let tree = TempTree::new();
        write_fixture(&tree);

        let output = scan_manifest(&fixture_manifest(), &tree.root).unwrap();
        let app = output.manifest.module("app").unwrap();
        let boundary = |id: &str| {
            app.dependencies
                .iter()
                .find(|dependency| dependency.module == id)
                .unwrap()
                .boundary
        };
        assert_eq!(boundary("parser"), Boundary::Cxx);
        assert_eq!(boundary("service"), Boundary::Mojo);
        assert_eq!(boundary("legacy"), Boundary::CAbi);
        assert_eq!(boundary("model"), Boundary::CppInternal);
        let model = app
            .dependencies
            .iter()
            .find(|dependency| dependency.module == "model")
            .unwrap();
        assert_eq!(model.reviews.len(), 2);
        assert_eq!(output.summary.updated_boundaries.len(), 3);
        assert_eq!(output.summary.edge_reviews, 2);
        assert!(output.summary.conflicts.is_empty());
    }

    #[test]
    fn scanning_twice_does_not_duplicate_evidence_or_reviews() {
        let tree = TempTree::new();
        write_fixture(&tree);
        let first = scan_manifest(&fixture_manifest(), &tree.root).unwrap();
        let second = scan_manifest(&first.manifest, &tree.root).unwrap();
        let first_app = first.manifest.module("app").unwrap();
        let second_app = second.manifest.module("app").unwrap();
        assert_eq!(first_app.dependencies, second_app.dependencies);
        assert!(second.summary.updated_boundaries.is_empty());
    }

    #[test]
    fn detects_a_cxx_bridge_include_from_rust_source() {
        let tree = TempTree::new();
        tree.write(
            "rust/client.rs",
            "#[cxx::bridge]\nmod ffi {\n    unsafe extern \"C++\" {\n        include!(\"legacy/api.h\");\n    }\n}\n",
        );
        tree.write("legacy/api.h", "int LegacyApi();\n");
        let manifest = Manifest {
            schema_version: 1,
            project: Project {
                name: "cxx bridge".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![
                module(
                    "client",
                    "rust",
                    &["rust/client.rs"],
                    vec![dependency("legacy")],
                ),
                module("legacy", "legacy", &["legacy/api.h"], vec![]),
            ],
        };

        let output = scan_manifest(&manifest, &tree.root).unwrap();
        let edge = &output.manifest.module("client").unwrap().dependencies[0];
        assert_eq!(edge.boundary, Boundary::Cxx);
        assert!(
            edge.evidence
                .iter()
                .any(|evidence| { evidence.kind == BoundaryEvidenceKind::CxxBridgeInclude })
        );
    }

    #[test]
    fn rejects_host_absolute_source_paths() {
        let tree = TempTree::new();
        let manifest = Manifest {
            schema_version: 1,
            project: Project {
                name: "absolute path".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![module("app", "app", &["/etc/passwd"], vec![])],
        };

        assert!(matches!(
            scan_manifest(&manifest, &tree.root),
            Err(ScanError::InvalidSourcePath { .. })
        ));
    }

    #[test]
    fn reports_missing_sources_without_aborting_the_scan() {
        let tree = TempTree::new();
        let output = scan_manifest(&fixture_manifest(), &tree.root).unwrap();
        assert_eq!(output.summary.scanned_files, 0);
        assert_eq!(output.summary.missing_sources.len(), 8);
    }

    #[test]
    fn conflicting_mechanisms_leave_the_existing_boundary_unchanged() {
        let tree = TempTree::new();
        tree.write(
            "app/client.cc",
            "#include \"mixed/api.rs.h\"\n#include \"mixed/api.mojom.h\"\n",
        );
        tree.write("mixed/api.rs", "pub fn api() {}\n");
        tree.write("mixed/api.mojom", "interface Api {};\n");
        let manifest = Manifest {
            schema_version: 1,
            project: Project {
                name: "conflict".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![
                module("app", "app", &["app/client.cc"], vec![dependency("mixed")]),
                module(
                    "mixed",
                    "mixed",
                    &["mixed/api.rs", "mixed/api.mojom"],
                    vec![],
                ),
            ],
        };

        let output = scan_manifest(&manifest, &tree.root).unwrap();
        let edge = &output.manifest.module("app").unwrap().dependencies[0];
        assert_eq!(edge.boundary, Boundary::CppInternal);
        assert_eq!(output.summary.conflicts.len(), 1);
        assert_eq!(edge.evidence.len(), 2);
    }
}
