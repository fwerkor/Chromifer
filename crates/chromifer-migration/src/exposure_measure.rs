use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

use proc_macro2::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use thiserror::Error;

use crate::{ExposureResults, MigrationEvidence, SUPPORTED_SCHEMA_VERSION};

pub const EXPOSURE_MEASUREMENT_TOOL_VERSION: &str = "chromifer-exposure-v1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureSourceSpec {
    pub schema_version: u32,
    pub baseline: ExposureSideSpec,
    pub candidate: ExposureSideSpec,
    pub contract_review: ExposureContractReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureSideSpec {
    pub files: Vec<String>,
    #[serde(default)]
    pub cross_language_forwarding_methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureContractReview {
    pub new_public_api_count: u64,
    pub new_mojom_method_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExposureFileMeasurement {
    pub side: String,
    pub path: String,
    pub language: String,
    pub sha256: String,
    pub authored_production_loc: u64,
    pub authored_memory_unsafe_loc: u64,
    pub branch_points: u64,
    pub manual_raw_pointer_fields: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExposureMeasurementReport {
    pub results: ExposureResults,
    pub files: Vec<ExposureFileMeasurement>,
    pub contract_review: ExposureContractReview,
}

#[derive(Debug, Error)]
pub enum ExposureMeasurementError {
    #[error("failed to read exposure source specification `{path}`: {source}")]
    ReadSpec {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse exposure source specification `{path}`: {source}")]
    ParseSpec {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "unsupported exposure source specification schema version {found}; supported version is {supported}"
    )]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("invalid exposure source specification: {0}")]
    InvalidSpec(String),
    #[error("failed to read candidate source `{path}`: {source}")]
    ReadCandidate {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read baseline source `{path}` from revision `{revision}`: {detail}")]
    ReadBaseline {
        path: String,
        revision: String,
        detail: String,
    },
    #[error("failed to parse Rust source `{path}`: {source}")]
    ParseRust {
        path: String,
        #[source]
        source: syn::Error,
    },
}

impl ExposureSourceSpec {
    pub fn load(path: &Path) -> Result<Self, ExposureMeasurementError> {
        let display = path.display().to_string();
        let source =
            fs::read_to_string(path).map_err(|source| ExposureMeasurementError::ReadSpec {
                path: display.clone(),
                source,
            })?;
        let spec: Self =
            toml::from_str(&source).map_err(|source| ExposureMeasurementError::ParseSpec {
                path: display,
                source,
            })?;
        spec.validate()?;
        Ok(spec)
    }

    fn validate(&self) -> Result<(), ExposureMeasurementError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(ExposureMeasurementError::UnsupportedSchema {
                found: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        validate_side("baseline", &self.baseline)?;
        validate_side("candidate", &self.candidate)?;
        Ok(())
    }
}

impl MigrationEvidence {
    pub fn measure_exposure(
        &self,
        source_root: &Path,
        spec_path: &Path,
    ) -> Result<ExposureMeasurementReport, ExposureMeasurementError> {
        let spec = ExposureSourceSpec::load(spec_path)?;
        measure_exposure_spec(self, source_root, &spec)
    }
}

pub fn measure_exposure_spec(
    evidence: &MigrationEvidence,
    source_root: &Path,
    spec: &ExposureSourceSpec,
) -> Result<ExposureMeasurementReport, ExposureMeasurementError> {
    spec.validate()?;
    let revision = &evidence.pilot.upstream.revision;
    let mut files = Vec::new();

    for path in &spec.baseline.files {
        let bytes = git_show(source_root, revision, path)?;
        files.push(measure_file("baseline", path, &bytes)?);
    }
    for path in &spec.candidate.files {
        let full_path = source_root.join(path);
        let bytes =
            fs::read(&full_path).map_err(|source| ExposureMeasurementError::ReadCandidate {
                path: full_path.display().to_string(),
                source,
            })?;
        files.push(measure_file("candidate", path, &bytes)?);
    }

    files.sort_by(|left, right| (&left.side, &left.path).cmp(&(&right.side, &right.path)));

    let baseline = aggregate_side(&files, "baseline");
    let candidate = aggregate_side(&files, "candidate");
    let file_hashes_sha256 = hash_file_inventory(&files);
    let raw_counts_sha256 = hash_raw_counts(&files, spec);

    let results = ExposureResults {
        baseline_authored_memory_unsafe_loc: baseline.authored_memory_unsafe_loc,
        candidate_authored_memory_unsafe_loc: candidate.authored_memory_unsafe_loc,
        baseline_authored_production_loc: baseline.authored_production_loc,
        candidate_authored_production_loc: candidate.authored_production_loc,
        baseline_active_implementation_files: spec.baseline.files.len() as u64,
        candidate_active_implementation_files: spec.candidate.files.len() as u64,
        baseline_branch_points: baseline.branch_points,
        candidate_branch_points: candidate.branch_points,
        baseline_manual_raw_pointer_fields: baseline.manual_raw_pointer_fields,
        candidate_manual_raw_pointer_fields: candidate.manual_raw_pointer_fields,
        baseline_cross_language_forwarding_methods: spec
            .baseline
            .cross_language_forwarding_methods
            .len() as u64,
        candidate_cross_language_forwarding_methods: spec
            .candidate
            .cross_language_forwarding_methods
            .len() as u64,
        new_public_api_count: spec.contract_review.new_public_api_count,
        new_mojom_method_count: spec.contract_review.new_mojom_method_count,
        measurement_tool_version: EXPOSURE_MEASUREMENT_TOOL_VERSION.to_owned(),
        file_hashes_sha256,
        raw_counts_sha256,
    };

    Ok(ExposureMeasurementReport {
        results,
        files,
        contract_review: spec.contract_review.clone(),
    })
}

#[derive(Default)]
struct AggregateMeasurement {
    authored_production_loc: u64,
    authored_memory_unsafe_loc: u64,
    branch_points: u64,
    manual_raw_pointer_fields: u64,
}

fn aggregate_side(files: &[ExposureFileMeasurement], side: &str) -> AggregateMeasurement {
    let mut aggregate = AggregateMeasurement::default();
    for file in files.iter().filter(|file| file.side == side) {
        aggregate.authored_production_loc += file.authored_production_loc;
        aggregate.authored_memory_unsafe_loc += file.authored_memory_unsafe_loc;
        aggregate.branch_points += file.branch_points;
        aggregate.manual_raw_pointer_fields += file.manual_raw_pointer_fields;
    }
    aggregate
}

fn validate_side(label: &str, side: &ExposureSideSpec) -> Result<(), ExposureMeasurementError> {
    if side.files.is_empty() {
        return Err(ExposureMeasurementError::InvalidSpec(format!(
            "{label} file list must not be empty"
        )));
    }
    let mut files = BTreeSet::new();
    for path in &side.files {
        validate_repo_relative_source_path(path)?;
        if !files.insert(path) {
            return Err(ExposureMeasurementError::InvalidSpec(format!(
                "duplicate {label} source `{path}`"
            )));
        }
        infer_language(path)?;
    }
    let mut methods = BTreeSet::new();
    for method in &side.cross_language_forwarding_methods {
        if method.trim().is_empty() {
            return Err(ExposureMeasurementError::InvalidSpec(format!(
                "{label} cross-language forwarding method must not be empty"
            )));
        }
        if !methods.insert(method) {
            return Err(ExposureMeasurementError::InvalidSpec(format!(
                "duplicate {label} cross-language forwarding method `{method}`"
            )));
        }
    }
    Ok(())
}

fn validate_repo_relative_source_path(path: &str) -> Result<(), ExposureMeasurementError> {
    let path_obj = Path::new(path);
    if path.trim().is_empty()
        || path_obj.is_absolute()
        || !path_obj
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ExposureMeasurementError::InvalidSpec(format!(
            "source path `{path}` must be a normalized repository-relative path"
        )));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SourceLanguage {
    Cpp,
    Rust,
}

impl SourceLanguage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Cpp => "cpp",
            Self::Rust => "rust",
        }
    }
}

fn infer_language(path: &str) -> Result<SourceLanguage, ExposureMeasurementError> {
    match Path::new(path).extension().and_then(|ext| ext.to_str()) {
        Some("rs") => Ok(SourceLanguage::Rust),
        Some("c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp") => Ok(SourceLanguage::Cpp),
        _ => Err(ExposureMeasurementError::InvalidSpec(format!(
            "source `{path}` has unsupported language extension"
        ))),
    }
}

fn git_show(
    source_root: &Path,
    revision: &str,
    path: &str,
) -> Result<Vec<u8>, ExposureMeasurementError> {
    let object = format!("{revision}:{path}");
    let output = Command::new("git")
        .arg("-C")
        .arg(source_root)
        .arg("show")
        .arg(&object)
        .output()
        .map_err(|source| ExposureMeasurementError::ReadBaseline {
            path: path.to_owned(),
            revision: revision.to_owned(),
            detail: source.to_string(),
        })?;
    if !output.status.success() {
        return Err(ExposureMeasurementError::ReadBaseline {
            path: path.to_owned(),
            revision: revision.to_owned(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(output.stdout)
}

fn measure_file(
    side: &str,
    path: &str,
    bytes: &[u8],
) -> Result<ExposureFileMeasurement, ExposureMeasurementError> {
    let source = String::from_utf8_lossy(bytes);
    let language = infer_language(path)?;
    let cleaned = strip_comments(&source, matches!(language, SourceLanguage::Rust));
    let authored_lines = authored_line_numbers(&cleaned);
    let authored_production_loc = authored_lines.len() as u64;

    let (authored_memory_unsafe_loc, branch_points, manual_raw_pointer_fields) = match language {
        SourceLanguage::Cpp => (
            authored_production_loc,
            count_cpp_branch_points(&cleaned),
            count_cpp_raw_pointer_fields(&cleaned),
        ),
        SourceLanguage::Rust => {
            let syntax =
                syn::parse_file(&source).map_err(|source| ExposureMeasurementError::ParseRust {
                    path: path.to_owned(),
                    source,
                })?;
            let mut visitor = RustMetricVisitor::default();
            visitor.visit_file(&syntax);
            let unsafe_loc = visitor.unsafe_lines.intersection(&authored_lines).count() as u64;
            (
                unsafe_loc,
                visitor.branch_points,
                visitor.manual_raw_pointer_fields,
            )
        }
    };

    Ok(ExposureFileMeasurement {
        side: side.to_owned(),
        path: path.to_owned(),
        language: language.as_str().to_owned(),
        sha256: sha256_hex(bytes),
        authored_production_loc,
        authored_memory_unsafe_loc,
        branch_points,
        manual_raw_pointer_fields,
    })
}

fn authored_line_numbers(cleaned: &str) -> BTreeSet<usize> {
    cleaned
        .lines()
        .enumerate()
        .filter_map(|(index, line)| (!line.trim().is_empty()).then_some(index + 1))
        .collect()
}

fn strip_comments(source: &str, nested_block_comments: bool) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Code,
        String,
        Char,
        LineComment,
        BlockComment,
    }

    let chars: Vec<char> = source.chars().collect();
    let mut output = String::with_capacity(source.len());
    let mut state = State::Code;
    let mut block_depth = 0usize;
    let mut escaped = false;
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();
        match state {
            State::Code => match (ch, next) {
                ('/', Some('/')) => {
                    output.push(' ');
                    output.push(' ');
                    state = State::LineComment;
                    index += 2;
                    continue;
                }
                ('/', Some('*')) => {
                    output.push(' ');
                    output.push(' ');
                    state = State::BlockComment;
                    block_depth = 1;
                    index += 2;
                    continue;
                }
                ('"', _) => {
                    output.push(ch);
                    state = State::String;
                    escaped = false;
                }
                ('\'', _) => {
                    output.push(ch);
                    state = State::Char;
                    escaped = false;
                }
                _ => output.push(ch),
            },
            State::String => {
                output.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    state = State::Code;
                }
            }
            State::Char => {
                output.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '\'' {
                    state = State::Code;
                }
            }
            State::LineComment => {
                if ch == '\n' {
                    output.push('\n');
                    state = State::Code;
                } else {
                    output.push(' ');
                }
            }
            State::BlockComment => {
                if nested_block_comments && ch == '/' && next == Some('*') {
                    output.push(' ');
                    output.push(' ');
                    block_depth += 1;
                    index += 2;
                    continue;
                }
                if ch == '*' && next == Some('/') {
                    output.push(' ');
                    output.push(' ');
                    block_depth -= 1;
                    index += 2;
                    if block_depth == 0 {
                        state = State::Code;
                    }
                    continue;
                }
                output.push(if ch == '\n' { '\n' } else { ' ' });
            }
        }
        index += 1;
    }
    output
}

fn count_cpp_branch_points(cleaned: &str) -> u64 {
    let mut count = 0u64;
    let mut ident = String::new();
    let flush = |ident: &mut String, count: &mut u64| {
        if matches!(ident.as_str(), "if" | "for" | "while" | "case" | "catch") {
            *count += 1;
        }
        ident.clear();
    };
    for ch in cleaned.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            ident.push(ch);
        } else {
            flush(&mut ident, &mut count);
            if ch == '?' {
                count += 1;
            }
        }
    }
    flush(&mut ident, &mut count);
    count
}

fn count_cpp_raw_pointer_fields(cleaned: &str) -> u64 {
    cleaned
        .lines()
        .filter(|line| {
            let line = line.trim();
            if !line.ends_with(';') || line.contains('(') {
                return false;
            }
            if line.contains("raw_ptr<") || line.contains("raw_ref<") {
                return true;
            }
            let declaration = line.trim_end_matches(';').trim();
            let Some(star) = declaration.rfind('*') else {
                return false;
            };
            let name = declaration[star + 1..].trim();
            !name.is_empty()
                && name
                    .chars()
                    .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        })
        .count() as u64
}

#[derive(Default)]
struct RustMetricVisitor {
    unsafe_lines: BTreeSet<usize>,
    branch_points: u64,
    manual_raw_pointer_fields: u64,
}

impl RustMetricVisitor {
    fn mark_span(&mut self, span: Span) {
        let start = span.start().line;
        let end = span.end().line.max(start);
        self.unsafe_lines.extend(start..=end);
    }
}

impl<'ast> Visit<'ast> for RustMetricVisitor {
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.mark_span(node.span());
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.unsafety.is_some() {
            self.mark_span(node.span());
        }
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.unsafety.is_some() {
            self.mark_span(node.span());
        }
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.unsafety.is_some() {
            self.mark_span(node.span());
        }
        visit::visit_item_impl(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if node.unsafety.is_some() {
            self.mark_span(node.span());
        }
        visit::visit_item_trait(self, node);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast syn::ItemForeignMod) {
        if node.unsafety.is_some() {
            self.mark_span(node.span());
        }
        visit::visit_item_foreign_mod(self, node);
    }

    fn visit_field(&mut self, node: &'ast syn::Field) {
        if matches!(node.ty, syn::Type::Ptr(_)) {
            self.manual_raw_pointer_fields += 1;
        }
        visit::visit_field(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.branch_points += 1;
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.branch_points += 1;
        visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.branch_points += 1;
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.branch_points += node.arms.len() as u64;
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.branch_points += 1;
        visit::visit_expr_try(self, node);
    }
}

fn hash_file_inventory(files: &[ExposureFileMeasurement]) -> String {
    let mut hasher = Sha256::new();
    for file in files {
        hasher.update(file.side.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(file.sha256.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

fn hash_raw_counts(files: &[ExposureFileMeasurement], spec: &ExposureSourceSpec) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EXPOSURE_MEASUREMENT_TOOL_VERSION.as_bytes());
    hasher.update(b"\n");
    for file in files {
        hasher.update(file.side.as_bytes());
        hasher.update(b"\t");
        hasher.update(file.path.as_bytes());
        hasher.update(b"\t");
        hasher.update(file.authored_production_loc.to_string().as_bytes());
        hasher.update(b"\t");
        hasher.update(file.authored_memory_unsafe_loc.to_string().as_bytes());
        hasher.update(b"\t");
        hasher.update(file.branch_points.to_string().as_bytes());
        hasher.update(b"\t");
        hasher.update(file.manual_raw_pointer_fields.to_string().as_bytes());
        hasher.update(b"\n");
    }
    for (side, methods) in [
        ("baseline", &spec.baseline.cross_language_forwarding_methods),
        (
            "candidate",
            &spec.candidate.cross_language_forwarding_methods,
        ),
    ] {
        for method in methods {
            hasher.update(b"ffi\t");
            hasher.update(side.as_bytes());
            hasher.update(b"\t");
            hasher.update(method.as_bytes());
            hasher.update(b"\n");
        }
    }
    hasher.update(
        format!(
            "contract\t{}\t{}\n",
            spec.contract_review.new_public_api_count, spec.contract_review.new_mojom_method_count
        )
        .as_bytes(),
    );
    format!("{:x}", hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_stripping_preserves_strings_and_line_numbers() {
        let source =
            "int a = 1; // comment\n/* block\ncomment */\nconst char* s = \"//not-comment\";\n";
        let cleaned = strip_comments(source, false);
        assert_eq!(cleaned.lines().count(), source.lines().count());
        assert!(cleaned.contains("int a = 1;"));
        assert!(cleaned.contains("\"//not-comment\""));
        assert!(!cleaned.contains("block"));
    }

    #[test]
    fn cpp_metrics_count_structural_branches_and_pointer_fields() {
        let source = r#"
class Demo {
  raw_ptr<Foo> foo_;
  Bar* bar_;
  void Run(int x) {
    if (x) { x = x ? 1 : 2; }
    for (;;) { break; }
    switch (x) { case 1: break; default: break; }
  }
};
"#;
        let cleaned = strip_comments(source, false);
        assert_eq!(count_cpp_branch_points(&cleaned), 4);
        assert_eq!(count_cpp_raw_pointer_fields(&cleaned), 2);
    }

    #[test]
    fn rust_metrics_count_only_explicit_unsafe_ranges() {
        let source = r#"
struct Handle(*mut i32);
unsafe impl Send for Handle {}
fn safe(flag: bool, ptr: *mut i32) {
    if flag {
        unsafe { *ptr = 1; }
    }
}
"#;
        let syntax = syn::parse_file(source).expect("parse Rust fixture");
        let mut visitor = RustMetricVisitor::default();
        visitor.visit_file(&syntax);
        let cleaned = strip_comments(source, true);
        let authored = authored_line_numbers(&cleaned);
        assert_eq!(visitor.manual_raw_pointer_fields, 1);
        assert_eq!(visitor.branch_points, 1);
        assert_eq!(visitor.unsafe_lines.intersection(&authored).count(), 2);
    }

    #[test]
    fn measurement_reads_exact_git_baseline_and_working_tree_candidate() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "chromifer-exposure-measure-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temporary Git repository");
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
                .expect("run git");
            assert!(
                output.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
            output.stdout
        };
        git(&["init", "-q"]);
        fs::write(
            root.join("legacy.cc"),
            "class Legacy {\n  raw_ptr<int> ptr_;\n  void Run() { if (ptr_) {} }\n};\n",
        )
        .expect("write baseline source");
        git(&["add", "legacy.cc"]);
        git(&[
            "-c",
            "user.name=Chromifer Test",
            "-c",
            "user.email=chromifer@example.invalid",
            "commit",
            "-q",
            "-m",
            "baseline",
        ]);
        let revision = String::from_utf8(git(&["rev-parse", "HEAD"]))
            .expect("revision is UTF-8")
            .trim()
            .to_owned();
        fs::write(
            root.join("candidate.rs"),
            "struct Handle(*mut i32);\nunsafe impl Send for Handle {}\nfn run(ptr: *mut i32) { unsafe { *ptr = 1; } }\n",
        )
        .expect("write candidate source");

        let migration = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/services-metrics-ukm-recorder");
        let mut evidence = MigrationEvidence::load(&migration).expect("load migration fixture");
        evidence.pilot.upstream.revision = revision;
        let spec = ExposureSourceSpec {
            schema_version: 1,
            baseline: ExposureSideSpec {
                files: vec!["legacy.cc".to_owned()],
                cross_language_forwarding_methods: Vec::new(),
            },
            candidate: ExposureSideSpec {
                files: vec!["candidate.rs".to_owned()],
                cross_language_forwarding_methods: vec!["BindCandidate".to_owned()],
            },
            contract_review: ExposureContractReview {
                new_public_api_count: 0,
                new_mojom_method_count: 0,
            },
        };

        let first = measure_exposure_spec(&evidence, &root, &spec).expect("measure exposure");
        let second = measure_exposure_spec(&evidence, &root, &spec).expect("repeat exposure");
        assert_eq!(first, second, "measurement must be deterministic");
        assert_eq!(first.results.baseline_active_implementation_files, 1);
        assert_eq!(first.results.candidate_active_implementation_files, 1);
        assert_eq!(first.results.baseline_manual_raw_pointer_fields, 1);
        assert_eq!(first.results.candidate_manual_raw_pointer_fields, 1);
        assert_eq!(first.results.baseline_branch_points, 1);
        assert_eq!(first.results.candidate_cross_language_forwarding_methods, 1);
        assert_eq!(first.results.new_public_api_count, 0);
        assert_eq!(first.results.new_mojom_method_count, 0);
        assert_eq!(first.results.file_hashes_sha256.len(), 64);
        assert_eq!(first.results.raw_counts_sha256.len(), 64);

        fs::remove_dir_all(&root).expect("remove temporary Git repository");
    }

    #[test]
    fn source_spec_rejects_traversal_and_duplicates() {
        let spec = ExposureSourceSpec {
            schema_version: 1,
            baseline: ExposureSideSpec {
                files: vec!["../escape.cc".to_owned()],
                cross_language_forwarding_methods: Vec::new(),
            },
            candidate: ExposureSideSpec {
                files: vec!["safe.rs".to_owned()],
                cross_language_forwarding_methods: Vec::new(),
            },
            contract_review: ExposureContractReview {
                new_public_api_count: 0,
                new_mojom_method_count: 0,
            },
        };
        assert!(matches!(
            spec.validate(),
            Err(ExposureMeasurementError::InvalidSpec(_))
        ));
    }
}
