#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use chromifer_manifest::{Manifest, normalize_repo_relative_path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const REPORT_SCHEMA_VERSION: u32 = 1;
const LLVM_EXPORT_TYPE: &str = "llvm.coverage.json.export";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageOptions {
    pub manifest: PathBuf,
    pub source_root: PathBuf,
    pub export: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema_version: u32,
    pub manifest_sha256: String,
    pub baseline: String,
    pub llvm_export_sha256: String,
    pub llvm_export_version: String,
    pub files: Vec<FileCoverage>,
    pub modules: Vec<ModuleCoverage>,
    pub totals: CoverageTotals,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileCoverage {
    pub path: String,
    pub lines: LineCoverage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LineCoverage {
    pub count: u64,
    pub covered: u64,
    pub basis_points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleCoverage {
    pub module: String,
    pub total_sources: usize,
    pub measured_sources: usize,
    pub missing_sources: Vec<String>,
    pub lines: LineCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageTotals {
    pub manifest_sources: usize,
    pub measured_sources: usize,
    pub missing_sources: Vec<String>,
    pub lines: LineCoverage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageSummary {
    pub modules: usize,
    pub manifest_sources: usize,
    pub measured_sources: usize,
    pub missing_sources: usize,
    pub covered_lines: u64,
    pub total_lines: u64,
    pub line_basis_points: u32,
    pub output: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCoverage {
    pub report_json: String,
    pub report: CoverageReport,
    pub summary: CoverageSummary,
}

#[derive(Debug, Error)]
pub enum CoverageError {
    #[error("source root `{0}` is not an accessible directory")]
    InvalidSourceRoot(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse LLVM coverage export JSON: {0}")]
    ParseExport(#[source] serde_json::Error),
    #[error("failed to parse coverage report JSON: {0}")]
    ParseReport(#[source] serde_json::Error),
    #[error("LLVM coverage export type `{0}` is unsupported")]
    UnsupportedExportType(String),
    #[error("LLVM coverage export version must not be empty")]
    EmptyExportVersion,
    #[error("manifest source `{0}` is not a normalized repository-relative path")]
    InvalidManifestSource(String),
    #[error("manifest source `{0}` is missing, symlinked, or outside the source root")]
    InvalidSourceFile(String),
    #[error("coverage file `{0}` cannot be resolved below the source root")]
    InvalidCoveragePath(String),
    #[error("coverage file `{0}` appears more than once in the LLVM export")]
    DuplicateCoverage(String),
    #[error("coverage for `{path}` reports {covered} covered lines out of only {count}")]
    InvalidLineCounts {
        path: String,
        count: u64,
        covered: u64,
    },
    #[error("unsupported coverage report schema version {found}; supported version is {supported}")]
    UnsupportedReportSchema { found: u32, supported: u32 },
    #[error("coverage report does not match the supplied manifest bytes or baseline")]
    ManifestMismatch,
    #[error("output `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("coverage report drift detected at `{0}`")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Manifest(#[from] chromifer_manifest::LoadError),
    #[error("failed to encode coverage report JSON: {0}")]
    Encode(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct LlvmExport {
    #[serde(rename = "type")]
    kind: String,
    version: String,
    #[serde(default)]
    data: Vec<LlvmData>,
}

#[derive(Debug, Deserialize)]
struct LlvmData {
    #[serde(default)]
    files: Vec<LlvmFile>,
}

#[derive(Debug, Deserialize)]
struct LlvmFile {
    filename: String,
    summary: LlvmSummary,
}

#[derive(Debug, Deserialize)]
struct LlvmSummary {
    lines: LlvmCount,
}

#[derive(Debug, Deserialize)]
struct LlvmCount {
    count: u64,
    covered: u64,
}

pub fn generate(options: &CoverageOptions) -> Result<GeneratedCoverage, CoverageError> {
    let source_root = canonical_directory(&options.source_root)
        .ok_or_else(|| CoverageError::InvalidSourceRoot(display(&options.source_root)))?;
    let manifest_bytes = read_file(&options.manifest)?;
    let manifest = Manifest::load(&options.manifest)?;
    let export_bytes = read_file(&options.export)?;
    let export: LlvmExport =
        serde_json::from_slice(&export_bytes).map_err(CoverageError::ParseExport)?;
    if export.kind != LLVM_EXPORT_TYPE {
        return Err(CoverageError::UnsupportedExportType(export.kind));
    }
    if export.version.trim().is_empty() {
        return Err(CoverageError::EmptyExportVersion);
    }

    let manifest_sources = manifest_sources(&manifest)?;
    for source in &manifest_sources {
        resolve_source_file(&source_root, source)?;
    }

    let mut measured = BTreeMap::<String, LineCoverage>::new();
    for file in export.data.into_iter().flat_map(|data| data.files) {
        let Some(path) = coverage_path(&source_root, &file.filename)? else {
            continue;
        };
        if !manifest_sources.contains(&path) {
            continue;
        }
        if file.summary.lines.covered > file.summary.lines.count {
            return Err(CoverageError::InvalidLineCounts {
                path,
                count: file.summary.lines.count,
                covered: file.summary.lines.covered,
            });
        }
        let lines = line_coverage(file.summary.lines.count, file.summary.lines.covered);
        if measured.insert(path.clone(), lines).is_some() {
            return Err(CoverageError::DuplicateCoverage(path));
        }
    }

    let files: Vec<_> = measured
        .iter()
        .map(|(path, lines)| FileCoverage {
            path: path.clone(),
            lines: *lines,
        })
        .collect();
    let report = CoverageReport {
        schema_version: REPORT_SCHEMA_VERSION,
        manifest_sha256: sha256_hex(&manifest_bytes),
        baseline: manifest.project.baseline.clone(),
        llvm_export_sha256: sha256_hex(&export_bytes),
        llvm_export_version: export.version,
        files,
        modules: aggregate_modules(&manifest, &measured),
        totals: aggregate_totals(&manifest_sources, &measured),
    };
    let report_json = format!("{}\n", serde_json::to_string_pretty(&report)?);
    let summary = CoverageSummary {
        modules: report.modules.len(),
        manifest_sources: report.totals.manifest_sources,
        measured_sources: report.totals.measured_sources,
        missing_sources: report.totals.missing_sources.len(),
        covered_lines: report.totals.lines.covered,
        total_lines: report.totals.lines.count,
        line_basis_points: report.totals.lines.basis_points,
        output: display(&options.output),
        checked: options.check,
    };
    Ok(GeneratedCoverage {
        report_json,
        report,
        summary,
    })
}

pub fn generate_and_write(options: &CoverageOptions) -> Result<CoverageSummary, CoverageError> {
    let generated = generate(options)?;
    if options.check {
        let current = read_file(&options.output)?;
        if current != generated.report_json.as_bytes() {
            return Err(CoverageError::Drift(display(&options.output)));
        }
        return Ok(generated.summary);
    }
    if options.output.exists() && !options.force {
        return Err(CoverageError::OutputExists(display(&options.output)));
    }
    fs::write(&options.output, generated.report_json.as_bytes()).map_err(|source| {
        CoverageError::WriteFile {
            path: display(&options.output),
            source,
        }
    })?;
    Ok(generated.summary)
}

pub fn load_report(path: &Path) -> Result<CoverageReport, CoverageError> {
    let bytes = read_file(path)?;
    let report: CoverageReport =
        serde_json::from_slice(&bytes).map_err(CoverageError::ParseReport)?;
    if report.schema_version != REPORT_SCHEMA_VERSION {
        return Err(CoverageError::UnsupportedReportSchema {
            found: report.schema_version,
            supported: REPORT_SCHEMA_VERSION,
        });
    }
    validate_report(&report)?;
    Ok(report)
}

pub fn verify_report_manifest(
    report: &CoverageReport,
    manifest: &Manifest,
    manifest_bytes: &[u8],
) -> Result<(), CoverageError> {
    validate_report(report)?;
    if report.manifest_sha256 != sha256_hex(manifest_bytes)
        || report.baseline != manifest.project.baseline
    {
        return Err(CoverageError::ManifestMismatch);
    }
    let manifest_sources = manifest_sources(manifest)?;
    let measured: BTreeMap<_, _> = report
        .files
        .iter()
        .map(|file| (file.path.clone(), file.lines))
        .collect();
    if measured.keys().any(|path| !manifest_sources.contains(path))
        || report.modules != aggregate_modules(manifest, &measured)
        || report.totals != aggregate_totals(&manifest_sources, &measured)
    {
        return Err(CoverageError::ManifestMismatch);
    }
    Ok(())
}

impl CoverageReport {
    pub fn file(&self, path: &str) -> Option<&FileCoverage> {
        self.files.iter().find(|file| file.path == path)
    }

    pub fn module(&self, id: &str) -> Option<&ModuleCoverage> {
        self.modules.iter().find(|module| module.module == id)
    }
}

fn manifest_sources(manifest: &Manifest) -> Result<BTreeSet<String>, CoverageError> {
    let mut sources = BTreeSet::new();
    for module in &manifest.modules {
        for source in &module.sources {
            let normalized = normalize_repo_relative_path(source)
                .filter(|normalized| normalized == source)
                .ok_or_else(|| CoverageError::InvalidManifestSource(source.clone()))?;
            sources.insert(normalized);
        }
    }
    Ok(sources)
}

fn aggregate_modules(
    manifest: &Manifest,
    measured: &BTreeMap<String, LineCoverage>,
) -> Vec<ModuleCoverage> {
    manifest
        .modules
        .iter()
        .map(|module| {
            let mut missing_sources = Vec::new();
            let mut line_count = 0_u64;
            let mut covered_lines = 0_u64;
            let mut measured_sources = 0_usize;
            for source in &module.sources {
                if let Some(lines) = measured.get(source) {
                    measured_sources += 1;
                    line_count = line_count.saturating_add(lines.count);
                    covered_lines = covered_lines.saturating_add(lines.covered);
                } else {
                    missing_sources.push(source.clone());
                }
            }
            ModuleCoverage {
                module: module.id.clone(),
                total_sources: module.sources.len(),
                measured_sources,
                missing_sources,
                lines: line_coverage(line_count, covered_lines),
            }
        })
        .collect()
}

fn aggregate_totals(
    manifest_sources: &BTreeSet<String>,
    measured: &BTreeMap<String, LineCoverage>,
) -> CoverageTotals {
    let missing_sources = manifest_sources
        .iter()
        .filter(|source| !measured.contains_key(*source))
        .cloned()
        .collect();
    let line_count = measured.values().map(|lines| lines.count).sum();
    let covered_lines = measured.values().map(|lines| lines.covered).sum();
    CoverageTotals {
        manifest_sources: manifest_sources.len(),
        measured_sources: measured.len(),
        missing_sources,
        lines: line_coverage(line_count, covered_lines),
    }
}

fn validate_report(report: &CoverageReport) -> Result<(), CoverageError> {
    if report.llvm_export_version.trim().is_empty() {
        return Err(CoverageError::EmptyExportVersion);
    }
    let mut paths = BTreeSet::new();
    for file in &report.files {
        if normalize_repo_relative_path(&file.path).as_deref() != Some(file.path.as_str()) {
            return Err(CoverageError::InvalidCoveragePath(file.path.clone()));
        }
        if !paths.insert(file.path.clone()) {
            return Err(CoverageError::DuplicateCoverage(file.path.clone()));
        }
        validate_line_coverage(&file.path, file.lines)?;
    }
    for module in &report.modules {
        validate_line_coverage(&module.module, module.lines)?;
    }
    validate_line_coverage("totals", report.totals.lines)?;
    Ok(())
}

fn validate_line_coverage(path: &str, lines: LineCoverage) -> Result<(), CoverageError> {
    if lines.covered > lines.count
        || lines.basis_points != line_coverage(lines.count, lines.covered).basis_points
    {
        return Err(CoverageError::InvalidLineCounts {
            path: path.to_owned(),
            count: lines.count,
            covered: lines.covered,
        });
    }
    Ok(())
}

fn coverage_path(source_root: &Path, filename: &str) -> Result<Option<String>, CoverageError> {
    let candidate = Path::new(filename);
    let path = if candidate.is_absolute() {
        let canonical = candidate
            .canonicalize()
            .map_err(|_| CoverageError::InvalidCoveragePath(filename.to_owned()))?;
        if !canonical.starts_with(source_root) {
            return Ok(None);
        }
        canonical
            .strip_prefix(source_root)
            .map_err(|_| CoverageError::InvalidCoveragePath(filename.to_owned()))?
            .to_path_buf()
    } else {
        let normalized = normalize_repo_relative_path(filename)
            .ok_or_else(|| CoverageError::InvalidCoveragePath(filename.to_owned()))?;
        let resolved = resolve_source_file(source_root, &normalized)?;
        resolved
            .strip_prefix(source_root)
            .map_err(|_| CoverageError::InvalidCoveragePath(filename.to_owned()))?
            .to_path_buf()
    };
    let relative = display(&path);
    let normalized = normalize_repo_relative_path(&relative)
        .ok_or_else(|| CoverageError::InvalidCoveragePath(filename.to_owned()))?;
    Ok(Some(normalized))
}

fn resolve_source_file(root: &Path, relative: &str) -> Result<PathBuf, CoverageError> {
    let normalized = normalize_repo_relative_path(relative)
        .filter(|normalized| normalized == relative)
        .ok_or_else(|| CoverageError::InvalidManifestSource(relative.to_owned()))?;
    let mut current = root.to_path_buf();
    for component in Path::new(&normalized).components() {
        let Component::Normal(component) = component else {
            return Err(CoverageError::InvalidSourceFile(relative.to_owned()));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| CoverageError::InvalidSourceFile(relative.to_owned()))?;
        if metadata.file_type().is_symlink() {
            return Err(CoverageError::InvalidSourceFile(relative.to_owned()));
        }
    }
    let canonical = current
        .canonicalize()
        .map_err(|_| CoverageError::InvalidSourceFile(relative.to_owned()))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(CoverageError::InvalidSourceFile(relative.to_owned()));
    }
    Ok(canonical)
}

fn canonical_directory(path: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    path.canonicalize().ok()
}

fn line_coverage(count: u64, covered: u64) -> LineCoverage {
    let basis_points = if count == 0 {
        10_000
    } else {
        ((covered.saturating_mul(10_000)) / count).min(10_000) as u32
    };
    LineCoverage {
        count,
        covered,
        basis_points,
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, CoverageError> {
    fs::read(path).map_err(|source| CoverageError::ReadFile {
        path: display(path),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    fn fixture() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "chromifer-coverage-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("source/base")).unwrap();
        fs::create_dir_all(root.join("source/services/network")).unwrap();
        fs::write(
            root.join("source/base/base.cc"),
            "int Base() { return 1; }\n",
        )
        .unwrap();
        fs::write(root.join("source/base/base.h"), "int Base();\n").unwrap();
        fs::write(
            root.join("source/services/network/network.cc"),
            "int Network() { return 2; }\n",
        )
        .unwrap();
        let manifest = root.join("manifest.toml");
        fs::write(
            &manifest,
            r#"schema_version = 1

[project]
name = "coverage-fixture"
upstream = "chromium"
baseline = "deadbeef"

[[modules]]
id = "base"
path = "base"
owner = "base"
sources = ["base/base.cc", "base/base.h"]
state = "legacy_cpp"

[[modules]]
id = "network"
path = "services/network"
owner = "network"
sources = ["services/network/network.cc"]
state = "legacy_cpp"
"#,
        )
        .unwrap();
        let export = root.join("coverage.json");
        let output = root.join("chromifer-coverage.json");
        (root, manifest, export, output)
    }

    fn write_export(path: &Path, files: &[(&str, u64, u64)]) {
        let files: Vec<_> = files
            .iter()
            .map(|(filename, count, covered)| {
                serde_json::json!({
                    "filename": filename,
                    "summary": { "lines": { "count": count, "covered": covered, "percent": 0.0 } }
                })
            })
            .collect();
        fs::write(
            path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "type": LLVM_EXPORT_TYPE,
                "version": "2.0.1",
                "data": [{ "files": files, "totals": {} }]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn aggregates_measured_and_missing_manifest_sources() {
        let (root, manifest, export, output) = fixture();
        write_export(
            &export,
            &[
                ("base/base.cc", 10, 8),
                ("base/base.h", 0, 0),
                ("services/network/network.cc", 20, 5),
                ("generated/out.cc", 1, 1),
            ],
        );
        fs::create_dir_all(root.join("source/generated")).unwrap();
        fs::write(root.join("source/generated/out.cc"), "int out;\n").unwrap();
        let generated = generate(&CoverageOptions {
            manifest,
            source_root: root.join("source"),
            export,
            output,
            force: false,
            check: false,
        })
        .unwrap();
        assert_eq!(generated.report.files.len(), 3);
        assert_eq!(generated.report.totals.manifest_sources, 3);
        assert_eq!(generated.report.totals.measured_sources, 3);
        assert_eq!(generated.report.totals.lines.count, 30);
        assert_eq!(generated.report.totals.lines.covered, 13);
        assert_eq!(generated.report.totals.lines.basis_points, 4_333);
        assert!(generated.report.totals.missing_sources.is_empty());
        let base = generated.report.module("base").unwrap();
        assert_eq!(base.lines.basis_points, 8_000);
        assert_eq!(base.measured_sources, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn records_sources_missing_from_export() {
        let (root, manifest, export, output) = fixture();
        write_export(&export, &[("base/base.cc", 10, 10)]);
        let generated = generate(&CoverageOptions {
            manifest,
            source_root: root.join("source"),
            export,
            output,
            force: false,
            check: false,
        })
        .unwrap();
        assert_eq!(generated.report.totals.measured_sources, 1);
        assert_eq!(generated.report.totals.missing_sources.len(), 2);
        assert_eq!(
            generated.report.module("network").unwrap().measured_sources,
            0
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_duplicate_and_invalid_line_coverage() {
        let (root, manifest, export, output) = fixture();
        write_export(&export, &[("base/base.cc", 10, 8), ("base/base.cc", 10, 8)]);
        let options = CoverageOptions {
            manifest: manifest.clone(),
            source_root: root.join("source"),
            export: export.clone(),
            output: output.clone(),
            force: false,
            check: false,
        };
        assert!(matches!(
            generate(&options),
            Err(CoverageError::DuplicateCoverage(_))
        ));
        write_export(&export, &[("base/base.cc", 3, 4)]);
        assert!(matches!(
            generate(&options),
            Err(CoverageError::InvalidLineCounts { .. })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn check_mode_detects_report_drift_and_manifest_binding() {
        let (root, manifest, export, output) = fixture();
        write_export(&export, &[("base/base.cc", 10, 8)]);
        let mut options = CoverageOptions {
            manifest: manifest.clone(),
            source_root: root.join("source"),
            export,
            output: output.clone(),
            force: false,
            check: false,
        };
        generate_and_write(&options).unwrap();
        options.check = true;
        assert!(generate_and_write(&options).is_ok());
        let report = load_report(&output).unwrap();
        let manifest_model = Manifest::load(&manifest).unwrap();
        let manifest_bytes = fs::read(&manifest).unwrap();
        verify_report_manifest(&report, &manifest_model, &manifest_bytes).unwrap();

        let mut tampered = report.clone();
        tampered.totals.lines = line_coverage(10, 10);
        let tampered_path = root.join("tampered.json");
        fs::write(
            &tampered_path,
            format!("{}\n", serde_json::to_string_pretty(&tampered).unwrap()),
        )
        .unwrap();
        let tampered = load_report(&tampered_path).unwrap();
        assert!(matches!(
            verify_report_manifest(&tampered, &manifest_model, &manifest_bytes),
            Err(CoverageError::ManifestMismatch)
        ));

        fs::write(&output, "{}\n").unwrap();
        assert!(matches!(
            generate_and_write(&options),
            Err(CoverageError::Drift(_))
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_manifest_sources() {
        use std::os::unix::fs::symlink;

        let (root, manifest, export, output) = fixture();
        fs::remove_file(root.join("source/base/base.h")).unwrap();
        symlink("base.cc", root.join("source/base/base.h")).unwrap();
        write_export(&export, &[("base/base.cc", 10, 8)]);
        let result = generate(&CoverageOptions {
            manifest,
            source_root: root.join("source"),
            export,
            output,
            force: false,
            check: false,
        });
        assert!(matches!(result, Err(CoverageError::InvalidSourceFile(_))));
        fs::remove_dir_all(root).unwrap();
    }
}
