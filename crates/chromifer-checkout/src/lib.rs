#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use chromifer_manifest::normalize_repo_relative_path;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTRACT_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: u32 = 1;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutAuditOptions {
    pub workspace_root: PathBuf,
    pub contract: PathBuf,
    pub output: PathBuf,
    pub gn: Option<PathBuf>,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutContract {
    pub schema_version: u32,
    pub source_dir: String,
    pub revision: String,
    #[serde(default = "default_true")]
    pub require_clean: bool,
    #[serde(default)]
    pub metadata_files: Vec<MetadataFileContract>,
    pub gn_outputs: Vec<GnOutputContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataFileContract {
    pub path: String,
    #[serde(default)]
    pub mode: MetadataMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MetadataMode {
    #[default]
    Raw,
    WorkspaceText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GnOutputContract {
    pub id: String,
    pub directory: String,
    #[serde(default = "default_args_file")]
    pub args_file: String,
    #[serde(default = "default_project_file")]
    pub project_file: String,
    #[serde(default = "default_build_file")]
    pub build_file: String,
    pub required_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_default_toolchain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutReport {
    pub schema_version: u32,
    pub contract_sha256: String,
    pub source: SourceLock,
    pub metadata_files: Vec<FileLock>,
    pub gn_outputs: Vec<GnOutputLock>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLock {
    pub source_dir: String,
    pub revision: String,
    pub clean: bool,
    pub status_sha256: String,
    pub status_entries: usize,
    pub submodule_status_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub submodules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileLock {
    pub path: String,
    pub mode: MetadataMode,
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnOutputLock {
    pub id: String,
    pub directory: String,
    pub args: FileLock,
    pub build: FileLock,
    pub project_file: String,
    pub project_semantic_sha256: String,
    pub project_semantic_bytes: usize,
    pub build_dir: String,
    pub default_toolchain: String,
    pub target_count: usize,
    pub required_targets: Vec<GnTargetLock>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GnTargetLock {
    pub label: String,
    pub target_type: String,
    pub toolchain: String,
    pub source_count: usize,
    pub dependency_count: usize,
    pub testonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckoutAuditSummary {
    pub source_revision: String,
    pub source_clean: bool,
    pub metadata_files: usize,
    pub gn_outputs: usize,
    pub required_targets: usize,
    pub output: String,
    pub checked: bool,
    pub gn_validated_outputs: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gn_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCheckoutAudit {
    pub report_json: String,
    pub report: CheckoutReport,
    pub summary: CheckoutAuditSummary,
}

#[derive(Debug, Error)]
pub enum CheckoutError {
    #[error("workspace root `{0}` is not an accessible directory")]
    InvalidWorkspaceRoot(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect `{path}`: {source}")]
    InspectPath {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse checkout contract JSON: {0}")]
    ParseContract(#[from] serde_json::Error),
    #[error(
        "unsupported checkout contract schema version {found}; supported version is {supported}"
    )]
    UnsupportedContractSchema { found: u32, supported: u32 },
    #[error("invalid checkout contract: {0}")]
    InvalidContract(String),
    #[error("workspace path `{0}` is invalid, missing, symlinked, or outside the workspace")]
    InvalidWorkspacePath(String),
    #[error("source directory `{0}` is not a Git checkout root")]
    InvalidSourceCheckout(String),
    #[error("checkout revision `{actual}` does not match contract revision `{expected}`")]
    RevisionMismatch { actual: String, expected: String },
    #[error("checkout is dirty with {0} status entries")]
    DirtyCheckout(usize),
    #[error("Git command failed: {0}")]
    Git(String),
    #[error("GN project `{path}` is invalid: {detail}")]
    InvalidGnProject { path: String, detail: String },
    #[error("GN output `{output}` is missing required target `{target}`")]
    MissingGnTarget { output: String, target: String },
    #[error(
        "live GN target `{target}` in output `{output}` differs from the checkout lock: {detail}"
    )]
    LiveGnTargetMismatch {
        output: String,
        target: String,
        detail: String,
    },
    #[error("GN output `{output}` default toolchain `{actual}` does not match `{expected}")]
    DefaultToolchainMismatch {
        output: String,
        actual: String,
        expected: String,
    },
    #[error("failed to run GN executable `{program}`: {source}")]
    RunGn {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("GN command `{command}` failed with status {status}: {stderr}")]
    GnFailed {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("output `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("checkout lock output `{0}` must not be inside the source checkout")]
    InvalidOutputLocation(String),
    #[error("generated checkout report differs from `{0}`")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteOutput {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn audit_and_write(
    options: &CheckoutAuditOptions,
) -> Result<GeneratedCheckoutAudit, CheckoutError> {
    if options.force && options.check {
        return Err(CheckoutError::InvalidContract(
            "--force and --check are mutually exclusive".into(),
        ));
    }
    let workspace = canonical_directory(&options.workspace_root)
        .ok_or_else(|| CheckoutError::InvalidWorkspaceRoot(display(&options.workspace_root)))?;
    let contract_bytes = read_file(&options.contract)?;
    let contract: CheckoutContract = serde_json::from_slice(&contract_bytes)?;
    validate_contract(&contract)?;
    let source_relative = normalized_path(&contract.source_dir, "source_dir")?;
    let source = resolve_directory(&workspace, &source_relative)?;
    let output_path = prospective_output_path(&options.output)?;
    if output_path.starts_with(&source) {
        return Err(CheckoutError::InvalidOutputLocation(display(
            &options.output,
        )));
    }

    let source_lock = audit_source(&source, &source_relative, &contract)?;
    let metadata_files = contract
        .metadata_files
        .iter()
        .map(|entry| audit_metadata(&workspace, &source, entry))
        .collect::<Result<Vec<_>, _>>()?;

    let mut gn_outputs = Vec::with_capacity(contract.gn_outputs.len());
    let mut target_total = 0;
    for output in &contract.gn_outputs {
        let lock = audit_gn_output(&workspace, &source, output)?;
        target_total += lock.required_targets.len();
        gn_outputs.push(lock);
    }
    gn_outputs.sort_by(|left, right| left.id.cmp(&right.id));

    let report = CheckoutReport {
        schema_version: REPORT_SCHEMA_VERSION,
        contract_sha256: sha256_hex(&contract_bytes),
        source: source_lock,
        metadata_files,
        gn_outputs,
    };
    let mut report_json = serde_json::to_string_pretty(&report)?;
    report_json.push('\n');

    let (gn_validated_outputs, gn_version) = if let Some(program) = &options.gn {
        let version = validate_with_gn(program, &workspace, &source, &report.gn_outputs)?;
        (report.gn_outputs.len(), Some(version))
    } else {
        (0, None)
    };

    if options.check {
        let current = fs::read(&options.output)
            .map_err(|_| CheckoutError::Drift(display(&options.output)))?;
        if current != report_json.as_bytes() {
            return Err(CheckoutError::Drift(display(&options.output)));
        }
    } else {
        write_output(&options.output, report_json.as_bytes(), options.force)?;
    }

    let summary = CheckoutAuditSummary {
        source_revision: report.source.revision.clone(),
        source_clean: report.source.clean,
        metadata_files: report.metadata_files.len(),
        gn_outputs: report.gn_outputs.len(),
        required_targets: target_total,
        output: display(&options.output),
        checked: options.check,
        gn_validated_outputs,
        gn_version,
    };
    Ok(GeneratedCheckoutAudit {
        report_json,
        report,
        summary,
    })
}

fn validate_contract(contract: &CheckoutContract) -> Result<(), CheckoutError> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(CheckoutError::UnsupportedContractSchema {
            found: contract.schema_version,
            supported: CONTRACT_SCHEMA_VERSION,
        });
    }
    normalized_path(&contract.source_dir, "source_dir")?;
    if !is_git_revision(&contract.revision) {
        return Err(CheckoutError::InvalidContract(
            "revision must be a 40- or 64-character lowercase hexadecimal Git object ID".into(),
        ));
    }
    let mut metadata_paths = BTreeSet::new();
    for file in &contract.metadata_files {
        let path = normalized_path(&file.path, "metadata file")?;
        if !metadata_paths.insert(path) {
            return Err(CheckoutError::InvalidContract(format!(
                "duplicate metadata path `{}`",
                file.path
            )));
        }
    }
    if contract.gn_outputs.is_empty() {
        return Err(CheckoutError::InvalidContract(
            "at least one GN output must be declared".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for output in &contract.gn_outputs {
        if output.id.trim().is_empty() || output.id.trim() != output.id {
            return Err(CheckoutError::InvalidContract(
                "GN output IDs must be non-empty and contain no surrounding whitespace".into(),
            ));
        }
        if !ids.insert(output.id.clone()) {
            return Err(CheckoutError::InvalidContract(format!(
                "duplicate GN output ID `{}`",
                output.id
            )));
        }
        let directory = normalized_path(&output.directory, "GN output directory")?;
        if !directories.insert(directory) {
            return Err(CheckoutError::InvalidContract(format!(
                "duplicate GN output directory `{}`",
                output.directory
            )));
        }
        normalized_path(&output.args_file, "GN args file")?;
        normalized_path(&output.project_file, "GN project file")?;
        normalized_path(&output.build_file, "GN build file")?;
        if output.required_targets.is_empty() {
            return Err(CheckoutError::InvalidContract(format!(
                "GN output `{}` has no required targets",
                output.id
            )));
        }
        let mut targets = BTreeSet::new();
        for target in &output.required_targets {
            if !is_gn_label(target) || !targets.insert(target.clone()) {
                return Err(CheckoutError::InvalidContract(format!(
                    "GN output `{}` contains invalid or duplicate target `{target}`",
                    output.id
                )));
            }
        }
        if output
            .expected_default_toolchain
            .as_ref()
            .is_some_and(|toolchain| {
                !is_gn_label(toolchain) || toolchain.contains('(') || toolchain.trim() != toolchain
            })
        {
            return Err(CheckoutError::InvalidContract(format!(
                "GN output `{}` has an invalid expected default toolchain",
                output.id
            )));
        }
    }
    Ok(())
}

fn audit_source(
    source: &Path,
    source_relative: &str,
    contract: &CheckoutContract,
) -> Result<SourceLock, CheckoutError> {
    let root = git_output(source, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(utf8_trimmed(root, "Git root").map_err(CheckoutError::Git)?);
    let canonical_root = root
        .canonicalize()
        .map_err(|_| CheckoutError::InvalidSourceCheckout(display(source)))?;
    if canonical_root != source {
        return Err(CheckoutError::InvalidSourceCheckout(display(source)));
    }
    let revision = utf8_trimmed(
        git_output(source, &["rev-parse", "--verify", "HEAD"])?,
        "Git revision",
    )
    .map_err(CheckoutError::Git)?;
    if revision != contract.revision {
        return Err(CheckoutError::RevisionMismatch {
            actual: revision,
            expected: contract.revision.clone(),
        });
    }
    let status = git_output(
        source,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    let status_entries = count_porcelain_v2_entries(&status)?;
    if contract.require_clean && status_entries > 0 {
        return Err(CheckoutError::DirtyCheckout(status_entries));
    }
    let submodule_status = git_output(source, &["submodule", "status", "--recursive"])?;
    let submodules = String::from_utf8_lossy(&submodule_status)
        .lines()
        .map(str::to_owned)
        .collect();
    Ok(SourceLock {
        source_dir: source_relative.to_owned(),
        revision: contract.revision.clone(),
        clean: status_entries == 0,
        status_sha256: sha256_hex(&status),
        status_entries,
        submodule_status_sha256: sha256_hex(&submodule_status),
        submodules,
    })
}

fn audit_metadata(
    workspace: &Path,
    source: &Path,
    contract: &MetadataFileContract,
) -> Result<FileLock, CheckoutError> {
    let relative = normalized_path(&contract.path, "metadata file")?;
    let path = resolve_file(workspace, &relative)?;
    let bytes = read_file(&path)?;
    let normalized = match contract.mode {
        MetadataMode::Raw => bytes,
        MetadataMode::WorkspaceText => {
            normalize_workspace_text(&bytes, workspace, source, &relative)?
        }
    };
    Ok(FileLock {
        path: relative,
        mode: contract.mode,
        sha256: sha256_hex(&normalized),
        bytes: normalized.len(),
    })
}

fn audit_gn_output(
    workspace: &Path,
    source: &Path,
    contract: &GnOutputContract,
) -> Result<GnOutputLock, CheckoutError> {
    let directory = normalized_path(&contract.directory, "GN output directory")?;
    let directory_path = resolve_directory(workspace, &directory)?;
    if !directory_path.starts_with(source) {
        return Err(CheckoutError::InvalidContract(format!(
            "GN output `{}` must be inside the source checkout",
            contract.id
        )));
    }
    let args_relative = join_normalized(&directory, &contract.args_file)?;
    let project_relative = join_normalized(&directory, &contract.project_file)?;
    let build_relative = join_normalized(&directory, &contract.build_file)?;
    let args_path = resolve_file(workspace, &args_relative)?;
    let project_path = resolve_file(workspace, &project_relative)?;
    let build_path = resolve_file(workspace, &build_relative)?;
    let args_bytes = read_file(&args_path)?;
    let build_bytes = read_file(&build_path)?;
    let project_bytes = read_file(&project_path)?;
    let mut project: Value = serde_json::from_slice(&project_bytes).map_err(|error| {
        CheckoutError::InvalidGnProject {
            path: project_relative.clone(),
            detail: error.to_string(),
        }
    })?;
    let build_settings = project
        .get("build_settings")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_project(&project_relative, "missing build_settings object"))?;
    let root_path = build_settings
        .get("root_path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_project(&project_relative, "missing build_settings.root_path"))?;
    let canonical_root = Path::new(root_path).canonicalize().map_err(|error| {
        invalid_project(
            &project_relative,
            &format!("root_path `{root_path}` could not be resolved: {error}"),
        )
    })?;
    if canonical_root != source {
        return Err(invalid_project(
            &project_relative,
            "build_settings.root_path does not match the source checkout",
        ));
    }
    let build_dir = string_field(build_settings, "build_dir", &project_relative)?;
    let default_toolchain = string_field(build_settings, "default_toolchain", &project_relative)?;
    let source_relative_directory = directory_path
        .strip_prefix(source)
        .map_err(|_| invalid_project(&project_relative, "output directory is outside source"))?;
    let expected_build_dir = format!(
        "//{}/",
        source_relative_directory
            .to_string_lossy()
            .replace('\\', "/")
    );
    if build_dir != expected_build_dir {
        return Err(invalid_project(
            &project_relative,
            &format!("build_dir `{build_dir}` does not match `{expected_build_dir}`"),
        ));
    }
    if let Some(expected) = &contract.expected_default_toolchain {
        if &default_toolchain != expected {
            return Err(CheckoutError::DefaultToolchainMismatch {
                output: contract.id.clone(),
                actual: default_toolchain,
                expected: expected.clone(),
            });
        }
    }
    let args_label = format!(
        "//{}/{}",
        source_relative_directory
            .to_string_lossy()
            .replace('\\', "/"),
        contract.args_file
    );
    let gen_inputs = build_settings
        .get("gen_input_files")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid_project(&project_relative, "missing build_settings.gen_input_files")
        })?;
    if !gen_inputs
        .iter()
        .any(|value| value.as_str() == Some(&args_label))
    {
        return Err(invalid_project(
            &project_relative,
            &format!("gen_input_files does not contain `{args_label}`"),
        ));
    }
    let targets = project
        .get("targets")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_project(&project_relative, "missing targets object"))?;
    let target_count = targets.len();
    let mut required_targets = Vec::new();
    for label in &contract.required_targets {
        let (actual_label, target) =
            find_target(targets, label, &default_toolchain).ok_or_else(|| {
                CheckoutError::MissingGnTarget {
                    output: contract.id.clone(),
                    target: label.clone(),
                }
            })?;
        let object = target.as_object().ok_or_else(|| {
            invalid_project(
                &project_relative,
                &format!("target `{actual_label}` is not an object"),
            )
        })?;
        required_targets.push(GnTargetLock {
            label: actual_label,
            target_type: string_field(object, "type", &project_relative)?,
            toolchain: object
                .get("toolchain")
                .and_then(Value::as_str)
                .unwrap_or(&default_toolchain)
                .to_owned(),
            source_count: object
                .get("sources")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            dependency_count: object
                .get("deps")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            testonly: object
                .get("testonly")
                .or_else(|| object.get("test_only"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        });
    }
    required_targets.sort();

    normalize_project_paths(&mut project, workspace, source);
    let semantic = canonical_json(&project)?;
    Ok(GnOutputLock {
        id: contract.id.clone(),
        directory,
        args: file_lock(args_relative, MetadataMode::Raw, &args_bytes),
        build: file_lock(build_relative, MetadataMode::Raw, &build_bytes),
        project_file: project_relative,
        project_semantic_sha256: sha256_hex(&semantic),
        project_semantic_bytes: semantic.len(),
        build_dir,
        default_toolchain,
        target_count,
        required_targets,
    })
}

fn validate_with_gn(
    program: &Path,
    workspace: &Path,
    source: &Path,
    outputs: &[GnOutputLock],
) -> Result<String, CheckoutError> {
    let version = run_gn(program, source, &["--version"])?;
    let version = utf8_trimmed(version, "GN version").map_err(CheckoutError::InvalidContract)?;
    for output in outputs {
        let source_relative =
            source_relative_output(workspace, source, Path::new(&output.directory))?;
        run_gn(
            program,
            source,
            &[
                "args",
                &source_relative,
                "--list",
                "--short",
                "--overrides-only",
            ],
        )?;
        for target in &output.required_targets {
            let labels = run_gn(program, source, &["ls", &source_relative, &target.label])?;
            let found = String::from_utf8_lossy(&labels)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .any(|label| gn_labels_equivalent(label, &target.label));
            if !found {
                return Err(CheckoutError::MissingGnTarget {
                    output: output.id.clone(),
                    target: target.label.clone(),
                });
            }
            validate_live_gn_target(program, source, &source_relative, output, target)?;
        }
    }
    Ok(version)
}

fn validate_live_gn_target(
    program: &Path,
    source: &Path,
    output_dir: &str,
    output: &GnOutputLock,
    expected: &GnTargetLock,
) -> Result<(), CheckoutError> {
    let bytes = run_gn(
        program,
        source,
        &["desc", output_dir, &expected.label, "--format=json"],
    )?;
    let project: Value =
        serde_json::from_slice(&bytes).map_err(|error| CheckoutError::LiveGnTargetMismatch {
            output: output.id.clone(),
            target: expected.label.clone(),
            detail: format!("GN desc output is not valid JSON: {error}"),
        })?;
    let targets = project
        .as_object()
        .ok_or_else(|| CheckoutError::LiveGnTargetMismatch {
            output: output.id.clone(),
            target: expected.label.clone(),
            detail: "GN desc output is not a target object".into(),
        })?;
    let (_, target) =
        find_target(targets, &expected.label, &output.default_toolchain).ok_or_else(|| {
            CheckoutError::MissingGnTarget {
                output: output.id.clone(),
                target: expected.label.clone(),
            }
        })?;
    let object = target
        .as_object()
        .ok_or_else(|| CheckoutError::LiveGnTargetMismatch {
            output: output.id.clone(),
            target: expected.label.clone(),
            detail: "GN desc target is not an object".into(),
        })?;
    let target_type = object
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CheckoutError::LiveGnTargetMismatch {
            output: output.id.clone(),
            target: expected.label.clone(),
            detail: "GN desc target has no non-empty type".into(),
        })?;
    let actual = GnTargetLock {
        label: expected.label.clone(),
        target_type: target_type.to_owned(),
        toolchain: object
            .get("toolchain")
            .and_then(Value::as_str)
            .unwrap_or(&output.default_toolchain)
            .to_owned(),
        source_count: object
            .get("sources")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        dependency_count: object
            .get("deps")
            .and_then(Value::as_array)
            .map_or(0, Vec::len),
        testonly: object
            .get("testonly")
            .or_else(|| object.get("test_only"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    if &actual != expected {
        return Err(CheckoutError::LiveGnTargetMismatch {
            output: output.id.clone(),
            target: expected.label.clone(),
            detail: format!("expected {expected:?}, found {actual:?}"),
        });
    }
    Ok(())
}

fn source_relative_output(
    workspace: &Path,
    source: &Path,
    workspace_relative: &Path,
) -> Result<String, CheckoutError> {
    let absolute = workspace.join(workspace_relative);
    let relative = absolute.strip_prefix(source).map_err(|_| {
        CheckoutError::InvalidContract(format!(
            "GN output `{}` is outside the source checkout",
            workspace_relative.display()
        ))
    })?;
    Ok(relative.to_string_lossy().replace('\\', "/"))
}

fn run_gn(program: &Path, cwd: &Path, args: &[&str]) -> Result<Vec<u8>, CheckoutError> {
    let output = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|source| CheckoutError::RunGn {
            program: display(program),
            source,
        })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CheckoutError::GnFailed {
            command: format!("{} {}", display(program), args.join(" ")),
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

fn normalize_project_paths(value: &mut Value, workspace: &Path, source: &Path) {
    match value {
        Value::String(text) => {
            *text = normalize_text_paths(text, workspace, source);
        }
        Value::Array(values) => {
            for value in values {
                normalize_project_paths(value, workspace, source);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                normalize_project_paths(value, workspace, source);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn normalize_workspace_text(
    bytes: &[u8],
    workspace: &Path,
    source: &Path,
    relative: &str,
) -> Result<Vec<u8>, CheckoutError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        CheckoutError::InvalidContract(format!(
            "workspace_text metadata `{relative}` is not valid UTF-8"
        ))
    })?;
    Ok(normalize_text_paths(text, workspace, source).into_bytes())
}

fn normalize_text_paths(text: &str, workspace: &Path, source: &Path) -> String {
    let mut normalized = text.replace("\r\n", "\n");
    let source_native = display(source);
    let workspace_native = display(workspace);
    let source_slash = source_native.replace('\\', "/");
    let workspace_slash = workspace_native.replace('\\', "/");
    for (from, to) in [
        (source_native.as_str(), "${SOURCE}"),
        (source_slash.as_str(), "${SOURCE}"),
        (workspace_native.as_str(), "${WORKSPACE}"),
        (workspace_slash.as_str(), "${WORKSPACE}"),
    ] {
        if !from.is_empty() {
            normalized = normalized.replace(from, to);
        }
    }
    normalized
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, CheckoutError> {
    fn write(value: &Value, output: &mut Vec<u8>) -> Result<(), serde_json::Error> {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
            Value::String(value) => serde_json::to_writer(&mut *output, value)?,
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    write(value, output)?;
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut entries: Vec<_> = values.iter().collect();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        output.push(b',');
                    }
                    serde_json::to_writer(&mut *output, key)?;
                    output.push(b':');
                    write(value, output)?;
                }
                output.push(b'}');
            }
        }
        Ok(())
    }
    let mut output = Vec::new();
    write(value, &mut output)?;
    Ok(output)
}

fn find_target<'a>(
    targets: &'a serde_json::Map<String, Value>,
    requested: &str,
    default_toolchain: &str,
) -> Option<(String, &'a Value)> {
    if let Some(target) = targets.get(requested) {
        return Some((requested.to_owned(), target));
    }
    if requested.contains('(') {
        return None;
    }
    let mut matches = targets.iter().filter(|(label, target)| {
        strip_toolchain(label) == requested
            && target
                .get("toolchain")
                .and_then(Value::as_str)
                .is_none_or(|toolchain| toolchain == default_toolchain)
    });
    let first = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some((first.0.clone(), first.1))
    }
}

fn strip_toolchain(label: &str) -> &str {
    label.split_once('(').map_or(label, |(base, _)| base)
}

fn gn_labels_equivalent(actual: &str, requested: &str) -> bool {
    actual == requested || (!requested.contains('(') && strip_toolchain(actual) == requested)
}

fn file_lock(path: String, mode: MetadataMode, bytes: &[u8]) -> FileLock {
    FileLock {
        path,
        mode,
        sha256: sha256_hex(bytes),
        bytes: bytes.len(),
    }
}

fn invalid_project(path: &str, detail: &str) -> CheckoutError {
    CheckoutError::InvalidGnProject {
        path: path.to_owned(),
        detail: detail.to_owned(),
    }
}

fn string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
    path: &str,
) -> Result<String, CheckoutError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid_project(path, &format!("missing or empty `{field}`")))
}

fn git_output(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, CheckoutError> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|error| CheckoutError::Git(format!("failed to launch git: {error}")))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(CheckoutError::Git(format!(
            "git {} failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn count_porcelain_v2_entries(status: &[u8]) -> Result<usize, CheckoutError> {
    let fields: Vec<_> = status
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect();
    let mut count = 0;
    let mut index = 0;
    while index < fields.len() {
        let kind = fields[index]
            .first()
            .copied()
            .ok_or_else(|| CheckoutError::Git("git status contained an empty record".into()))?;
        if !matches!(kind, b'1' | b'2' | b'u' | b'?' | b'!') {
            return Err(CheckoutError::Git(format!(
                "git status contained unknown record type `{}`",
                kind as char
            )));
        }
        count += 1;
        index += if kind == b'2' { 2 } else { 1 };
        if index > fields.len() {
            return Err(CheckoutError::Git(
                "git rename/copy record is missing its original path".into(),
            ));
        }
    }
    Ok(count)
}

fn resolve_file(root: &Path, relative: &str) -> Result<PathBuf, CheckoutError> {
    reject_symlink_components(root, relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| CheckoutError::InvalidWorkspacePath(relative.to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| CheckoutError::InvalidWorkspacePath(relative.to_owned()))?;
    if !canonical.starts_with(root) {
        return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
    }
    Ok(canonical)
}

fn resolve_directory(root: &Path, relative: &str) -> Result<PathBuf, CheckoutError> {
    reject_symlink_components(root, relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| CheckoutError::InvalidWorkspacePath(relative.to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|_| CheckoutError::InvalidWorkspacePath(relative.to_owned()))?;
    if !canonical.starts_with(root) {
        return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
    }
    Ok(canonical)
}

fn reject_symlink_components(root: &Path, relative: &str) -> Result<(), CheckoutError> {
    let mut current = root.to_path_buf();
    for component in Path::new(relative).components() {
        let Component::Normal(component) = component else {
            return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| CheckoutError::InvalidWorkspacePath(relative.to_owned()))?;
        if metadata.file_type().is_symlink() {
            return Err(CheckoutError::InvalidWorkspacePath(relative.to_owned()));
        }
    }
    Ok(())
}

fn canonical_directory(path: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    path.canonicalize().ok()
}

fn prospective_output_path(path: &Path) -> Result<PathBuf, CheckoutError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| CheckoutError::InvalidOutputLocation(display(path)))?
            .join(path)
    };
    let filename = absolute
        .file_name()
        .ok_or_else(|| CheckoutError::InvalidOutputLocation(display(path)))?
        .to_owned();
    let mut parent = absolute
        .parent()
        .ok_or_else(|| CheckoutError::InvalidOutputLocation(display(path)))?;
    let mut missing = Vec::new();
    while !parent.exists() {
        let component = parent
            .file_name()
            .ok_or_else(|| CheckoutError::InvalidOutputLocation(display(path)))?;
        missing.push(component.to_owned());
        parent = parent
            .parent()
            .ok_or_else(|| CheckoutError::InvalidOutputLocation(display(path)))?;
    }
    let mut canonical = parent
        .canonicalize()
        .map_err(|_| CheckoutError::InvalidOutputLocation(display(path)))?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    canonical.push(filename);
    Ok(canonical)
}

fn normalized_path(value: &str, field: &str) -> Result<String, CheckoutError> {
    normalize_repo_relative_path(value).ok_or_else(|| {
        CheckoutError::InvalidContract(format!(
            "{field} `{value}` is not a normalized relative path"
        ))
    })
}

fn join_normalized(parent: &str, child: &str) -> Result<String, CheckoutError> {
    normalized_path(&format!("{parent}/{child}"), "joined workspace path")
}

fn is_git_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_gn_label(value: &str) -> bool {
    value.starts_with("//")
        && value.trim() == value
        && !value.contains(char::is_whitespace)
        && !value.contains("..")
        && value.contains(':')
}

fn default_true() -> bool {
    true
}
fn default_args_file() -> String {
    "args.gn".into()
}
fn default_project_file() -> String {
    "project.json".into()
}
fn default_build_file() -> String {
    "build.ninja".into()
}

fn read_file(path: &Path) -> Result<Vec<u8>, CheckoutError> {
    fs::read(path).map_err(|source| CheckoutError::ReadFile {
        path: display(path),
        source,
    })
}

fn write_output(path: &Path, bytes: &[u8], force: bool) -> Result<(), CheckoutError> {
    if path.exists() && !force {
        return Err(CheckoutError::OutputExists(display(path)));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| CheckoutError::WriteOutput {
            path: display(parent),
            source,
        })?;
    }
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let temp = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|source| CheckoutError::WriteOutput {
                path: display(&temp),
                source,
            })?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| CheckoutError::WriteOutput {
                path: display(&temp),
                source,
            })?;
        if force && path.exists() {
            fs::remove_file(path).map_err(|source| CheckoutError::WriteOutput {
                path: display(path),
                source,
            })?;
        }
        fs::rename(&temp, path).map_err(|source| CheckoutError::WriteOutput {
            path: display(path),
            source,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn utf8_trimmed(bytes: Vec<u8>, field: &str) -> Result<String, String> {
    let value = String::from_utf8(bytes).map_err(|_| format!("{field} is not valid UTF-8"))?;
    let value = value.trim();
    if value.is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(value.to_owned())
    }
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

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("chromifer-checkout-{}-{id}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, relative: &str, bytes: impl AsRef<[u8]>) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn git(cwd: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn commit_fixture(cwd: &Path) {
        let output = Command::new("git")
            .current_dir(cwd)
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
            .args([
                "-c",
                "user.name=Chromifer Test",
                "-c",
                "user.email=chromifer@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn fixture() -> (TempTree, String) {
        let tree = TempTree::new();
        tree.write("src/.gitignore", b"/out/\n");
        tree.write("src/DEPS", b"vars = {}\n");
        tree.write("src/BUILD.gn", b"group(\"all\") {}\n");
        tree.write(".gclient", b"solutions = [{ 'name': 'src' }]\n");
        git(&tree.root.join("src"), &["init", "-q"]);
        git(&tree.root.join("src"), &["add", "."]);
        commit_fixture(&tree.root.join("src"));
        let revision = String::from_utf8(git(&tree.root.join("src"), &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        let source = tree.root.join("src").canonicalize().unwrap();
        tree.write(
            ".gclient_entries",
            format!("entries = {{r'{}': 'src'}}\n", source.display()),
        );
        tree.write("src/out/Default/args.gn", b"is_debug = false\n");
        tree.write(
            "src/out/Default/build.ninja",
            b"rule noop\n  command = true\n",
        );
        let project = serde_json::json!({
            "build_settings": {
                "root_path": source,
                "build_dir": "//out/Default/",
                "default_toolchain": "//build/toolchain/linux:clang_x64",
                "gen_input_files": ["//.gn", "//BUILD.gn", "//out/Default/args.gn"]
            },
            "targets": {
                "//app:browser": {
                    "type": "executable",
                    "toolchain": "//build/toolchain/linux:clang_x64",
                    "sources": ["//app/main.cc"],
                    "deps": ["//base:base"]
                },
                "//base:base": {
                    "type": "source_set",
                    "toolchain": "//build/toolchain/linux:clang_x64",
                    "sources": ["//base/base.cc"],
                    "deps": []
                }
            }
        });
        tree.write(
            "src/out/Default/project.json",
            serde_json::to_vec_pretty(&project).unwrap(),
        );
        let contract = CheckoutContract {
            schema_version: 1,
            source_dir: "src".into(),
            revision: revision.clone(),
            require_clean: true,
            metadata_files: vec![
                MetadataFileContract {
                    path: "src/DEPS".into(),
                    mode: MetadataMode::Raw,
                },
                MetadataFileContract {
                    path: ".gclient".into(),
                    mode: MetadataMode::Raw,
                },
                MetadataFileContract {
                    path: ".gclient_entries".into(),
                    mode: MetadataMode::WorkspaceText,
                },
            ],
            gn_outputs: vec![GnOutputContract {
                id: "linux-release".into(),
                directory: "src/out/Default".into(),
                args_file: "args.gn".into(),
                project_file: "project.json".into(),
                build_file: "build.ninja".into(),
                required_targets: vec!["//app:browser".into(), "//base:base".into()],
                expected_default_toolchain: Some("//build/toolchain/linux:clang_x64".into()),
            }],
        };
        tree.write(
            "contract.json",
            format!("{}\n", serde_json::to_string_pretty(&contract).unwrap()),
        );
        (tree, revision)
    }

    fn options(tree: &TempTree) -> CheckoutAuditOptions {
        CheckoutAuditOptions {
            workspace_root: tree.root.clone(),
            contract: tree.root.join("contract.json"),
            output: tree.root.join("checkout-lock.json"),
            gn: None,
            force: false,
            check: false,
        }
    }

    #[test]
    fn generates_deterministic_checkout_lock_and_normalizes_workspace_paths() {
        let (first, revision) = fixture();
        let generated = audit_and_write(&options(&first)).unwrap();
        assert_eq!(generated.report.source.revision, revision);
        assert!(generated.report.source.clean);
        assert_eq!(generated.report.gn_outputs[0].required_targets.len(), 2);
        assert!(!generated.report_json.contains(&display(&first.root)));

        let (second, _) = fixture();
        let second_generated = audit_and_write(&options(&second)).unwrap();
        assert_eq!(generated.report_json, second_generated.report_json);

        let mut check = options(&first);
        check.check = true;
        audit_and_write(&check).unwrap();
    }

    #[test]
    fn detects_metadata_gn_output_and_checkout_drift() {
        let (tree, _) = fixture();
        audit_and_write(&options(&tree)).unwrap();
        fs::write(
            tree.root.join("src/out/Default/args.gn"),
            b"is_debug = true\n",
        )
        .unwrap();
        let mut check = options(&tree);
        check.check = true;
        assert!(matches!(
            audit_and_write(&check),
            Err(CheckoutError::Drift(_))
        ));

        fs::write(tree.root.join("src/tracked.txt"), b"dirty\n").unwrap();
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::DirtyCheckout(_))
        ));
    }

    #[test]
    fn rejects_revision_toolchain_target_and_build_directory_mismatches() {
        let (tree, _) = fixture();
        let mut contract: CheckoutContract =
            serde_json::from_slice(&fs::read(tree.root.join("contract.json")).unwrap()).unwrap();
        contract.revision = "0000000000000000000000000000000000000000".into();
        tree.write(
            "contract.json",
            serde_json::to_vec_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::RevisionMismatch { .. })
        ));

        let (tree, _) = fixture();
        let mut contract: CheckoutContract =
            serde_json::from_slice(&fs::read(tree.root.join("contract.json")).unwrap()).unwrap();
        contract.gn_outputs[0]
            .required_targets
            .push("//missing:target".into());
        tree.write(
            "contract.json",
            serde_json::to_vec_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::MissingGnTarget { .. })
        ));

        let (tree, _) = fixture();
        let mut project: Value = serde_json::from_slice(
            &fs::read(tree.root.join("src/out/Default/project.json")).unwrap(),
        )
        .unwrap();
        project["build_settings"]["build_dir"] = Value::String("//out/Wrong/".into());
        tree.write(
            "src/out/Default/project.json",
            serde_json::to_vec_pretty(&project).unwrap(),
        );
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::InvalidGnProject { .. })
        ));
    }

    #[test]
    fn rejects_source_internal_outputs_and_reports_missing_lock_as_drift() {
        let (tree, _) = fixture();
        let mut inside = options(&tree);
        inside.output = tree.root.join("src/out/checkout-lock.json");
        assert!(matches!(
            audit_and_write(&inside),
            Err(CheckoutError::InvalidOutputLocation(_))
        ));

        let mut missing = options(&tree);
        missing.check = true;
        assert!(matches!(
            audit_and_write(&missing),
            Err(CheckoutError::Drift(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_workspace_inputs() {
        use std::os::unix::fs::symlink;
        let (tree, _) = fixture();
        let outside = tree.root.join("outside");
        fs::write(&outside, b"outside\n").unwrap();
        fs::remove_file(tree.root.join(".gclient")).unwrap();
        symlink(&outside, tree.root.join(".gclient")).unwrap();
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::InvalidWorkspacePath(_))
        ));

        let (tree, _) = fixture();
        fs::create_dir_all(tree.root.join("real-meta")).unwrap();
        fs::write(tree.root.join("real-meta/value"), b"value\n").unwrap();
        symlink(tree.root.join("real-meta"), tree.root.join("alias-meta")).unwrap();
        let mut contract: CheckoutContract =
            serde_json::from_slice(&fs::read(tree.root.join("contract.json")).unwrap()).unwrap();
        contract.metadata_files.push(MetadataFileContract {
            path: "alias-meta/value".into(),
            mode: MetadataMode::Raw,
        });
        tree.write(
            "contract.json",
            serde_json::to_vec_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            audit_and_write(&options(&tree)),
            Err(CheckoutError::InvalidWorkspacePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn optional_gn_validation_checks_required_targets() {
        use std::os::unix::fs::PermissionsExt;
        let (tree, _) = fixture();
        let fake = tree.root.join("gn");
        fs::write(
            &fake,
            b"#!/bin/sh\ncase \"$1\" in\n  --version) echo 'fixture-gn' ;;\n  args) exit 0 ;;\n  ls) printf '%s\\n' '//app:browser' '//base:base' ;;\n  desc)\n    case \"$3\" in\n      '//app:browser') printf '%s\\n' '{\"//app:browser\":{\"type\":\"executable\",\"toolchain\":\"//build/toolchain/linux:clang_x64\",\"sources\":[\"//app/main.cc\"],\"deps\":[\"//base:base\"],\"testonly\":false}}' ;;\n      '//base:base') printf '%s\\n' '{\"//base:base\":{\"type\":\"source_set\",\"toolchain\":\"//build/toolchain/linux:clang_x64\",\"sources\":[\"//base/base.cc\"],\"deps\":[],\"testonly\":false}}' ;;\n      *) exit 3 ;;\n    esac ;;\n  *) exit 2 ;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let mut options = options(&tree);
        options.gn = Some(fake);
        let generated = audit_and_write(&options).unwrap();
        assert_eq!(generated.summary.gn_validated_outputs, 1);
        assert_eq!(generated.summary.gn_version.as_deref(), Some("fixture-gn"));

        fs::write(
            options.gn.as_ref().unwrap(),
            b"#!/bin/sh\ncase \"$1\" in\n  --version) echo 'fixture-gn' ;;\n  args) exit 0 ;;\n  ls) printf '%s\\n' '//app:browser' '//base:base' ;;\n  desc) printf '%s\\n' '{\"//app:browser\":{\"type\":\"source_set\",\"toolchain\":\"//build/toolchain/linux:clang_x64\",\"sources\":[\"//app/main.cc\"],\"deps\":[\"//base:base\"],\"testonly\":false}}' ;;\n  *) exit 2 ;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(
            options.gn.as_ref().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let mut check = options;
        check.check = true;
        assert!(matches!(
            audit_and_write(&check),
            Err(CheckoutError::LiveGnTargetMismatch { .. })
        ));
    }
}
