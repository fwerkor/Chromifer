#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chromifer_manifest::{CompatibilityGate, GateExecution, GateInput, Manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_SCHEMA_VERSION: u32 = 3;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub workdir: PathBuf,
    pub output_dir: PathBuf,
    pub gate_ids: Vec<String>,
    pub module_ids: Vec<String>,
    pub fail_fast: bool,
    pub timeout: Duration,
    pub max_tail_bytes: usize,
    pub attest_checkout: bool,
    pub expected_revision: Option<String>,
    pub require_clean_checkout: bool,
    pub attest_executables: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRun {
    pub digest: String,
    pub path: PathBuf,
    pub bundle: EvidenceBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub project: String,
    pub baseline: String,
    pub manifest_sha256: String,
    pub started_unix_ms: u128,
    pub finished_unix_ms: u128,
    pub duration_ms: u128,
    pub host: HostFingerprint,
    pub workdir: String,
    pub attestation_policy: AttestationPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout: Option<CheckoutAttestation>,
    pub selected_gates: Vec<String>,
    pub skipped_gates: Vec<String>,
    pub fail_fast: bool,
    pub timeout_ms: u128,
    pub passed: bool,
    pub gates: Vec<GateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostFingerprint {
    pub operating_system: String,
    pub architecture: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub checkout: bool,
    pub require_clean_checkout: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<String>,
    pub executables: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutAttestation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<ExecutableAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<GitSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<GitSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitSnapshot {
    pub root: String,
    pub revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub dirty: bool,
    pub status_sha256: String,
    pub status_entries: usize,
    pub submodule_status_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub submodules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableAttestation {
    pub requested_program: String,
    pub invocation_path: String,
    pub resolved_path: String,
    pub before: FileIdentity,
    pub after: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub sha256: String,
    pub bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvidence {
    pub gate: String,
    pub execution: GateExecution,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<GateInput>,
    pub declared_targets: Vec<String>,
    pub status: GateStatus,
    pub exit_code: Option<i32>,
    pub started_unix_ms: u128,
    pub duration_ms: u128,
    pub stdout: OutputArtifact,
    pub stderr: OutputArtifact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<ExecutableAttestation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Failed,
    TimedOut,
    LaunchFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputArtifact {
    pub sha256: String,
    pub bytes: usize,
    pub path: String,
    pub tail_start_byte: usize,
    pub tail: String,
    pub tail_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationSummary {
    pub digest: String,
    pub passed: bool,
    pub gate_count: usize,
    pub log_count: usize,
    pub passed_gates: Vec<String>,
    pub checkout_attested: bool,
    pub executables_attested: usize,
    pub live_attestation_verified: bool,
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("working directory `{0}` is not a directory")]
    InvalidWorkdir(String),
    #[error("unknown compatibility gate `{0}`")]
    UnknownGate(String),
    #[error("unknown module `{0}`")]
    UnknownModule(String),
    #[error("no compatibility gates were selected")]
    NoGatesSelected,
    #[error("invalid attestation options: {0}")]
    InvalidAttestationOptions(String),
    #[error("failed to create evidence directory `{path}`: {source}")]
    CreateDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to create temporary output `{path}`: {source}")]
    CreateTemporaryOutput {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect gate process `{gate}`: {source}")]
    InspectProcess {
        gate: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read gate output `{path}`: {source}")]
    ReadOutput {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write content-addressed artifact `{path}`: {source}")]
    WriteArtifact {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to encode or decode evidence JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence file `{path}` is not named with its SHA-256 digest `{actual}`")]
    EvidenceDigestMismatch { path: String, actual: String },
    #[error("unsupported evidence schema version {found}; supported version is {supported}")]
    UnsupportedEvidenceSchema { found: u32, supported: u32 },
    #[error("evidence project or baseline does not match the manifest")]
    ManifestIdentityMismatch,
    #[error("evidence manifest digest does not match the supplied manifest")]
    ManifestDigestMismatch,
    #[error("evidence references unknown gate `{0}`")]
    EvidenceUnknownGate(String),
    #[error("evidence gate `{0}` no longer matches its manifest command or targets")]
    GateDefinitionMismatch(String),
    #[error("evidence selected/executed/skipped gate sets are inconsistent")]
    InconsistentGateSets,
    #[error("evidence `passed` value is inconsistent with recorded gate results")]
    InconsistentPassStatus,
    #[error("artifact path `{0}` is not a safe relative path")]
    UnsafeArtifactPath(String),
    #[error("artifact `{path}` has size or digest mismatch")]
    ArtifactDigestMismatch { path: String },
    #[error("artifact `{path}` tail metadata does not match its content")]
    ArtifactMetadataMismatch { path: String },
    #[error("checkout attestation is inconsistent: {0}")]
    CheckoutAttestationMismatch(String),
    #[error("executable attestation for gate `{gate}` is inconsistent: {detail}")]
    ExecutableAttestationMismatch { gate: String, detail: String },
    #[error("live checkout does not match the evidence: {0}")]
    LiveCheckoutMismatch(String),
    #[error("live executable for gate `{gate}` does not match the evidence")]
    LiveExecutableMismatch { gate: String },
}

#[derive(Debug)]
struct CheckoutRuntime {
    git_invocation_path: PathBuf,
    git_resolved_path: PathBuf,
    git_before: FileIdentity,
    before: GitSnapshot,
}

#[derive(Debug)]
struct ExecutableRuntime {
    requested_program: String,
    invocation_path: PathBuf,
    resolved_path: PathBuf,
    before: FileIdentity,
}

#[derive(Debug)]
struct ResolvedExecutable {
    invocation_path: PathBuf,
    resolved_path: PathBuf,
}

pub fn run_gates(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    options: &RunOptions,
) -> Result<EvidenceRun, EvidenceError> {
    validate_attestation_options(options)?;
    if !options.workdir.is_dir() {
        return Err(EvidenceError::InvalidWorkdir(
            options.workdir.display().to_string(),
        ));
    }
    create_dir(&options.output_dir)?;
    create_dir(&options.output_dir.join("logs"))?;
    create_dir(&options.output_dir.join("evidence"))?;
    create_dir(&options.output_dir.join(".tmp"))?;

    let selected = select_gates(manifest, &options.gate_ids, &options.module_ids)?;
    let selected_ids: Vec<_> = selected.iter().map(|gate| gate.id.clone()).collect();
    let attestation_policy = AttestationPolicy {
        checkout: options.attest_checkout,
        require_clean_checkout: options.require_clean_checkout,
        expected_revision: options.expected_revision.clone(),
        executables: options.attest_executables,
    };
    let (checkout_runtime, checkout_preflight_error) = if options.attest_checkout {
        match begin_checkout_attestation(&options.workdir) {
            Ok(runtime) => {
                let error = validate_checkout_preflight(&runtime.before, options);
                (Some(runtime), error)
            }
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    let started = unix_ms();
    let timer = Instant::now();
    let mut gates = Vec::with_capacity(selected.len());
    let mut skipped_gates = Vec::new();

    if checkout_preflight_error.is_some() {
        skipped_gates.extend(selected.iter().map(|gate| gate.id.clone()));
    } else {
        for (index, gate) in selected.iter().enumerate() {
            let evidence = execute_gate(gate, options)?;
            let passed = evidence.status == GateStatus::Passed;
            gates.push(evidence);
            if options.fail_fast && !passed {
                skipped_gates.extend(
                    selected[index + 1..]
                        .iter()
                        .map(|remaining| remaining.id.clone()),
                );
                break;
            }
        }
    }

    let checkout = if options.attest_checkout {
        Some(finish_checkout_attestation(
            checkout_runtime,
            &options.workdir,
            checkout_preflight_error,
        ))
    } else {
        None
    };
    let checkout_passed = checkout
        .as_ref()
        .is_none_or(|attestation| attestation.error.is_none());
    let passed = checkout_passed
        && skipped_gates.is_empty()
        && gates.len() == selected.len()
        && gates.iter().all(|gate| gate.status == GateStatus::Passed);
    let bundle = EvidenceBundle {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        project: manifest.project.name.clone(),
        baseline: manifest.project.baseline.clone(),
        manifest_sha256: sha256_hex(manifest_bytes),
        started_unix_ms: started,
        finished_unix_ms: unix_ms(),
        duration_ms: timer.elapsed().as_millis(),
        host: HostFingerprint {
            operating_system: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            shell: shell_description().to_owned(),
        },
        workdir: options.workdir.display().to_string(),
        attestation_policy,
        checkout,
        selected_gates: selected_ids,
        skipped_gates,
        fail_fast: options.fail_fast,
        timeout_ms: options.timeout.as_millis(),
        passed,
        gates,
    };

    let encoded = serde_json::to_vec_pretty(&bundle)?;
    let digest = sha256_hex(&encoded);
    let relative = PathBuf::from("evidence").join(format!("{digest}.json"));
    let path = options.output_dir.join(&relative);
    write_content_addressed(&path, &encoded)?;

    Ok(EvidenceRun {
        digest,
        path,
        bundle,
    })
}

pub fn verify_evidence(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    evidence_path: &Path,
    artifact_root: &Path,
) -> Result<VerificationSummary, EvidenceError> {
    verify_evidence_with_workdir(manifest, manifest_bytes, evidence_path, artifact_root, None)
}

pub fn verify_evidence_with_workdir(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    evidence_path: &Path,
    artifact_root: &Path,
    live_workdir: Option<&Path>,
) -> Result<VerificationSummary, EvidenceError> {
    let encoded = read_output(evidence_path)?;
    let digest = sha256_hex(&encoded);
    let named_digest = evidence_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if named_digest != digest {
        return Err(EvidenceError::EvidenceDigestMismatch {
            path: evidence_path.display().to_string(),
            actual: digest,
        });
    }

    let bundle: EvidenceBundle = serde_json::from_slice(&encoded)?;
    if bundle.schema_version != EVIDENCE_SCHEMA_VERSION {
        return Err(EvidenceError::UnsupportedEvidenceSchema {
            found: bundle.schema_version,
            supported: EVIDENCE_SCHEMA_VERSION,
        });
    }
    if bundle.project != manifest.project.name || bundle.baseline != manifest.project.baseline {
        return Err(EvidenceError::ManifestIdentityMismatch);
    }
    if bundle.manifest_sha256 != sha256_hex(manifest_bytes) {
        return Err(EvidenceError::ManifestDigestMismatch);
    }
    verify_attestation_consistency(&bundle)?;

    let selected: BTreeSet<_> = bundle.selected_gates.iter().cloned().collect();
    let executed: BTreeSet<_> = bundle.gates.iter().map(|gate| gate.gate.clone()).collect();
    let skipped: BTreeSet<_> = bundle.skipped_gates.iter().cloned().collect();
    if selected.len() != bundle.selected_gates.len()
        || executed.len() != bundle.gates.len()
        || skipped.len() != bundle.skipped_gates.len()
        || !executed.is_disjoint(&skipped)
        || executed.union(&skipped).cloned().collect::<BTreeSet<_>>() != selected
    {
        return Err(EvidenceError::InconsistentGateSets);
    }

    for gate_id in &selected {
        if manifest.gate(gate_id).is_none() {
            return Err(EvidenceError::EvidenceUnknownGate(gate_id.clone()));
        }
    }

    let mut logs = BTreeSet::new();
    let mut passed_gates = Vec::new();
    for gate in &bundle.gates {
        let definition = manifest
            .gate(&gate.gate)
            .ok_or_else(|| EvidenceError::EvidenceUnknownGate(gate.gate.clone()))?;
        if gate.execution != definition.execution
            || gate.inputs != definition.inputs
            || gate.declared_targets != definition.targets
        {
            return Err(EvidenceError::GateDefinitionMismatch(gate.gate.clone()));
        }
        verify_artifact(&gate.stdout, artifact_root)?;
        verify_artifact(&gate.stderr, artifact_root)?;
        logs.insert(gate.stdout.path.clone());
        logs.insert(gate.stderr.path.clone());
        if gate.status == GateStatus::Passed {
            passed_gates.push(gate.gate.clone());
        }
    }
    passed_gates.sort();

    let checkout_passed = bundle
        .checkout
        .as_ref()
        .is_none_or(|checkout| checkout.error.is_none());
    let computed_passed = checkout_passed
        && skipped.is_empty()
        && bundle.gates.len() == selected.len()
        && bundle
            .gates
            .iter()
            .all(|gate| gate.status == GateStatus::Passed);
    if bundle.passed != computed_passed {
        return Err(EvidenceError::InconsistentPassStatus);
    }

    let executables_attested = bundle
        .gates
        .iter()
        .filter(|gate| gate.executable.is_some())
        .count();
    let live_attestation_verified = if let Some(workdir) = live_workdir {
        verify_live_attestations(&bundle, workdir)?;
        bundle.checkout.is_some() || executables_attested > 0
    } else {
        false
    };

    Ok(VerificationSummary {
        digest: named_digest.to_owned(),
        passed: bundle.passed,
        gate_count: bundle.gates.len(),
        log_count: logs.len(),
        passed_gates,
        checkout_attested: bundle.checkout.is_some(),
        executables_attested,
        live_attestation_verified,
    })
}

fn validate_attestation_options(options: &RunOptions) -> Result<(), EvidenceError> {
    if !options.attest_checkout
        && (options.expected_revision.is_some() || options.require_clean_checkout)
    {
        return Err(EvidenceError::InvalidAttestationOptions(
            "expected revision and clean-checkout enforcement require checkout attestation".into(),
        ));
    }
    if options
        .expected_revision
        .as_ref()
        .is_some_and(|revision| revision.trim().is_empty() || revision.trim() != revision)
    {
        return Err(EvidenceError::InvalidAttestationOptions(
            "expected revision must be non-empty and contain no surrounding whitespace".into(),
        ));
    }
    Ok(())
}

fn begin_checkout_attestation(workdir: &Path) -> Result<CheckoutRuntime, String> {
    let git = resolve_executable("git", workdir)?;
    let git_before = file_identity(&git.resolved_path)?;
    let before = capture_git_snapshot(&git.invocation_path, workdir)?;
    Ok(CheckoutRuntime {
        git_invocation_path: git.invocation_path,
        git_resolved_path: git.resolved_path,
        git_before,
        before,
    })
}

fn validate_checkout_preflight(snapshot: &GitSnapshot, options: &RunOptions) -> Option<String> {
    if let Some(expected) = &options.expected_revision {
        if snapshot.revision != *expected {
            return Some(format!(
                "checkout revision {} does not match expected revision {expected}",
                snapshot.revision
            ));
        }
    }
    if options.require_clean_checkout && snapshot.dirty {
        return Some(format!(
            "checkout is dirty with {} status entr{}",
            snapshot.status_entries,
            if snapshot.status_entries == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }
    None
}

fn finish_checkout_attestation(
    runtime: Option<CheckoutRuntime>,
    workdir: &Path,
    mut error: Option<String>,
) -> CheckoutAttestation {
    let Some(runtime) = runtime else {
        return CheckoutAttestation {
            git: None,
            before: None,
            after: None,
            error,
        };
    };

    let git_after = match verify_current_resolution(
        "git",
        workdir,
        &runtime.git_invocation_path,
        &runtime.git_resolved_path,
    )
    .and_then(|()| file_identity(&runtime.git_resolved_path))
    {
        Ok(identity) => Some(identity),
        Err(current) => {
            push_attestation_error(&mut error, current);
            None
        }
    };
    let after = match capture_git_snapshot(&runtime.git_invocation_path, workdir) {
        Ok(snapshot) => Some(snapshot),
        Err(current) => {
            push_attestation_error(&mut error, current);
            None
        }
    };

    if git_after
        .as_ref()
        .is_some_and(|identity| identity != &runtime.git_before)
    {
        push_attestation_error(&mut error, "git executable changed during execution".into());
    }
    if after
        .as_ref()
        .is_some_and(|snapshot| snapshot != &runtime.before)
    {
        push_attestation_error(&mut error, "checkout state changed during execution".into());
    }

    let git = git_after.map(|after_identity| ExecutableAttestation {
        requested_program: "git".into(),
        invocation_path: display_path(&runtime.git_invocation_path),
        resolved_path: display_path(&runtime.git_resolved_path),
        before: runtime.git_before,
        after: after_identity,
    });
    CheckoutAttestation {
        git,
        before: Some(runtime.before),
        after,
        error,
    }
}

fn push_attestation_error(error: &mut Option<String>, current: String) {
    match error {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(&current);
        }
        None => *error = Some(current),
    }
}

fn capture_git_snapshot(git_path: &Path, workdir: &Path) -> Result<GitSnapshot, String> {
    let canonical_workdir = workdir
        .canonicalize()
        .map_err(|error| format!("working directory could not be resolved: {error}"))?;
    let root_bytes = run_git(git_path, workdir, &["rev-parse", "--show-toplevel"])?;
    let root_text = String::from_utf8(root_bytes)
        .map_err(|_| "git checkout root is not valid UTF-8".to_owned())?;
    let root = PathBuf::from(root_text.trim());
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("git checkout root could not be resolved: {error}"))?;
    if canonical_root != canonical_workdir {
        return Err(format!(
            "attested working directory `{}` is not the Git checkout root `{}`",
            canonical_workdir.display(),
            canonical_root.display()
        ));
    }

    let revision = utf8_trimmed(
        run_git(git_path, workdir, &["rev-parse", "--verify", "HEAD"])?,
        "git revision",
    )?;
    let branch = run_git_optional(
        git_path,
        workdir,
        &["symbolic-ref", "--short", "-q", "HEAD"],
    )?
    .map(|bytes| utf8_trimmed(bytes, "git branch"))
    .transpose()?;
    let status = run_git(
        git_path,
        workdir,
        &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    let submodule_status = run_git(git_path, workdir, &["submodule", "status", "--recursive"])?;
    let status_entries = count_porcelain_v2_entries(&status)?;
    let submodules = String::from_utf8_lossy(&submodule_status)
        .lines()
        .map(str::to_owned)
        .collect();

    Ok(GitSnapshot {
        root: display_path(&canonical_root),
        revision,
        branch,
        dirty: !status.is_empty(),
        status_sha256: sha256_hex(&status),
        status_entries,
        submodule_status_sha256: sha256_hex(&submodule_status),
        submodules,
    })
}

fn run_git(git_path: &Path, workdir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new(git_path)
        .current_dir(workdir)
        .args(args)
        .output()
        .map_err(|error| format!("failed to launch `{}`: {error}", git_path.display()))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {} failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn run_git_optional(
    git_path: &Path,
    workdir: &Path,
    args: &[&str],
) -> Result<Option<Vec<u8>>, String> {
    let output = Command::new(git_path)
        .current_dir(workdir)
        .args(args)
        .output()
        .map_err(|error| format!("failed to launch `{}`: {error}", git_path.display()))?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else if output.status.code() == Some(1)
        && output.stdout.is_empty()
        && output.stderr.is_empty()
    {
        Ok(None)
    } else {
        Err(format!(
            "git {} failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn utf8_trimmed(bytes: Vec<u8>, field: &str) -> Result<String, String> {
    let value = String::from_utf8(bytes).map_err(|_| format!("{field} is not valid UTF-8"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(trimmed.to_owned())
    }
}

fn count_porcelain_v2_entries(status: &[u8]) -> Result<usize, String> {
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
            .ok_or_else(|| "git status contained an empty porcelain v2 record".to_owned())?;
        if !matches!(kind, b'1' | b'2' | b'u' | b'?' | b'!') {
            return Err(format!(
                "git status contained an unknown porcelain v2 record type `{}`",
                kind as char
            ));
        }
        count += 1;
        index += if kind == b'2' { 2 } else { 1 };
        if index > fields.len() {
            return Err("git status rename/copy record is missing its original path".into());
        }
    }
    Ok(count)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_file_identity(identity: &FileIdentity, label: &str) -> Result<(), String> {
    if !is_sha256(&identity.sha256) {
        return Err(format!("{label} has an invalid SHA-256 digest"));
    }
    if identity.bytes == 0 {
        return Err(format!("{label} records an empty executable"));
    }
    Ok(())
}

fn validate_executable_record(
    executable: &ExecutableAttestation,
    label: &str,
) -> Result<(), String> {
    if executable.requested_program.trim().is_empty()
        || executable.requested_program.trim() != executable.requested_program
    {
        return Err(format!("{label} has an invalid requested program"));
    }
    for (field, value) in [
        ("invocation path", executable.invocation_path.as_str()),
        ("resolved path", executable.resolved_path.as_str()),
    ] {
        if value.trim().is_empty() || !Path::new(value).is_absolute() {
            return Err(format!("{label} has an invalid {field}"));
        }
    }
    validate_file_identity(&executable.before, &format!("{label} initial identity"))?;
    validate_file_identity(&executable.after, &format!("{label} final identity"))?;
    Ok(())
}

fn validate_git_snapshot(snapshot: &GitSnapshot, label: &str) -> Result<(), String> {
    if !Path::new(&snapshot.root).is_absolute() {
        return Err(format!("{label} has a non-absolute checkout root"));
    }
    if !matches!(snapshot.revision.len(), 40 | 64)
        || !snapshot
            .revision
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!("{label} has an invalid Git revision"));
    }
    if snapshot
        .branch
        .as_ref()
        .is_some_and(|branch| branch.trim().is_empty() || branch.trim() != branch)
    {
        return Err(format!("{label} has an invalid branch name"));
    }
    if snapshot.dirty != (snapshot.status_entries > 0) {
        return Err(format!(
            "{label} dirty state and status entry count disagree"
        ));
    }
    if !is_sha256(&snapshot.status_sha256) || !is_sha256(&snapshot.submodule_status_sha256) {
        return Err(format!("{label} has an invalid status digest"));
    }
    let encoded_submodules = if snapshot.submodules.is_empty() {
        Vec::new()
    } else {
        format!("{}\n", snapshot.submodules.join("\n")).into_bytes()
    };
    if sha256_hex(&encoded_submodules) != snapshot.submodule_status_sha256 {
        return Err(format!("{label} submodule lines do not match their digest"));
    }
    Ok(())
}

fn verify_attestation_consistency(bundle: &EvidenceBundle) -> Result<(), EvidenceError> {
    let policy = &bundle.attestation_policy;
    if !policy.checkout
        && (bundle.checkout.is_some()
            || policy.expected_revision.is_some()
            || policy.require_clean_checkout)
    {
        return Err(EvidenceError::CheckoutAttestationMismatch(
            "checkout fields exist while checkout attestation is disabled".into(),
        ));
    }
    if policy.checkout {
        let checkout = bundle.checkout.as_ref().ok_or_else(|| {
            EvidenceError::CheckoutAttestationMismatch(
                "checkout attestation is enabled but missing".into(),
            )
        })?;
        if checkout
            .error
            .as_ref()
            .is_some_and(|error| error.trim().is_empty() || error.trim() != error)
        {
            return Err(EvidenceError::CheckoutAttestationMismatch(
                "checkout error is empty or has surrounding whitespace".into(),
            ));
        }
        if let Some(git) = &checkout.git {
            validate_executable_record(git, "Git executable")
                .map_err(EvidenceError::CheckoutAttestationMismatch)?;
            if git.requested_program != "git" {
                return Err(EvidenceError::CheckoutAttestationMismatch(
                    "Git executable requested program is not `git`".into(),
                ));
            }
        }
        if let Some(before) = &checkout.before {
            validate_git_snapshot(before, "initial checkout snapshot")
                .map_err(EvidenceError::CheckoutAttestationMismatch)?;
        }
        if let Some(after) = &checkout.after {
            validate_git_snapshot(after, "final checkout snapshot")
                .map_err(EvidenceError::CheckoutAttestationMismatch)?;
        }
        if checkout.error.is_none() {
            let git = checkout.git.as_ref().ok_or_else(|| {
                EvidenceError::CheckoutAttestationMismatch(
                    "successful checkout attestation has no Git executable identity".into(),
                )
            })?;
            let before = checkout.before.as_ref().ok_or_else(|| {
                EvidenceError::CheckoutAttestationMismatch(
                    "successful checkout attestation has no initial snapshot".into(),
                )
            })?;
            let after = checkout.after.as_ref().ok_or_else(|| {
                EvidenceError::CheckoutAttestationMismatch(
                    "successful checkout attestation has no final snapshot".into(),
                )
            })?;
            if git.before != git.after {
                return Err(EvidenceError::CheckoutAttestationMismatch(
                    "Git executable changed during execution".into(),
                ));
            }
            if before != after {
                return Err(EvidenceError::CheckoutAttestationMismatch(
                    "checkout state changed during execution".into(),
                ));
            }
            if policy.require_clean_checkout && before.dirty {
                return Err(EvidenceError::CheckoutAttestationMismatch(
                    "clean checkout was required but evidence records a dirty checkout".into(),
                ));
            }
            if policy
                .expected_revision
                .as_ref()
                .is_some_and(|expected| expected != &before.revision)
            {
                return Err(EvidenceError::CheckoutAttestationMismatch(
                    "recorded revision does not match the expected revision".into(),
                ));
            }
        }
    }

    for gate in &bundle.gates {
        for (field, error) in [
            ("launch error", gate.launch_error.as_deref()),
            ("input error", gate.input_error.as_deref()),
            ("executable error", gate.executable_error.as_deref()),
        ] {
            if error.is_some_and(|value| value.trim().is_empty() || value.trim() != value) {
                return Err(EvidenceError::ExecutableAttestationMismatch {
                    gate: gate.gate.clone(),
                    detail: format!("{field} is empty or has surrounding whitespace"),
                });
            }
        }
        if gate.status == GateStatus::Passed
            && (gate.exit_code != Some(0)
                || gate.launch_error.is_some()
                || gate.input_error.is_some()
                || gate.executable_error.is_some())
        {
            return Err(EvidenceError::InconsistentPassStatus);
        }
        if gate.status == GateStatus::LaunchFailed && gate.exit_code.is_some() {
            return Err(EvidenceError::InconsistentPassStatus);
        }
        match (&gate.execution, policy.executables) {
            (GateExecution::Shell { .. }, _)
                if gate.executable.is_some() || gate.executable_error.is_some() =>
            {
                return Err(EvidenceError::ExecutableAttestationMismatch {
                    gate: gate.gate.clone(),
                    detail: "shell gate contains direct executable evidence".into(),
                });
            }
            (GateExecution::Direct { .. }, false)
                if gate.executable.is_some() || gate.executable_error.is_some() =>
            {
                return Err(EvidenceError::ExecutableAttestationMismatch {
                    gate: gate.gate.clone(),
                    detail: "executable evidence exists while executable attestation is disabled"
                        .into(),
                });
            }
            (GateExecution::Direct { program, .. }, true) => {
                if let Some(executable) = &gate.executable {
                    validate_executable_record(executable, "gate executable").map_err(
                        |detail| EvidenceError::ExecutableAttestationMismatch {
                            gate: gate.gate.clone(),
                            detail,
                        },
                    )?;
                    if executable.requested_program != *program {
                        return Err(EvidenceError::ExecutableAttestationMismatch {
                            gate: gate.gate.clone(),
                            detail: "requested program does not match the gate definition".into(),
                        });
                    }
                    if executable.before != executable.after && gate.executable_error.is_none() {
                        return Err(EvidenceError::ExecutableAttestationMismatch {
                            gate: gate.gate.clone(),
                            detail: "executable changed without a recorded error".into(),
                        });
                    }
                } else if gate.executable_error.is_none() {
                    return Err(EvidenceError::ExecutableAttestationMismatch {
                        gate: gate.gate.clone(),
                        detail: "direct gate has neither executable identity nor resolution error"
                            .into(),
                    });
                }
            }
            _ => {}
        }
    }

    if bundle.passed {
        if bundle
            .checkout
            .as_ref()
            .is_some_and(|checkout| checkout.error.is_some())
        {
            return Err(EvidenceError::CheckoutAttestationMismatch(
                "passing evidence contains a checkout attestation error".into(),
            ));
        }
        if bundle.gates.iter().any(|gate| {
            gate.input_error.is_some()
                || gate.executable_error.is_some()
                || gate.launch_error.is_some()
        }) {
            return Err(EvidenceError::InconsistentPassStatus);
        }
    }
    Ok(())
}

fn verify_live_attestations(bundle: &EvidenceBundle, workdir: &Path) -> Result<(), EvidenceError> {
    if let Some(checkout) = &bundle.checkout {
        let git = checkout.git.as_ref().ok_or_else(|| {
            EvidenceError::LiveCheckoutMismatch(
                "evidence does not contain a complete Git executable identity".into(),
            )
        })?;
        let expected = checkout.after.as_ref().ok_or_else(|| {
            EvidenceError::LiveCheckoutMismatch(
                "evidence does not contain a final checkout snapshot".into(),
            )
        })?;
        let git_invocation = Path::new(&git.invocation_path);
        let git_resolved = Path::new(&git.resolved_path);
        verify_current_resolution("git", workdir, git_invocation, git_resolved)
            .map_err(EvidenceError::LiveCheckoutMismatch)?;
        let identity = file_identity(git_resolved).map_err(EvidenceError::LiveCheckoutMismatch)?;
        if identity != git.after {
            return Err(EvidenceError::LiveCheckoutMismatch(
                "Git executable identity has changed".into(),
            ));
        }
        let current = capture_git_snapshot(git_invocation, workdir)
            .map_err(EvidenceError::LiveCheckoutMismatch)?;
        if &current != expected {
            return Err(EvidenceError::LiveCheckoutMismatch(
                "current checkout snapshot differs from the recorded final snapshot".into(),
            ));
        }
    }

    for gate in &bundle.gates {
        if let Some(executable) = &gate.executable {
            let invocation = Path::new(&executable.invocation_path);
            let resolved = Path::new(&executable.resolved_path);
            verify_current_resolution(&executable.requested_program, workdir, invocation, resolved)
                .map_err(|_| EvidenceError::LiveExecutableMismatch {
                    gate: gate.gate.clone(),
                })?;
            let current =
                file_identity(resolved).map_err(|_| EvidenceError::LiveExecutableMismatch {
                    gate: gate.gate.clone(),
                })?;
            if current != executable.after {
                return Err(EvidenceError::LiveExecutableMismatch {
                    gate: gate.gate.clone(),
                });
            }
        }
    }
    Ok(())
}

fn verify_artifact(artifact: &OutputArtifact, artifact_root: &Path) -> Result<(), EvidenceError> {
    let relative = Path::new(&artifact.path);
    let expected = PathBuf::from("logs").join(format!("{}.log", artifact.sha256));
    if artifact.path.is_empty()
        || relative.is_absolute()
        || relative != expected
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(EvidenceError::UnsafeArtifactPath(artifact.path.clone()));
    }
    let path = artifact_root.join(relative);
    let bytes = read_output(&path)?;
    if bytes.len() != artifact.bytes || sha256_hex(&bytes) != artifact.sha256 {
        return Err(EvidenceError::ArtifactDigestMismatch {
            path: path.display().to_string(),
        });
    }
    if artifact.tail_start_byte > bytes.len()
        || artifact.tail_truncated != (artifact.tail_start_byte > 0)
        || String::from_utf8_lossy(&bytes[artifact.tail_start_byte..]) != artifact.tail
    {
        return Err(EvidenceError::ArtifactMetadataMismatch {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

fn select_gates<'a>(
    manifest: &'a Manifest,
    explicit_gates: &[String],
    module_ids: &[String],
) -> Result<Vec<&'a CompatibilityGate>, EvidenceError> {
    let mut selected = BTreeSet::new();
    for gate in explicit_gates {
        if manifest.gate(gate).is_none() {
            return Err(EvidenceError::UnknownGate(gate.clone()));
        }
        selected.insert(gate.clone());
    }
    for module_id in module_ids {
        let module = manifest
            .module(module_id)
            .ok_or_else(|| EvidenceError::UnknownModule(module_id.clone()))?;
        selected.extend(module.gates.iter().cloned());
    }
    if explicit_gates.is_empty() && module_ids.is_empty() {
        selected.extend(manifest.gates.iter().map(|gate| gate.id.clone()));
    }
    if selected.is_empty() {
        return Err(EvidenceError::NoGatesSelected);
    }

    selected
        .into_iter()
        .map(|id| manifest.gate(&id).ok_or(EvidenceError::UnknownGate(id)))
        .collect()
}

fn execute_gate(
    gate: &CompatibilityGate,
    options: &RunOptions,
) -> Result<GateEvidence, EvidenceError> {
    let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let started = unix_ms();
    let prefix = format!(
        "{}-{}-{}-{}",
        sanitize(&gate.id),
        std::process::id(),
        started,
        sequence
    );
    let stdout_temp = options
        .output_dir
        .join(".tmp")
        .join(format!("{prefix}.out"));
    let stderr_temp = options
        .output_dir
        .join(".tmp")
        .join(format!("{prefix}.err"));
    let stdout_file = create_temp(&stdout_temp)?;
    let stderr_file = create_temp(&stderr_temp)?;
    let timer = Instant::now();

    let mut input_error = verify_gate_inputs(gate, &options.workdir);
    let inputs_verified = input_error.is_none();
    let mut executable_error = None;
    let prepared = if input_error.is_none() {
        match prepare_gate_command(
            &gate.execution,
            &options.workdir,
            options.attest_executables,
        ) {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                executable_error = Some(error);
                None
            }
        }
    } else {
        None
    };

    let mut executable_runtime = None;
    let (mut status, exit_code, launch_error) = if let Some((mut command, runtime)) = prepared {
        executable_runtime = runtime;
        command
            .current_dir(&options.workdir)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        match command.spawn() {
            Ok(mut child) => {
                let mut timed_out = false;
                let exit = loop {
                    if let Some(status) =
                        child
                            .try_wait()
                            .map_err(|source| EvidenceError::InspectProcess {
                                gate: gate.id.clone(),
                                source,
                            })?
                    {
                        break status;
                    }
                    if timer.elapsed() >= options.timeout {
                        timed_out = true;
                        match child.kill() {
                            Ok(()) => {
                                break child.wait().map_err(|source| {
                                    EvidenceError::InspectProcess {
                                        gate: gate.id.clone(),
                                        source,
                                    }
                                })?;
                            }
                            Err(kill_error) => {
                                if let Some(status) = child.try_wait().map_err(|source| {
                                    EvidenceError::InspectProcess {
                                        gate: gate.id.clone(),
                                        source,
                                    }
                                })? {
                                    break status;
                                }
                                return Err(EvidenceError::InspectProcess {
                                    gate: gate.id.clone(),
                                    source: kill_error,
                                });
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(20));
                };
                (classify_status(exit, timed_out), exit.code(), None)
            }
            Err(error) => (GateStatus::LaunchFailed, None, Some(error.to_string())),
        }
    } else {
        drop(stdout_file);
        drop(stderr_file);
        (GateStatus::LaunchFailed, None, None)
    };

    if inputs_verified {
        if let Some(error) = verify_gate_inputs(gate, &options.workdir) {
            if status == GateStatus::Passed {
                status = GateStatus::Failed;
            }
            input_error = Some(error);
        }
    }

    let executable = if let Some(runtime) = executable_runtime {
        match finish_executable_attestation(runtime, &options.workdir) {
            Ok((attestation, changed)) => {
                if changed {
                    if status == GateStatus::Passed {
                        status = GateStatus::Failed;
                    }
                    executable_error = Some("gate executable changed during execution".into());
                }
                Some(attestation)
            }
            Err(error) => {
                if status == GateStatus::Passed {
                    status = GateStatus::Failed;
                }
                executable_error = Some(error);
                None
            }
        }
    } else {
        None
    };

    let stdout_bytes = read_output(&stdout_temp)?;
    let mut stderr_bytes = read_output(&stderr_temp)?;
    append_error(&mut stderr_bytes, launch_error.as_deref());
    append_error(&mut stderr_bytes, input_error.as_deref());
    append_error(&mut stderr_bytes, executable_error.as_deref());
    let stdout = persist_output(&options.output_dir, &stdout_bytes, options.max_tail_bytes)?;
    let stderr = persist_output(&options.output_dir, &stderr_bytes, options.max_tail_bytes)?;
    let _ = fs::remove_file(&stdout_temp);
    let _ = fs::remove_file(&stderr_temp);

    Ok(GateEvidence {
        gate: gate.id.clone(),
        execution: gate.execution.clone(),
        inputs: gate.inputs.clone(),
        declared_targets: gate.targets.clone(),
        status,
        exit_code,
        started_unix_ms: started,
        duration_ms: timer.elapsed().as_millis(),
        stdout,
        stderr,
        executable,
        launch_error,
        input_error,
        executable_error,
    })
}

fn append_error(output: &mut Vec<u8>, error: Option<&str>) {
    let Some(error) = error else {
        return;
    };
    if !output.is_empty() {
        output.push(b'\n');
    }
    output.extend_from_slice(error.as_bytes());
}

fn verify_gate_inputs(gate: &CompatibilityGate, workdir: &Path) -> Option<String> {
    let canonical_workdir = match workdir.canonicalize() {
        Ok(path) => path,
        Err(error) => return Some(format!("working directory could not be resolved: {error}")),
    };
    for input in &gate.inputs {
        let path = workdir.join(&input.path);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Some(format!(
                    "gate input `{}` could not be inspected: {error}",
                    input.path
                ));
            }
        };
        if metadata.file_type().is_symlink() {
            return Some(format!("gate input `{}` must not be a symlink", input.path));
        }
        let canonical = match path.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                return Some(format!(
                    "gate input `{}` could not be resolved: {error}",
                    input.path
                ));
            }
        };
        if !canonical.starts_with(&canonical_workdir) || !canonical.is_file() {
            return Some(format!(
                "gate input `{}` resolves outside the working directory or is not a file",
                input.path
            ));
        }
        let bytes = match fs::read(&canonical) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Some(format!(
                    "gate input `{}` could not be read: {error}",
                    input.path
                ));
            }
        };
        let actual = sha256_hex(&bytes);
        if actual != input.sha256 {
            return Some(format!(
                "gate input `{}` has SHA-256 {actual}; expected {}",
                input.path, input.sha256
            ));
        }
    }
    None
}

fn prepare_gate_command(
    execution: &GateExecution,
    workdir: &Path,
    attest_executable: bool,
) -> Result<(Command, Option<ExecutableRuntime>), String> {
    match execution {
        GateExecution::Shell { command } => Ok((shell_command(command), None)),
        GateExecution::Direct { program, args } if attest_executable => {
            let resolved = resolve_executable(program, workdir)?;
            let before = file_identity(&resolved.resolved_path)?;
            let mut command = Command::new(&resolved.invocation_path);
            command.args(args);
            Ok((
                command,
                Some(ExecutableRuntime {
                    requested_program: program.clone(),
                    invocation_path: resolved.invocation_path,
                    resolved_path: resolved.resolved_path,
                    before,
                }),
            ))
        }
        GateExecution::Direct { program, args } => {
            let mut command = Command::new(program);
            command.args(args);
            Ok((command, None))
        }
    }
}

fn finish_executable_attestation(
    runtime: ExecutableRuntime,
    workdir: &Path,
) -> Result<(ExecutableAttestation, bool), String> {
    verify_current_resolution(
        &runtime.requested_program,
        workdir,
        &runtime.invocation_path,
        &runtime.resolved_path,
    )?;
    let after = file_identity(&runtime.resolved_path)?;
    let changed = runtime.before != after;
    Ok((
        ExecutableAttestation {
            requested_program: runtime.requested_program,
            invocation_path: display_path(&runtime.invocation_path),
            resolved_path: display_path(&runtime.resolved_path),
            before: runtime.before,
            after,
        },
        changed,
    ))
}

fn resolve_executable(program: &str, workdir: &Path) -> Result<ResolvedExecutable, String> {
    let absolute_workdir = workdir
        .canonicalize()
        .map_err(|error| format!("working directory could not be resolved: {error}"))?;
    let program_path = Path::new(program);
    let path_like = program_path.is_absolute() || program.contains('/') || program.contains('\\');
    if path_like {
        let candidate = if program_path.is_absolute() {
            program_path.to_path_buf()
        } else {
            absolute_workdir.join(program_path)
        };
        return canonical_executable(candidate, program);
    }

    let path = env::var_os("PATH")
        .ok_or_else(|| format!("cannot resolve executable `{program}` because PATH is unset"))?;
    for directory in env::split_paths(&path) {
        let directory = if directory.as_os_str().is_empty() {
            absolute_workdir.clone()
        } else if directory.is_absolute() {
            directory
        } else {
            absolute_workdir.join(directory)
        };
        for candidate in executable_candidates(&directory, program) {
            if is_executable_file(&candidate) {
                return canonical_executable(candidate, program);
            }
        }
    }
    Err(format!("executable `{program}` was not found in PATH"))
}

fn canonical_executable(
    invocation_path: PathBuf,
    requested: &str,
) -> Result<ResolvedExecutable, String> {
    let resolved_path = invocation_path
        .canonicalize()
        .map_err(|error| format!("executable `{requested}` could not be resolved: {error}"))?;
    if !is_executable_file(&resolved_path) {
        return Err(format!(
            "resolved executable `{}` is not an executable file",
            resolved_path.display()
        ));
    }
    Ok(ResolvedExecutable {
        invocation_path,
        resolved_path,
    })
}

fn verify_resolved_target(
    invocation_path: &Path,
    expected_resolved_path: &Path,
    requested: &str,
) -> Result<(), String> {
    let current = invocation_path.canonicalize().map_err(|error| {
        format!(
            "executable entry `{}` could not be resolved: {error}",
            invocation_path.display()
        )
    })?;
    if current != expected_resolved_path {
        return Err(format!(
            "executable entry `{}` for `{requested}` now resolves to `{}` instead of `{}`",
            invocation_path.display(),
            current.display(),
            expected_resolved_path.display()
        ));
    }
    Ok(())
}

fn verify_current_resolution(
    requested: &str,
    workdir: &Path,
    expected_invocation_path: &Path,
    expected_resolved_path: &Path,
) -> Result<(), String> {
    let current = resolve_executable(requested, workdir)?;
    if current.invocation_path != expected_invocation_path {
        return Err(format!(
            "executable `{requested}` now resolves through `{}` instead of `{}`",
            current.invocation_path.display(),
            expected_invocation_path.display()
        ));
    }
    if current.resolved_path != expected_resolved_path {
        return Err(format!(
            "executable `{requested}` now resolves to `{}` instead of `{}`",
            current.resolved_path.display(),
            expected_resolved_path.display()
        ));
    }
    verify_resolved_target(expected_invocation_path, expected_resolved_path, requested)
}

#[cfg(unix)]
fn executable_candidates(directory: &Path, program: &str) -> Vec<PathBuf> {
    vec![directory.join(program)]
}

#[cfg(windows)]
fn executable_candidates(directory: &Path, program: &str) -> Vec<PathBuf> {
    let path = Path::new(program);
    if path.extension().is_some() {
        return vec![directory.join(path)];
    }
    let extensions = env::var_os("PATHEXT")
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
    extensions
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| directory.join(format!("{program}{extension}")))
        .collect()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn file_identity(path: &Path) -> Result<FileIdentity, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read executable `{}`: {error}", path.display()))?;
    Ok(FileIdentity {
        sha256: sha256_hex(&bytes),
        bytes: bytes.len(),
    })
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn classify_status(status: ExitStatus, timed_out: bool) -> GateStatus {
    if timed_out {
        GateStatus::TimedOut
    } else if status.success() {
        GateStatus::Passed
    } else {
        GateStatus::Failed
    }
}

fn persist_output(
    output_dir: &Path,
    bytes: &[u8],
    max_tail_bytes: usize,
) -> Result<OutputArtifact, EvidenceError> {
    let digest = sha256_hex(bytes);
    let relative = PathBuf::from("logs").join(format!("{digest}.log"));
    let path = output_dir.join(&relative);
    write_content_addressed(&path, bytes)?;
    let start = bytes.len().saturating_sub(max_tail_bytes);
    Ok(OutputArtifact {
        sha256: digest,
        bytes: bytes.len(),
        path: relative.to_string_lossy().replace('\\', "/"),
        tail_start_byte: start,
        tail: String::from_utf8_lossy(&bytes[start..]).into_owned(),
        tail_truncated: start > 0,
    })
}

fn write_content_addressed(path: &Path, bytes: &[u8]) -> Result<(), EvidenceError> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file
            .write_all(bytes)
            .map_err(|source| EvidenceError::WriteArtifact {
                path: path.display().to_string(),
                source,
            }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|source| EvidenceError::ReadOutput {
                path: path.display().to_string(),
                source,
            })?;
            if existing == bytes {
                Ok(())
            } else {
                Err(EvidenceError::WriteArtifact {
                    path: path.display().to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "content-addressed path contains different bytes",
                    ),
                })
            }
        }
        Err(source) => Err(EvidenceError::WriteArtifact {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn create_dir(path: &Path) -> Result<(), EvidenceError> {
    fs::create_dir_all(path).map_err(|source| EvidenceError::CreateDirectory {
        path: path.display().to_string(),
        source,
    })
}

fn create_temp(path: &Path) -> Result<File, EvidenceError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| EvidenceError::CreateTemporaryOutput {
            path: path.display().to_string(),
            source,
        })
}

fn read_output(path: &Path) -> Result<Vec<u8>, EvidenceError> {
    fs::read(path).map_err(|source| EvidenceError::ReadOutput {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(unix)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("sh");
    shell.arg("-lc").arg(command);
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("cmd");
    shell.arg("/D").arg("/S").arg("/C").arg(command);
    shell
}

#[cfg(unix)]
fn shell_description() -> &'static str {
    "sh -lc"
}

#[cfg(windows)]
fn shell_description() -> &'static str {
    "cmd /D /S /C"
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sanitize(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            output.push(character);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "gate".into()
    } else {
        output
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chromifer_manifest::{CompatibilityGate, Module, Project};

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir()
                .join(format!("chromifer-evidence-{}-{id}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn passing_command() -> String {
        if cfg!(windows) {
            "echo passed".into()
        } else {
            "printf passed".into()
        }
    }

    fn failing_command() -> String {
        if cfg!(windows) {
            "echo failed 1>&2 & exit /b 7".into()
        } else {
            "printf failed >&2; exit 7".into()
        }
    }

    fn slow_command() -> String {
        if cfg!(windows) {
            "ping -n 3 127.0.0.1 >NUL".into()
        } else {
            "sleep 1".into()
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "evidence fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture-baseline".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![
                CompatibilityGate {
                    id: "pass".into(),
                    execution: GateExecution::Shell {
                        command: passing_command(),
                    },
                    inputs: vec![],
                    targets: vec![],
                },
                CompatibilityGate {
                    id: "fail".into(),
                    execution: GateExecution::Shell {
                        command: failing_command(),
                    },
                    inputs: vec![],
                    targets: vec![],
                },
                CompatibilityGate {
                    id: "slow".into(),
                    execution: GateExecution::Shell {
                        command: slow_command(),
                    },
                    inputs: vec![],
                    targets: vec![],
                },
            ],
            modules: vec![Module {
                id: "service".into(),
                path: "services/example".into(),
                owner: "services".into(),
                ownership: None,
                source_label: None,
                source_type: None,
                sources: vec![],
                state: chromifer_manifest::MigrationState::LegacyCpp,
                gates: vec!["pass".into(), "fail".into()],
                reviews: vec![],
                dependencies: vec![],
            }],
        }
    }

    fn options(tree: &TempTree) -> RunOptions {
        RunOptions {
            workdir: tree.root.clone(),
            output_dir: tree.root.join("artifacts"),
            gate_ids: vec![],
            module_ids: vec!["service".into()],
            fail_fast: false,
            timeout: Duration::from_secs(5),
            max_tail_bytes: 1024,
            attest_checkout: false,
            expected_revision: None,
            require_clean_checkout: false,
            attest_executables: false,
        }
    }

    fn git(workdir: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .current_dir(workdir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn init_git_repo(tree: &TempTree) -> String {
        git(&tree.root, &["init", "-q"]);
        fs::write(tree.root.join("tracked.txt"), b"initial\n").unwrap();
        git(&tree.root, &["add", "tracked.txt"]);
        git(
            &tree.root,
            &[
                "-c",
                "user.name=Chromifer Test",
                "-c",
                "user.email=chromifer@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "initial",
            ],
        );
        String::from_utf8(git(&tree.root, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn attested_options(repo: &TempTree, artifacts: &TempTree) -> RunOptions {
        let mut options = options(repo);
        options.output_dir = artifacts.root.join("artifacts");
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];
        options.attest_checkout = true;
        options.require_clean_checkout = true;
        options.attest_executables = true;
        options
    }

    #[test]
    fn records_clean_checkout_and_direct_executable_identity() {
        let repo = TempTree::new();
        let artifacts = TempTree::new();
        let revision = init_git_repo(&repo);
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "git".into(),
            args: vec!["--version".into()],
        };
        let mut options = attested_options(&repo, &artifacts);
        options.expected_revision = Some(revision.clone());

        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert!(run.bundle.passed);
        let checkout = run.bundle.checkout.as_ref().unwrap();
        assert!(checkout.error.is_none());
        assert_eq!(checkout.before.as_ref().unwrap().revision, revision);
        assert!(!checkout.before.as_ref().unwrap().dirty);
        assert_eq!(checkout.before, checkout.after);
        assert_eq!(
            checkout.git.as_ref().unwrap().before,
            checkout.git.as_ref().unwrap().after
        );
        let executable = run.bundle.gates[0].executable.as_ref().unwrap();
        assert_eq!(executable.requested_program, "git");
        assert_eq!(executable.before, executable.after);
        assert!(Path::new(&executable.resolved_path).is_absolute());

        let summary = verify_evidence_with_workdir(
            &manifest,
            b"manifest",
            &run.path,
            &options.output_dir,
            Some(&repo.root),
        )
        .unwrap();
        assert!(summary.checkout_attested);
        assert_eq!(summary.executables_attested, 1);
        assert!(summary.live_attestation_verified);

        fs::write(repo.root.join("tracked.txt"), b"changed after evidence\n").unwrap();
        assert!(matches!(
            verify_evidence_with_workdir(
                &manifest,
                b"manifest",
                &run.path,
                &options.output_dir,
                Some(&repo.root),
            ),
            Err(EvidenceError::LiveCheckoutMismatch(_))
        ));
    }

    #[test]
    fn rejects_checkout_constraints_without_checkout_attestation() {
        let tree = TempTree::new();
        let mut options = options(&tree);
        options.expected_revision = Some("0000000000000000000000000000000000000000".into());
        assert!(matches!(
            run_gates(&manifest(), b"manifest", &options),
            Err(EvidenceError::InvalidAttestationOptions(_))
        ));

        options.expected_revision = None;
        options.require_clean_checkout = true;
        assert!(matches!(
            run_gates(&manifest(), b"manifest", &options),
            Err(EvidenceError::InvalidAttestationOptions(_))
        ));
    }

    #[test]
    fn counts_porcelain_v2_rename_records_as_one_status_entry() {
        let status = b"1 .M N... 100644 100644 100644 abc abc tracked.txt\0\
2 R. N... 100644 100644 100644 abc def R100 renamed.txt\0original.txt\0\
? untracked.txt\0";
        assert_eq!(count_porcelain_v2_entries(status).unwrap(), 3);
        assert!(count_porcelain_v2_entries(b"2 R. incomplete\0").is_err());
        assert!(count_porcelain_v2_entries(b"x unknown\0").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn checkout_attestation_records_recursive_submodule_state() {
        let repo = TempTree::new();
        let submodule = TempTree::new();
        let artifacts = TempTree::new();
        init_git_repo(&repo);
        init_git_repo(&submodule);
        let submodule_path = submodule.root.to_string_lossy().into_owned();
        git(
            &repo.root,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                &submodule_path,
                "deps/sub",
            ],
        );
        git(&repo.root, &["add", ".gitmodules", "deps/sub"]);
        git(
            &repo.root,
            &[
                "-c",
                "user.name=Chromifer Test",
                "-c",
                "user.email=chromifer@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "add submodule",
            ],
        );
        let revision = String::from_utf8(git(&repo.root, &["rev-parse", "HEAD"]))
            .unwrap()
            .trim()
            .to_owned();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "git".into(),
            args: vec!["--version".into()],
        };
        let mut options = attested_options(&repo, &artifacts);
        options.expected_revision = Some(revision);

        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert!(run.bundle.passed);
        let snapshot = run
            .bundle
            .checkout
            .as_ref()
            .and_then(|checkout| checkout.before.as_ref())
            .unwrap();
        assert_eq!(snapshot.submodules.len(), 1);
        assert!(snapshot.submodules[0].contains("deps/sub"));
        assert_ne!(snapshot.submodule_status_sha256, sha256_hex(b""));
        verify_evidence(&manifest, b"manifest", &run.path, &options.output_dir).unwrap();
    }

    #[test]
    fn rejects_tampered_checkout_and_executable_attestation_fields() {
        let repo = TempTree::new();
        let artifacts = TempTree::new();
        let revision = init_git_repo(&repo);
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "git".into(),
            args: vec!["--version".into()],
        };
        let mut options = attested_options(&repo, &artifacts);
        options.expected_revision = Some(revision);
        let run = run_gates(&manifest, b"manifest", &options).unwrap();

        let mut checkout_tampered = run.bundle.clone();
        checkout_tampered
            .checkout
            .as_mut()
            .unwrap()
            .before
            .as_mut()
            .unwrap()
            .status_entries = 1;
        let encoded = serde_json::to_vec_pretty(&checkout_tampered).unwrap();
        let digest = sha256_hex(&encoded);
        let path = options
            .output_dir
            .join("evidence")
            .join(format!("{digest}.json"));
        fs::write(&path, encoded).unwrap();
        assert!(matches!(
            verify_evidence(&manifest, b"manifest", &path, &options.output_dir),
            Err(EvidenceError::CheckoutAttestationMismatch(_))
        ));

        let mut executable_tampered = run.bundle.clone();
        executable_tampered.gates[0].executable = None;
        let encoded = serde_json::to_vec_pretty(&executable_tampered).unwrap();
        let digest = sha256_hex(&encoded);
        let path = options
            .output_dir
            .join("evidence")
            .join(format!("{digest}.json"));
        fs::write(&path, encoded).unwrap();
        assert!(matches!(
            verify_evidence(&manifest, b"manifest", &path, &options.output_dir),
            Err(EvidenceError::ExecutableAttestationMismatch { .. })
        ));
    }

    #[test]
    fn clean_checkout_policy_skips_gates_when_dirty_or_at_the_wrong_revision() {
        let repo = TempTree::new();
        let artifacts = TempTree::new();
        let revision = init_git_repo(&repo);
        fs::write(repo.root.join("tracked.txt"), b"dirty\n").unwrap();
        let mut options = attested_options(&repo, &artifacts);
        options.attest_executables = false;
        options.expected_revision = Some(revision);

        let dirty = run_gates(&manifest(), b"manifest", &options).unwrap();
        assert!(!dirty.bundle.passed);
        assert!(dirty.bundle.gates.is_empty());
        assert_eq!(dirty.bundle.skipped_gates, vec!["pass"]);
        assert!(
            dirty
                .bundle
                .checkout
                .as_ref()
                .and_then(|checkout| checkout.error.as_deref())
                .is_some_and(|error| error.contains("dirty"))
        );

        git(&repo.root, &["checkout", "--", "tracked.txt"]);
        options.expected_revision = Some("0000000000000000000000000000000000000000".into());
        let mismatch = run_gates(&manifest(), b"manifest", &options).unwrap();
        assert!(!mismatch.bundle.passed);
        assert!(
            mismatch
                .bundle
                .checkout
                .as_ref()
                .and_then(|checkout| checkout.error.as_deref())
                .is_some_and(|error| error.contains("does not match"))
        );
    }

    #[test]
    fn checkout_drift_during_execution_fails_the_bundle() {
        let repo = TempTree::new();
        let artifacts = TempTree::new();
        let revision = init_git_repo(&repo);
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Shell {
            command: if cfg!(windows) {
                "echo changed>>tracked.txt".into()
            } else {
                "printf changed >> tracked.txt".into()
            },
        };
        let mut options = attested_options(&repo, &artifacts);
        options.expected_revision = Some(revision);
        options.attest_executables = false;

        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert!(!run.bundle.passed);
        assert_eq!(run.bundle.gates[0].status, GateStatus::Passed);
        assert!(
            run.bundle
                .checkout
                .as_ref()
                .and_then(|checkout| checkout.error.as_deref())
                .is_some_and(|error| error.contains("changed during execution"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_drift_fails_gate_and_live_verification_detects_later_changes() {
        use std::os::unix::fs::PermissionsExt;

        let tree = TempTree::new();
        let script = tree.root.join("tool.sh");
        fs::write(&script, b"#!/bin/sh\nprintf changed > \"$0\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "./tool.sh".into(),
            args: vec![],
        };
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];
        options.attest_executables = true;

        let changed = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(changed.bundle.gates[0].exit_code, Some(0));
        assert_eq!(changed.bundle.gates[0].status, GateStatus::Failed);
        assert!(
            changed.bundle.gates[0]
                .executable_error
                .as_deref()
                .is_some_and(|error| error.contains("changed during execution"))
        );

        fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let stable = run_gates(&manifest, b"manifest", &options).unwrap();
        assert!(stable.bundle.passed);
        fs::write(&script, b"#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            verify_evidence_with_workdir(
                &manifest,
                b"manifest",
                &stable.path,
                &options.output_dir,
                Some(&tree.root),
            ),
            Err(EvidenceError::LiveExecutableMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn executable_attestation_preserves_multicall_symlink_entry_name() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let tree = TempTree::new();
        let dispatcher = tree.root.join("dispatcher.sh");
        let entry = tree.root.join("tool");
        fs::write(
            &dispatcher,
            b"#!/bin/sh\n[ \"$(basename \"$0\")\" = tool ]\n",
        )
        .unwrap();
        fs::set_permissions(&dispatcher, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&dispatcher, &entry).unwrap();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "./tool".into(),
            args: vec![],
        };
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];
        options.attest_executables = true;

        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert!(run.bundle.passed);
        let executable = run.bundle.gates[0].executable.as_ref().unwrap();
        assert!(Path::new(&executable.invocation_path).is_absolute());
        assert!(executable.invocation_path.ends_with("/tool"));
        assert!(executable.resolved_path.ends_with("/dispatcher.sh"));
        assert_ne!(executable.invocation_path, executable.resolved_path);
    }

    #[cfg(unix)]
    #[test]
    fn direct_gate_preserves_argument_boundaries_without_shell_interpretation() {
        let tree = TempTree::new();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "printf".into(),
            args: vec!["%s".into(), "literal;printf injected".into()],
        };
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];

        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(run.bundle.gates[0].status, GateStatus::Passed);
        assert_eq!(run.bundle.gates[0].stdout.tail, "literal;printf injected");
        assert!(matches!(
            run.bundle.gates[0].execution,
            GateExecution::Direct { .. }
        ));
    }

    #[test]
    fn gate_inputs_are_verified_before_process_launch() {
        let tree = TempTree::new();
        fs::write(tree.root.join("contract.json"), b"contract-v1").unwrap();
        let mut manifest = manifest();
        manifest.gates[0].inputs = vec![GateInput {
            path: "contract.json".into(),
            sha256: sha256_hex(b"contract-v1"),
        }];
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];

        let passed = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(passed.bundle.gates[0].status, GateStatus::Passed);
        assert_eq!(passed.bundle.gates[0].inputs, manifest.gates[0].inputs);

        fs::write(tree.root.join("contract.json"), b"contract-v2").unwrap();
        let blocked = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(blocked.bundle.gates[0].status, GateStatus::LaunchFailed);
        assert_eq!(blocked.bundle.gates[0].exit_code, None);
        assert!(
            blocked.bundle.gates[0]
                .input_error
                .as_deref()
                .is_some_and(|error| error.contains("expected"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn gate_inputs_reject_symlinks_even_when_the_digest_matches() {
        use std::os::unix::fs::symlink;

        let tree = TempTree::new();
        let outside = TempTree::new();
        fs::write(outside.root.join("contract.json"), b"contract-v1").unwrap();
        symlink(
            outside.root.join("contract.json"),
            tree.root.join("contract.json"),
        )
        .unwrap();
        let mut manifest = manifest();
        manifest.gates[0].inputs = vec![GateInput {
            path: "contract.json".into(),
            sha256: sha256_hex(b"contract-v1"),
        }];
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];

        let blocked = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(blocked.bundle.gates[0].status, GateStatus::LaunchFailed);
        assert!(
            blocked.bundle.gates[0]
                .input_error
                .as_deref()
                .is_some_and(|error| error.contains("must not be a symlink"))
        );
    }

    #[test]
    fn gate_input_drift_during_execution_fails_a_successful_process() {
        let tree = TempTree::new();
        fs::write(tree.root.join("contract.json"), b"contract-v1").unwrap();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Shell {
            command: if cfg!(windows) {
                "echo contract-v2>contract.json".into()
            } else {
                "printf contract-v2 > contract.json".into()
            },
        };
        manifest.gates[0].inputs = vec![GateInput {
            path: "contract.json".into(),
            sha256: sha256_hex(b"contract-v1"),
        }];
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];

        let blocked = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(blocked.bundle.gates[0].exit_code, Some(0));
        assert_eq!(blocked.bundle.gates[0].status, GateStatus::Failed);
        assert!(blocked.bundle.gates[0].launch_error.is_none());
        assert!(
            blocked.bundle.gates[0]
                .input_error
                .as_deref()
                .is_some_and(|error| error.contains("expected"))
        );
    }

    #[test]
    fn records_pass_and_failure_with_content_addressed_logs() {
        let tree = TempTree::new();
        let run = run_gates(&manifest(), b"manifest", &options(&tree)).unwrap();
        assert!(!run.bundle.passed);
        assert_eq!(run.bundle.gates.len(), 2);
        assert_eq!(run.bundle.gates[0].gate, "fail");
        assert_eq!(run.bundle.gates[0].status, GateStatus::Failed);
        assert_eq!(run.bundle.gates[0].exit_code, Some(7));
        assert!(run.bundle.gates[0].stderr.tail.contains("failed"));
        assert_eq!(run.bundle.gates[1].status, GateStatus::Passed);
        assert!(run.path.is_file());
        assert!(
            tree.root
                .join("artifacts")
                .join(&run.bundle.gates[1].stdout.path)
                .is_file()
        );
    }

    #[test]
    fn fail_fast_records_skipped_gate_ids() {
        let tree = TempTree::new();
        let mut options = options(&tree);
        options.fail_fast = true;
        let run = run_gates(&manifest(), b"manifest", &options).unwrap();
        assert_eq!(run.bundle.gates.len(), 1);
        assert_eq!(run.bundle.gates[0].gate, "fail");
        assert_eq!(run.bundle.skipped_gates, vec!["pass"]);
    }

    #[test]
    fn timeout_is_recorded_and_evidence_is_still_written() {
        let tree = TempTree::new();
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["slow".into()];
        options.timeout = Duration::from_millis(40);
        let run = run_gates(&manifest(), b"manifest", &options).unwrap();
        assert_eq!(run.bundle.gates[0].status, GateStatus::TimedOut);
        assert!(!run.bundle.passed);
        assert!(run.path.is_file());
    }

    #[test]
    fn evidence_and_logs_are_reusable_when_content_matches() {
        let tree = TempTree::new();
        let first = run_gates(&manifest(), b"manifest", &options(&tree)).unwrap();
        let second = run_gates(&manifest(), b"manifest", &options(&tree)).unwrap();
        assert_ne!(first.digest, second.digest);
        assert_eq!(
            first.bundle.gates[1].stdout.sha256,
            second.bundle.gates[1].stdout.sha256
        );
        assert_eq!(
            first.bundle.gates[1].stdout.path,
            second.bundle.gates[1].stdout.path
        );
    }

    #[test]
    fn rejects_unknown_selection_and_empty_manifests() {
        let tree = TempTree::new();
        let mut options = options(&tree);
        options.module_ids = vec!["missing".into()];
        assert!(matches!(
            run_gates(&manifest(), b"manifest", &options),
            Err(EvidenceError::UnknownModule(_))
        ));

        let mut empty = manifest();
        empty.gates.clear();
        empty.modules.clear();
        options.module_ids.clear();
        assert!(matches!(
            run_gates(&empty, b"manifest", &options),
            Err(EvidenceError::NoGatesSelected)
        ));
    }

    #[test]
    fn output_tail_is_bounded_but_full_log_is_preserved() {
        let tree = TempTree::new();
        let mut manifest = manifest();
        manifest.gates[0].execution = GateExecution::Shell {
            command: if cfg!(windows) {
                "echo 0123456789".into()
            } else {
                "printf 0123456789".into()
            },
        };
        let mut options = options(&tree);
        options.module_ids.clear();
        options.gate_ids = vec!["pass".into()];
        options.max_tail_bytes = 4;
        let run = run_gates(&manifest, b"manifest", &options).unwrap();
        assert_eq!(run.bundle.gates[0].stdout.tail, "6789");
        assert_eq!(run.bundle.gates[0].stdout.tail_start_byte, 6);
        assert!(run.bundle.gates[0].stdout.tail_truncated);
        let full = fs::read(
            tree.root
                .join("artifacts")
                .join(&run.bundle.gates[0].stdout.path),
        )
        .unwrap();
        assert_eq!(full, b"0123456789");
    }

    #[test]
    fn rejects_tampered_embedded_tail_metadata_even_when_logs_are_intact() {
        let tree = TempTree::new();
        let manifest = manifest();
        let run = run_gates(&manifest, b"manifest", &options(&tree)).unwrap();
        let mut bundle = run.bundle.clone();
        bundle.gates[1].stdout.tail = "not-the-log-tail".into();
        let encoded = serde_json::to_vec_pretty(&bundle).unwrap();
        let digest = sha256_hex(&encoded);
        let path = tree
            .root
            .join("artifacts/evidence")
            .join(format!("{digest}.json"));
        fs::write(&path, encoded).unwrap();

        assert!(matches!(
            verify_evidence(&manifest, b"manifest", &path, &tree.root.join("artifacts")),
            Err(EvidenceError::ArtifactMetadataMismatch { .. })
        ));
    }

    #[test]
    fn verifies_bundle_name_manifest_gate_definitions_and_logs() {
        let tree = TempTree::new();
        let manifest = manifest();
        let run = run_gates(&manifest, b"manifest", &options(&tree)).unwrap();
        let summary = verify_evidence(
            &manifest,
            b"manifest",
            &run.path,
            &tree.root.join("artifacts"),
        )
        .unwrap();
        assert_eq!(summary.digest, run.digest);
        assert_eq!(summary.gate_count, 2);
        assert_eq!(summary.passed_gates, vec!["pass"]);
        assert!(!summary.passed);

        let stdout_path = tree
            .root
            .join("artifacts")
            .join(&run.bundle.gates[1].stdout.path);
        fs::write(&stdout_path, b"tampered").unwrap();
        assert!(matches!(
            verify_evidence(
                &manifest,
                b"manifest",
                &run.path,
                &tree.root.join("artifacts")
            ),
            Err(EvidenceError::ArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_renamed_evidence_and_changed_manifest_definitions() {
        let tree = TempTree::new();
        let manifest = manifest();
        let run = run_gates(&manifest, b"manifest", &options(&tree)).unwrap();
        let renamed = tree.root.join("artifacts/evidence/not-the-digest.json");
        fs::copy(&run.path, &renamed).unwrap();
        assert!(matches!(
            verify_evidence(
                &manifest,
                b"manifest",
                &renamed,
                &tree.root.join("artifacts")
            ),
            Err(EvidenceError::EvidenceDigestMismatch { .. })
        ));

        let mut changed = manifest.clone();
        changed.gates[0].execution = GateExecution::Shell {
            command: "different command".into(),
        };
        assert!(matches!(
            verify_evidence(
                &changed,
                b"manifest",
                &run.path,
                &tree.root.join("artifacts")
            ),
            Err(EvidenceError::GateDefinitionMismatch(_))
        ));
    }

    #[test]
    fn rejects_evidence_for_different_manifest_bytes() {
        let tree = TempTree::new();
        let manifest = manifest();
        let run = run_gates(&manifest, b"manifest", &options(&tree)).unwrap();
        assert!(matches!(
            verify_evidence(
                &manifest,
                b"different",
                &run.path,
                &tree.root.join("artifacts")
            ),
            Err(EvidenceError::ManifestDigestMismatch)
        ));
    }
}
