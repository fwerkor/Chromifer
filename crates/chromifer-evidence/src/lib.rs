#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chromifer_manifest::{CompatibilityGate, Manifest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const EVIDENCE_SCHEMA_VERSION: u32 = 1;
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
pub struct GateEvidence {
    pub gate: String,
    pub command: String,
    pub declared_targets: Vec<String>,
    pub status: GateStatus,
    pub exit_code: Option<i32>,
    pub started_unix_ms: u128,
    pub duration_ms: u128,
    pub stdout: OutputArtifact,
    pub stderr: OutputArtifact,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_error: Option<String>,
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
}

pub fn run_gates(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    options: &RunOptions,
) -> Result<EvidenceRun, EvidenceError> {
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
    let started = unix_ms();
    let timer = Instant::now();
    let mut gates = Vec::with_capacity(selected.len());
    let mut skipped_gates = Vec::new();

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

    let passed = skipped_gates.is_empty()
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
        if gate.command != definition.command || gate.declared_targets != definition.targets {
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

    let computed_passed = skipped.is_empty()
        && bundle.gates.len() == selected.len()
        && bundle
            .gates
            .iter()
            .all(|gate| gate.status == GateStatus::Passed);
    if bundle.passed != computed_passed {
        return Err(EvidenceError::InconsistentPassStatus);
    }

    Ok(VerificationSummary {
        digest: named_digest.to_owned(),
        passed: bundle.passed,
        gate_count: bundle.gates.len(),
        log_count: logs.len(),
        passed_gates,
    })
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

    let mut command = shell_command(&gate.command);
    command
        .current_dir(&options.workdir)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let (status, exit_code, launch_error) = match command.spawn() {
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
    };

    let stdout_bytes = read_output(&stdout_temp)?;
    let mut stderr_bytes = read_output(&stderr_temp)?;
    if let Some(error) = &launch_error {
        if !stderr_bytes.is_empty() {
            stderr_bytes.push(b'\n');
        }
        stderr_bytes.extend_from_slice(error.as_bytes());
    }
    let stdout = persist_output(&options.output_dir, &stdout_bytes, options.max_tail_bytes)?;
    let stderr = persist_output(&options.output_dir, &stderr_bytes, options.max_tail_bytes)?;
    let _ = fs::remove_file(&stdout_temp);
    let _ = fs::remove_file(&stderr_temp);

    Ok(GateEvidence {
        gate: gate.id.clone(),
        command: gate.command.clone(),
        declared_targets: gate.targets.clone(),
        status,
        exit_code,
        started_unix_ms: started,
        duration_ms: timer.elapsed().as_millis(),
        stdout,
        stderr,
        launch_error,
    })
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
                    command: passing_command(),
                    targets: vec![],
                },
                CompatibilityGate {
                    id: "fail".into(),
                    command: failing_command(),
                    targets: vec![],
                },
                CompatibilityGate {
                    id: "slow".into(),
                    command: slow_command(),
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
        }
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
        manifest.gates[0].command = if cfg!(windows) {
            "echo 0123456789".into()
        } else {
            "printf 0123456789".into()
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
        changed.gates[0].command = "different command".into();
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
