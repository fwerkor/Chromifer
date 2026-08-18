#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub mod exposure_measure;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotStatus {
    InProgress,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pending,
    Partial,
    DefinedNotMeasured,
    Verified,
    Passed,
    PassedLinux,
    Failed,
}

impl EvidenceStatus {
    const fn is_satisfied(self) -> bool {
        matches!(self, Self::Passed)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PilotManifest {
    pub schema_version: u32,
    pub id: String,
    pub status: PilotStatus,
    pub upstream: Upstream,
    pub boundary: Boundary,
    pub rollback: Rollback,
    pub implementation: ImplementationEvidence,
    #[serde(default)]
    pub verification: Vec<Verification>,
    pub m3_acceptance: M3Acceptance,
    pub parity: LinkedEvidence,
    pub performance: LinkedEvidence,
    pub exposure: LinkedEvidence,
    pub notes: Notes,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub repository: String,
    pub revision: String,
    pub target: String,
    pub ownership: String,
    pub blobs: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Boundary {
    pub kind: String,
    pub interface: String,
    pub mojom: String,
    pub legacy_sources: Vec<String>,
    pub rust_source: String,
    pub factory: String,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollback {
    pub status: EvidenceStatus,
    pub gn_arg: String,
    pub rust_value: bool,
    pub fallback_value: bool,
    pub default_expression: String,
    pub shared_test_target: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationEvidence {
    pub status: EvidenceStatus,
    #[serde(default)]
    pub patch: Option<PatchArtifact>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchArtifact {
    pub path: String,
    pub base_revision: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub id: String,
    pub status: EvidenceStatus,
    #[serde(default)]
    pub configuration: Option<String>,
    pub target: String,
    #[serde(default)]
    pub passed_tests: Option<u64>,
    #[serde(default)]
    pub failed_tests: Option<u64>,
    #[serde(default)]
    pub rust_receiver_dependencies_present: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3Acceptance {
    pub feature_parity: EvidenceStatus,
    pub upstream_test_parity: EvidenceStatus,
    pub performance_budget: EvidenceStatus,
    pub rollback: EvidenceStatus,
    pub memory_safety_reduction: EvidenceStatus,
    pub maintenance_complexity_reduction: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkedEvidence {
    #[serde(default)]
    pub matrix: Option<String>,
    #[serde(default)]
    pub budget: Option<String>,
    #[serde(default)]
    pub measurement: Option<String>,
    pub status: EvidenceStatus,
}

impl LinkedEvidence {
    fn path(&self) -> Option<&str> {
        self.matrix
            .as_deref()
            .or(self.budget.as_deref())
            .or(self.measurement.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
    pub verified_platform: String,
    pub feature_parity_scope: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityManifest {
    pub schema_version: u32,
    pub id: String,
    pub status: EvidenceStatus,
    pub interface: ParityInterface,
    #[serde(default)]
    pub contract_cases: Vec<ContractCase>,
    #[serde(default)]
    pub upstream_suites: Vec<UpstreamSuite>,
    pub desktop_matrix: DesktopMatrix,
    pub rollback_matrix: RollbackMatrix,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityInterface {
    pub mojom: String,
    pub name: String,
    pub methods: Vec<String>,
    pub require_identical_mojom: bool,
    pub require_identical_factory_signature: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractCase {
    pub id: String,
    pub status: EvidenceStatus,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub evidence_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSuite {
    pub id: String,
    pub target: String,
    pub status: EvidenceStatus,
    #[serde(default)]
    pub evidence_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopMatrix {
    pub platforms: Vec<String>,
    pub require_rust_build: bool,
    pub require_shared_contract_test: bool,
    pub require_upstream_suite_when_target_supported: bool,
    pub linux: EvidenceStatus,
    pub mac: EvidenceStatus,
    pub win: EvidenceStatus,
    #[serde(default)]
    pub evidence_sha256: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackMatrix {
    pub require_fallback_build: bool,
    pub require_shared_contract_test: bool,
    pub linux: EvidenceStatus,
    pub mac: EvidenceStatus,
    pub win: EvidenceStatus,
    #[serde(default)]
    pub evidence_sha256: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceManifest {
    pub schema_version: u32,
    pub id: String,
    pub status: EvidenceStatus,
    pub comparison: PerformanceComparison,
    pub workload: PerformanceWorkload,
    pub latency_budget: LatencyBudget,
    pub memory_budget: MemoryBudget,
    pub validity: PerformanceValidity,
    #[serde(default)]
    pub results: Option<PerformanceResults>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceComparison {
    pub upstream_revision: String,
    pub baseline_configuration: String,
    pub candidate_configuration: String,
    pub build_mode: String,
    pub require_identical_non_migration_gn_args: bool,
    pub require_same_machine: bool,
    pub require_alternating_sample_order: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceWorkload {
    pub warmup_messages: u64,
    pub messages_per_sample: u64,
    pub samples: u64,
    pub in_process_mojo: bool,
    pub cases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LatencyBudget {
    pub median_regression_percent_max: f64,
    pub p95_regression_percent_max: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryBudget {
    pub steady_state_rss_regression_bytes_max: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceValidity {
    pub minimum_completed_samples: u64,
    pub reject_if_cpu_migration_or_frequency_policy_differs: bool,
    pub reject_if_background_load_invalidates_pairing: bool,
    pub record_raw_samples: bool,
    pub record_binary_hashes: bool,
    pub record_gn_args_hashes: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceResults {
    pub completed_samples: u64,
    pub cases: Vec<PerformanceCaseResult>,
    pub steady_state_rss_regression_bytes: i64,
    pub baseline_binary_sha256: String,
    pub candidate_binary_sha256: String,
    pub baseline_gn_args_sha256: String,
    pub candidate_gn_args_sha256: String,
    pub raw_samples_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceCaseResult {
    pub id: String,
    pub median_regression_percent: f64,
    pub p95_regression_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureManifest {
    pub schema_version: u32,
    pub id: String,
    pub status: EvidenceStatus,
    pub comparison: ExposureComparison,
    pub memory_safety: MemorySafetyMeasurement,
    pub maintenance: MaintenanceMeasurement,
    pub evidence: ExposureEvidence,
    #[serde(default)]
    pub results: Option<ExposureResults>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureComparison {
    pub upstream_revision: String,
    pub baseline_configuration: String,
    pub candidate_configuration: String,
    pub production_only: bool,
    pub exclude_tests: bool,
    pub exclude_generated_bindings: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySafetyMeasurement {
    pub metric: String,
    pub require_candidate_less_than_baseline: bool,
    pub report_unsafe_rust_blocks: bool,
    pub report_unsafe_rust_loc: bool,
    pub report_active_cpp_loc: bool,
    pub report_generated_boundary_loc: bool,
    pub report_manual_raw_pointer_fields: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceMeasurement {
    pub metrics: Vec<String>,
    pub non_increasing_metrics: Vec<String>,
    pub require_strict_decrease: bool,
    pub require_no_new_public_api: bool,
    pub require_no_new_mojom_methods: bool,
    pub require_no_increase_manual_raw_pointer_fields: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureEvidence {
    pub source_inventory: String,
    pub record_file_hashes: bool,
    pub record_measurement_tool_version: bool,
    pub record_raw_counts: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExposureResults {
    pub baseline_authored_memory_unsafe_loc: u64,
    pub candidate_authored_memory_unsafe_loc: u64,
    pub baseline_authored_production_loc: u64,
    pub candidate_authored_production_loc: u64,
    pub baseline_active_implementation_files: u64,
    pub candidate_active_implementation_files: u64,
    pub baseline_branch_points: u64,
    pub candidate_branch_points: u64,
    pub baseline_manual_raw_pointer_fields: u64,
    pub candidate_manual_raw_pointer_fields: u64,
    pub baseline_cross_language_forwarding_methods: u64,
    pub candidate_cross_language_forwarding_methods: u64,
    pub new_public_api_count: u64,
    pub new_mojom_method_count: u64,
    pub measurement_tool_version: String,
    pub file_hashes_sha256: String,
    pub raw_counts_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MigrationEvidence {
    pub directory: PathBuf,
    pub pilot: PilotManifest,
    pub parity: ParityManifest,
    pub performance: PerformanceManifest,
    pub exposure: ExposureManifest,
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read migration evidence `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse migration evidence `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(transparent)]
    Validation(#[from] ValidationErrors),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<String>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "migration evidence validation failed with {} error(s):",
            self.0.len()
        )?;
        for error in &self.0 {
            writeln!(f, "- {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

impl MigrationEvidence {
    pub fn load(directory: impl AsRef<Path>) -> Result<Self, LoadError> {
        let directory = directory.as_ref();
        let pilot: PilotManifest = load_toml(&directory.join("pilot.toml"))?;
        let parity = load_linked::<ParityManifest>(directory, &pilot.parity, "parity")?;
        let performance =
            load_linked::<PerformanceManifest>(directory, &pilot.performance, "performance")?;
        let exposure = load_linked::<ExposureManifest>(directory, &pilot.exposure, "exposure")?;
        let evidence = Self {
            directory: directory.to_path_buf(),
            pilot,
            parity,
            performance,
            exposure,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();
        for (name, version) in [
            ("pilot", self.pilot.schema_version),
            ("parity", self.parity.schema_version),
            ("performance", self.performance.schema_version),
            ("exposure", self.exposure.schema_version),
        ] {
            if version != SUPPORTED_SCHEMA_VERSION {
                errors.push(format!(
                    "{name} schema version {version} is unsupported; expected {SUPPORTED_SCHEMA_VERSION}"
                ));
            }
        }

        check_nonempty("pilot id", &self.pilot.id, &mut errors);
        for (kind, actual, expected) in [
            (
                "parity",
                self.parity.id.as_str(),
                format!("{}-parity", self.pilot.id),
            ),
            (
                "performance",
                self.performance.id.as_str(),
                format!("{}-performance", self.pilot.id),
            ),
            (
                "exposure",
                self.exposure.id.as_str(),
                format!("{}-exposure", self.pilot.id),
            ),
        ] {
            if actual != expected {
                errors.push(format!(
                    "{kind} evidence id `{actual}` does not match pilot id `{}`",
                    self.pilot.id
                ));
            }
        }
        check_nonempty(
            "upstream repository",
            &self.pilot.upstream.repository,
            &mut errors,
        );
        check_nonempty("upstream target", &self.pilot.upstream.target, &mut errors);
        check_nonempty(
            "upstream ownership",
            &self.pilot.upstream.ownership,
            &mut errors,
        );
        check_git_sha(
            "upstream revision",
            &self.pilot.upstream.revision,
            &mut errors,
        );
        if self.pilot.upstream.blobs.is_empty() {
            errors.push("upstream blob identity map must not be empty".to_owned());
        }
        for (name, digest) in &self.pilot.upstream.blobs {
            check_nonempty("upstream blob name", name, &mut errors);
            check_git_sha(&format!("upstream blob `{name}`"), digest, &mut errors);
        }

        check_nonempty("boundary kind", &self.pilot.boundary.kind, &mut errors);
        check_nonempty(
            "boundary interface",
            &self.pilot.boundary.interface,
            &mut errors,
        );
        check_nonempty("boundary mojom", &self.pilot.boundary.mojom, &mut errors);
        check_nonempty(
            "boundary Rust source",
            &self.pilot.boundary.rust_source,
            &mut errors,
        );
        check_nonempty(
            "boundary factory",
            &self.pilot.boundary.factory,
            &mut errors,
        );
        check_unique_nonempty("boundary method", &self.pilot.boundary.methods, &mut errors);
        check_unique_nonempty(
            "legacy source",
            &self.pilot.boundary.legacy_sources,
            &mut errors,
        );

        check_nonempty("rollback GN arg", &self.pilot.rollback.gn_arg, &mut errors);
        check_nonempty(
            "rollback default expression",
            &self.pilot.rollback.default_expression,
            &mut errors,
        );
        check_nonempty(
            "rollback shared test target",
            &self.pilot.rollback.shared_test_target,
            &mut errors,
        );
        if self.pilot.rollback.rust_value == self.pilot.rollback.fallback_value {
            errors.push("rollback Rust and fallback values must differ".to_owned());
        }

        let mut verification_ids = BTreeSet::new();
        for verification in &self.pilot.verification {
            check_nonempty("verification id", &verification.id, &mut errors);
            check_nonempty("verification target", &verification.target, &mut errors);
            if !verification_ids.insert(verification.id.as_str()) {
                errors.push(format!("duplicate verification id `{}`", verification.id));
            }
            if verification.status == EvidenceStatus::Passed {
                if verification.passed_tests.unwrap_or(0) == 0 {
                    errors.push(format!(
                        "passed verification `{}` must record at least one passed test",
                        verification.id
                    ));
                }
                if verification.failed_tests.unwrap_or(0) != 0 {
                    errors.push(format!(
                        "passed verification `{}` must record zero failed tests",
                        verification.id
                    ));
                }
            }
        }

        if self.pilot.rollback.status == EvidenceStatus::Verified {
            let rust_configuration = format!("{}=true", self.pilot.rollback.gn_arg);
            let fallback_configuration = format!("{}=false", self.pilot.rollback.gn_arg);
            let rust_passed = self.pilot.verification.iter().any(|item| {
                item.status == EvidenceStatus::Passed
                    && item.configuration.as_deref() == Some(rust_configuration.as_str())
                    && item.target == self.pilot.rollback.shared_test_target
            });
            let fallback_passed = self.pilot.verification.iter().any(|item| {
                item.status == EvidenceStatus::Passed
                    && item.configuration.as_deref() == Some(fallback_configuration.as_str())
                    && item.target == self.pilot.rollback.shared_test_target
                    && item.rust_receiver_dependencies_present == Some(false)
            });
            if !rust_passed || !fallback_passed {
                errors.push(
                    "verified rollback requires passed Rust and dependency-clean fallback configurations"
                        .to_owned(),
                );
            }
        }
        if matches!(
            self.pilot.m3_acceptance.rollback,
            EvidenceStatus::Verified | EvidenceStatus::Passed
        ) && self.pilot.rollback.status != EvidenceStatus::Verified
        {
            errors
                .push("M3 rollback cannot advance before rollback evidence is verified".to_owned());
        }
        if self.pilot.m3_acceptance.rollback == EvidenceStatus::Passed {
            let matrix = &self.parity.rollback_matrix;
            if !matrix.require_fallback_build || !matrix.require_shared_contract_test {
                errors.push(
                    "passed M3 rollback requires fallback-build and shared-contract checks"
                        .to_owned(),
                );
            }
            if ![matrix.linux, matrix.mac, matrix.win]
                .into_iter()
                .all(EvidenceStatus::is_satisfied)
            {
                errors.push(
                    "passed M3 rollback requires linux, mac, and win rollback rows to pass"
                        .to_owned(),
                );
            }
            check_platform_evidence("rollback", &matrix.evidence_sha256, true, &mut errors);
        } else {
            check_platform_evidence(
                "rollback",
                &self.parity.rollback_matrix.evidence_sha256,
                false,
                &mut errors,
            );
        }

        self.validate_implementation(&mut errors);

        for (kind, linked, actual) in [
            ("parity", self.pilot.parity.status, self.parity.status),
            (
                "performance",
                self.pilot.performance.status,
                self.performance.status,
            ),
            ("exposure", self.pilot.exposure.status, self.exposure.status),
        ] {
            if linked != actual {
                errors.push(format!(
                    "linked {kind} status {linked:?} does not match record status {actual:?}"
                ));
            }
        }

        self.validate_parity(&mut errors);
        self.validate_performance(&mut errors);
        self.validate_exposure(&mut errors);

        if self.pilot.status == PilotStatus::Complete {
            for (name, status) in [
                ("feature parity", self.pilot.m3_acceptance.feature_parity),
                (
                    "upstream test parity",
                    self.pilot.m3_acceptance.upstream_test_parity,
                ),
                (
                    "performance budget",
                    self.pilot.m3_acceptance.performance_budget,
                ),
                ("rollback", self.pilot.m3_acceptance.rollback),
                (
                    "memory-safety reduction",
                    self.pilot.m3_acceptance.memory_safety_reduction,
                ),
                (
                    "maintenance-complexity reduction",
                    self.pilot.m3_acceptance.maintenance_complexity_reduction,
                ),
            ] {
                if !status.is_satisfied() {
                    errors.push(format!(
                        "complete pilot requires satisfied {name}; found {status:?}"
                    ));
                }
            }
            if !self.pilot.implementation.status.is_satisfied() {
                errors.push(format!(
                    "complete pilot requires passed implementation patch; found {:?}",
                    self.pilot.implementation.status
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }

    fn validate_implementation(&self, errors: &mut Vec<String>) {
        let implementation = &self.pilot.implementation;
        if implementation.status == EvidenceStatus::Passed && implementation.patch.is_none() {
            errors.push("passed implementation evidence requires a patch artifact".to_owned());
        }

        let Some(patch) = implementation.patch.as_ref() else {
            return;
        };
        check_git_sha(
            "implementation patch base revision",
            &patch.base_revision,
            errors,
        );
        if patch.base_revision != self.pilot.upstream.revision {
            errors.push(
                "implementation patch base revision does not match pilot revision".to_owned(),
            );
        }
        check_sha256("implementation patch", &patch.sha256, errors);
        if !is_plain_patch_filename(&patch.path) {
            errors.push(format!(
                "implementation patch path `{}` must be a plain .patch filename",
                patch.path
            ));
            return;
        }

        let patch_path = self.directory.join(&patch.path);
        match fs::read(&patch_path) {
            Ok(bytes) => {
                let actual = format!("{:x}", Sha256::digest(&bytes));
                if actual != patch.sha256 {
                    errors.push(format!(
                        "implementation patch SHA-256 mismatch: declared {}, actual {actual}",
                        patch.sha256
                    ));
                }
            }
            Err(source) => errors.push(format!(
                "failed to read implementation patch `{}`: {source}",
                patch_path.display()
            )),
        }
    }

    fn validate_parity(&self, errors: &mut Vec<String>) {
        if self.parity.interface.mojom != self.pilot.boundary.mojom {
            errors.push("parity mojom path does not match pilot boundary".to_owned());
        }
        if self.parity.interface.name != self.pilot.boundary.interface {
            errors.push("parity interface name does not match pilot boundary".to_owned());
        }
        if as_set(&self.parity.interface.methods) != as_set(&self.pilot.boundary.methods) {
            errors.push("parity methods do not match pilot boundary methods".to_owned());
        }
        check_unique_nonempty(
            "parity interface method",
            &self.parity.interface.methods,
            errors,
        );
        check_unique_nonempty(
            "desktop platform",
            &self.parity.desktop_matrix.platforms,
            errors,
        );
        let required_platforms = BTreeSet::from(["linux", "mac", "win"]);
        if as_set(&self.parity.desktop_matrix.platforms) != required_platforms {
            errors.push("desktop parity matrix must cover linux, mac, and win exactly".to_owned());
        }

        if self.parity.contract_cases.is_empty() {
            errors.push("parity contract case list must not be empty".to_owned());
        }
        if self.parity.upstream_suites.is_empty() {
            errors.push("parity upstream suite list must not be empty".to_owned());
        }

        let mut suite_ids = BTreeSet::new();
        for suite in &self.parity.upstream_suites {
            check_nonempty("upstream suite id", &suite.id, errors);
            check_nonempty("upstream suite target", &suite.target, errors);
            if !suite_ids.insert(suite.id.as_str()) {
                errors.push(format!("duplicate upstream suite id `{}`", suite.id));
            }
            if let Some(digest) = &suite.evidence_sha256 {
                check_sha256(
                    &format!("upstream suite `{}` evidence", suite.id),
                    digest,
                    errors,
                );
            }
        }

        let mut case_ids = BTreeSet::new();
        for case in &self.parity.contract_cases {
            check_nonempty("contract case id", &case.id, errors);
            if !case_ids.insert(case.id.as_str()) {
                errors.push(format!("duplicate contract case id `{}`", case.id));
            }
            if let Some(method) = &case.method
                && !self.pilot.boundary.methods.contains(method)
            {
                errors.push(format!(
                    "contract case `{}` references unknown method `{method}`",
                    case.id
                ));
            }
            for method in &case.methods {
                if !self.pilot.boundary.methods.contains(method) {
                    errors.push(format!(
                        "contract case `{}` references unknown method `{method}`",
                        case.id
                    ));
                }
            }
            if let Some(digest) = &case.evidence_sha256 {
                check_sha256(
                    &format!("contract case `{}` evidence", case.id),
                    digest,
                    errors,
                );
            }
        }

        if self.pilot.m3_acceptance.feature_parity.is_satisfied() {
            let desktop = &self.parity.desktop_matrix;
            if ![desktop.linux, desktop.mac, desktop.win]
                .into_iter()
                .all(EvidenceStatus::is_satisfied)
            {
                errors
                    .push("satisfied feature parity requires all desktop rows to pass".to_owned());
            }
            if self
                .parity
                .contract_cases
                .iter()
                .any(|case| !case.status.is_satisfied())
            {
                errors.push(
                    "satisfied feature parity requires every contract case to pass".to_owned(),
                );
            }
            for case in &self.parity.contract_cases {
                if case.evidence_sha256.is_none() {
                    errors.push(format!(
                        "satisfied feature parity requires evidence for contract case `{}`",
                        case.id
                    ));
                }
            }
            check_platform_evidence("desktop parity", &desktop.evidence_sha256, true, errors);
        } else {
            check_platform_evidence(
                "desktop parity",
                &self.parity.desktop_matrix.evidence_sha256,
                false,
                errors,
            );
        }
        if self.pilot.m3_acceptance.upstream_test_parity.is_satisfied()
            && self
                .parity
                .upstream_suites
                .iter()
                .any(|suite| !suite.status.is_satisfied())
        {
            errors.push(
                "satisfied upstream test parity requires every upstream suite to pass".to_owned(),
            );
        }
        if self.pilot.m3_acceptance.upstream_test_parity.is_satisfied() {
            for suite in &self.parity.upstream_suites {
                if suite.evidence_sha256.is_none() {
                    errors.push(format!(
                        "satisfied upstream test parity requires evidence for suite `{}`",
                        suite.id
                    ));
                }
            }
        }
    }

    fn validate_performance(&self, errors: &mut Vec<String>) {
        if self.performance.comparison.upstream_revision != self.pilot.upstream.revision {
            errors.push("performance revision does not match pilot revision".to_owned());
        }
        let expected_baseline = format!(
            "{}={}",
            self.pilot.rollback.gn_arg, self.pilot.rollback.fallback_value
        );
        let expected_candidate = format!(
            "{}={}",
            self.pilot.rollback.gn_arg, self.pilot.rollback.rust_value
        );
        if self.performance.comparison.baseline_configuration != expected_baseline {
            errors.push(
                "performance baseline does not match rollback fallback configuration".to_owned(),
            );
        }
        if self.performance.comparison.candidate_configuration != expected_candidate {
            errors.push("performance candidate does not match Rust configuration".to_owned());
        }
        if self.performance.workload.samples < 3
            || self.performance.workload.messages_per_sample == 0
            || self.performance.workload.cases.is_empty()
        {
            errors.push("performance workload is too small to be meaningful".to_owned());
        }
        if self.performance.validity.minimum_completed_samples > self.performance.workload.samples {
            errors.push("minimum completed samples exceeds configured samples".to_owned());
        }
        if !self
            .performance
            .latency_budget
            .median_regression_percent_max
            .is_finite()
            || !self
                .performance
                .latency_budget
                .p95_regression_percent_max
                .is_finite()
            || self
                .performance
                .latency_budget
                .median_regression_percent_max
                < 0.0
            || self.performance.latency_budget.p95_regression_percent_max < 0.0
        {
            errors.push("performance latency budgets must be finite and non-negative".to_owned());
        }
        if let Some(results) = &self.performance.results {
            if results.completed_samples < self.performance.validity.minimum_completed_samples {
                errors
                    .push("performance results do not contain enough completed samples".to_owned());
            }
            let mut result_ids = BTreeSet::new();
            for result in &results.cases {
                check_nonempty("performance result case id", &result.id, errors);
                if !result_ids.insert(result.id.as_str()) {
                    errors.push(format!("duplicate performance result case `{}`", result.id));
                }
                if !result.median_regression_percent.is_finite()
                    || !result.p95_regression_percent.is_finite()
                {
                    errors.push(format!(
                        "performance result `{}` contains non-finite latency values",
                        result.id
                    ));
                }
            }
            if result_ids != as_set(&self.performance.workload.cases) {
                errors.push(
                    "performance result cases do not match configured workload cases".to_owned(),
                );
            }
            for (label, digest) in [
                (
                    "baseline performance binary",
                    &results.baseline_binary_sha256,
                ),
                (
                    "candidate performance binary",
                    &results.candidate_binary_sha256,
                ),
                (
                    "baseline performance GN args",
                    &results.baseline_gn_args_sha256,
                ),
                (
                    "candidate performance GN args",
                    &results.candidate_gn_args_sha256,
                ),
                ("raw performance samples", &results.raw_samples_sha256),
            ] {
                check_sha256(label, digest, errors);
            }
        }
        match (&self.performance.results, self.performance.status) {
            (Some(results), EvidenceStatus::Passed) => {
                errors.extend(performance_budget_violations(&self.performance, results));
            }
            (Some(results), EvidenceStatus::Failed) => {
                if performance_budget_violations(&self.performance, results).is_empty() {
                    errors.push(
                        "failed performance record must violate at least one configured budget"
                            .to_owned(),
                    );
                }
            }
            (Some(_), _) => errors.push(
                "measured performance results require status `passed` or `failed`".to_owned(),
            ),
            (None, EvidenceStatus::Passed) => {
                errors.push("passed performance record requires measured results".to_owned());
            }
            (None, EvidenceStatus::Failed) => {
                errors.push("failed performance record requires measured results".to_owned());
            }
            (None, _) => {}
        }
        if self.pilot.m3_acceptance.performance_budget.is_satisfied()
            && self.performance.status != EvidenceStatus::Passed
        {
            errors.push(
                "satisfied performance acceptance requires a passed performance record".to_owned(),
            );
        }
    }

    fn validate_exposure(&self, errors: &mut Vec<String>) {
        if self.exposure.comparison.upstream_revision != self.pilot.upstream.revision {
            errors.push("exposure revision does not match pilot revision".to_owned());
        }
        let expected_baseline = format!(
            "{}={}",
            self.pilot.rollback.gn_arg, self.pilot.rollback.fallback_value
        );
        let expected_candidate = format!(
            "{}={}",
            self.pilot.rollback.gn_arg, self.pilot.rollback.rust_value
        );
        if self.exposure.comparison.baseline_configuration != expected_baseline {
            errors.push(
                "exposure baseline does not match rollback fallback configuration".to_owned(),
            );
        }
        if self.exposure.comparison.candidate_configuration != expected_candidate {
            errors.push("exposure candidate does not match Rust configuration".to_owned());
        }
        check_nonempty(
            "memory-safety metric",
            &self.exposure.memory_safety.metric,
            errors,
        );
        check_unique_nonempty(
            "maintenance metric",
            &self.exposure.maintenance.metrics,
            errors,
        );
        check_unique_nonempty(
            "non-increasing maintenance metric",
            &self.exposure.maintenance.non_increasing_metrics,
            errors,
        );
        for metric in &self.exposure.maintenance.non_increasing_metrics {
            if !self.exposure.maintenance.metrics.contains(metric) {
                errors.push(format!(
                    "non-increasing maintenance metric `{metric}` is not in the reported metric set"
                ));
            }
            if maintenance_metric_pair(None, metric).is_none() {
                errors.push(format!("unsupported maintenance metric `{metric}"));
            }
        }
        let source_spec = if !is_plain_toml_filename(&self.exposure.evidence.source_inventory) {
            errors.push(format!(
                "exposure source inventory path `{}` must be a plain .toml filename",
                self.exposure.evidence.source_inventory
            ));
            None
        } else {
            let path = self
                .directory
                .join(&self.exposure.evidence.source_inventory);
            match exposure_measure::ExposureSourceSpec::load(&path) {
                Ok(spec) => Some(spec),
                Err(error) => {
                    errors.push(format!("invalid exposure source inventory: {error}"));
                    None
                }
            }
        };
        if let Some(results) = &self.exposure.results {
            if results.measurement_tool_version
                != exposure_measure::EXPOSURE_MEASUREMENT_TOOL_VERSION
            {
                errors.push(format!(
                    "unsupported exposure measurement tool version `{}`; expected `{}`",
                    results.measurement_tool_version,
                    exposure_measure::EXPOSURE_MEASUREMENT_TOOL_VERSION
                ));
            }
            if let Some(spec) = source_spec.as_ref() {
                let expected = [
                    (
                        "baseline active implementation files",
                        results.baseline_active_implementation_files,
                        spec.baseline.files.len() as u64,
                    ),
                    (
                        "candidate active implementation files",
                        results.candidate_active_implementation_files,
                        spec.candidate.files.len() as u64,
                    ),
                    (
                        "baseline cross-language forwarding methods",
                        results.baseline_cross_language_forwarding_methods,
                        spec.baseline.cross_language_forwarding_methods.len() as u64,
                    ),
                    (
                        "candidate cross-language forwarding methods",
                        results.candidate_cross_language_forwarding_methods,
                        spec.candidate.cross_language_forwarding_methods.len() as u64,
                    ),
                    (
                        "new public API count",
                        results.new_public_api_count,
                        spec.contract_review.new_public_api_count,
                    ),
                    (
                        "new Mojom method count",
                        results.new_mojom_method_count,
                        spec.contract_review.new_mojom_method_count,
                    ),
                ];
                for (label, measured, declared) in expected {
                    if measured != declared {
                        errors.push(format!(
                            "exposure {label} {measured} does not match source inventory {declared}"
                        ));
                    }
                }
            }
            let memory_safety_violations =
                exposure_memory_safety_violations(&self.exposure, results);
            let maintenance_violations = exposure_maintenance_violations(&self.exposure, results);
            match self.exposure.status {
                EvidenceStatus::Passed => {
                    errors.extend(memory_safety_violations.iter().cloned());
                    errors.extend(maintenance_violations.iter().cloned());
                }
                EvidenceStatus::Failed => {
                    if memory_safety_violations.is_empty() && maintenance_violations.is_empty() {
                        errors.push(
                            "failed exposure record must violate at least one configured acceptance criterion"
                                .to_owned(),
                        );
                    }
                }
                _ => errors.push(
                    "measured exposure results require status `passed` or `failed`".to_owned(),
                ),
            }
            check_nonempty(
                "exposure measurement tool version",
                &results.measurement_tool_version,
                errors,
            );
            check_sha256("exposure file hashes", &results.file_hashes_sha256, errors);
            check_sha256("exposure raw counts", &results.raw_counts_sha256, errors);
        }
        match (&self.exposure.results, self.exposure.status) {
            (None, EvidenceStatus::Passed) => {
                errors.push("passed exposure record requires measured results".to_owned());
            }
            (None, EvidenceStatus::Failed) => {
                errors.push("failed exposure record requires measured results".to_owned());
            }
            _ => {}
        }

        if self
            .pilot
            .m3_acceptance
            .memory_safety_reduction
            .is_satisfied()
        {
            match self.exposure.results.as_ref() {
                Some(results) => {
                    errors.extend(exposure_memory_safety_violations(&self.exposure, results))
                }
                None => errors.push(
                    "satisfied memory-safety acceptance requires measured exposure results"
                        .to_owned(),
                ),
            }
        }
        if self
            .pilot
            .m3_acceptance
            .maintenance_complexity_reduction
            .is_satisfied()
        {
            match self.exposure.results.as_ref() {
                Some(results) => {
                    errors.extend(exposure_maintenance_violations(&self.exposure, results))
                }
                None => errors.push(
                    "satisfied maintenance acceptance requires measured exposure results"
                        .to_owned(),
                ),
            }
        }
        if self
            .pilot
            .m3_acceptance
            .memory_safety_reduction
            .is_satisfied()
            && self
                .pilot
                .m3_acceptance
                .maintenance_complexity_reduction
                .is_satisfied()
            && self.exposure.status != EvidenceStatus::Passed
        {
            errors
                .push("satisfied exposure acceptance requires a passed exposure record".to_owned());
        }
    }
}

fn load_linked<T: for<'de> Deserialize<'de>>(
    directory: &Path,
    linked: &LinkedEvidence,
    kind: &str,
) -> Result<T, LoadError> {
    let correct_field = match kind {
        "parity" => {
            linked.matrix.is_some() && linked.budget.is_none() && linked.measurement.is_none()
        }
        "performance" => {
            linked.matrix.is_none() && linked.budget.is_some() && linked.measurement.is_none()
        }
        "exposure" => {
            linked.matrix.is_none() && linked.budget.is_none() && linked.measurement.is_some()
        }
        _ => false,
    };
    if !correct_field {
        return Err(LoadError::Validation(ValidationErrors(vec![format!(
            "{kind} evidence must use its designated link field"
        )])));
    }
    let link_count = [
        linked.matrix.as_deref(),
        linked.budget.as_deref(),
        linked.measurement.as_deref(),
    ]
    .into_iter()
    .flatten()
    .count();
    if link_count != 1 {
        return Err(LoadError::Validation(ValidationErrors(vec![format!(
            "{kind} evidence must declare exactly one linked TOML file; found {link_count}"
        )])));
    }
    let path = linked
        .path()
        .expect("exactly one evidence link was checked");
    if !is_plain_toml_filename(path) {
        return Err(LoadError::Validation(ValidationErrors(vec![format!(
            "{kind} evidence path `{path}` must be a plain .toml filename"
        )])));
    }
    load_toml(&directory.join(path))
}

fn load_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, LoadError> {
    let display = path.display().to_string();
    let source = fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: display.clone(),
        source,
    })?;
    toml::from_str(&source).map_err(|source| LoadError::Parse {
        path: display,
        source,
    })
}

fn is_plain_toml_filename(value: &str) -> bool {
    let path = Path::new(value);
    path.extension()
        .is_some_and(|extension| extension == "toml")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && path
            .file_name()
            .is_some_and(|file| file == path.as_os_str())
}

fn is_plain_patch_filename(value: &str) -> bool {
    let path = Path::new(value);
    path.extension()
        .is_some_and(|extension| extension == "patch")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && path
            .file_name()
            .is_some_and(|file| file == path.as_os_str())
}

fn check_nonempty(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.trim().is_empty() {
        errors.push(format!("{label} must not be empty"));
    }
}

fn check_unique_nonempty(label: &str, values: &[String], errors: &mut Vec<String>) {
    if values.is_empty() {
        errors.push(format!("{label} list must not be empty"));
        return;
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            errors.push(format!("{label} must not be empty"));
        } else if !seen.insert(value.as_str()) {
            errors.push(format!("duplicate {label} `{value}`"));
        }
    }
}

fn check_git_sha(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        errors.push(format!(
            "{label} must be a 40-character lowercase Git SHA-1"
        ));
    }
}

fn maintenance_metric_pair(results: Option<&ExposureResults>, metric: &str) -> Option<(u64, u64)> {
    let values = results.map(|results| match metric {
        "authored_production_loc" => (
            results.baseline_authored_production_loc,
            results.candidate_authored_production_loc,
        ),
        "active_implementation_files" => (
            results.baseline_active_implementation_files,
            results.candidate_active_implementation_files,
        ),
        "branch_points" => (
            results.baseline_branch_points,
            results.candidate_branch_points,
        ),
        "manual_raw_pointer_fields" => (
            results.baseline_manual_raw_pointer_fields,
            results.candidate_manual_raw_pointer_fields,
        ),
        "cross_language_forwarding_methods" => (
            results.baseline_cross_language_forwarding_methods,
            results.candidate_cross_language_forwarding_methods,
        ),
        _ => (u64::MAX, u64::MAX),
    });
    match (results, values) {
        (_, Some((u64::MAX, u64::MAX))) => None,
        (Some(_), Some(values)) => Some(values),
        (None, _) => match metric {
            "authored_production_loc"
            | "active_implementation_files"
            | "branch_points"
            | "manual_raw_pointer_fields"
            | "cross_language_forwarding_methods" => Some((0, 0)),
            _ => None,
        },
        _ => None,
    }
}

fn performance_budget_violations(
    performance: &PerformanceManifest,
    results: &PerformanceResults,
) -> Vec<String> {
    let mut violations = Vec::new();
    for result in &results.cases {
        if result.median_regression_percent
            > performance.latency_budget.median_regression_percent_max
        {
            violations.push(format!(
                "performance result `{}` exceeds the median regression budget",
                result.id
            ));
        }
        if result.p95_regression_percent > performance.latency_budget.p95_regression_percent_max {
            violations.push(format!(
                "performance result `{}` exceeds the p95 regression budget",
                result.id
            ));
        }
    }
    if results.steady_state_rss_regression_bytes
        > performance
            .memory_budget
            .steady_state_rss_regression_bytes_max as i64
    {
        violations.push("performance results exceed the steady-state RSS budget".to_owned());
    }
    violations
}

fn exposure_memory_safety_violations(
    exposure: &ExposureManifest,
    results: &ExposureResults,
) -> Vec<String> {
    let mut violations = Vec::new();
    if exposure.memory_safety.require_candidate_less_than_baseline
        && results.candidate_authored_memory_unsafe_loc
            >= results.baseline_authored_memory_unsafe_loc
    {
        violations.push("exposure results do not reduce authored memory-unsafe LOC".to_owned());
    }
    violations
}

fn exposure_maintenance_violations(
    exposure: &ExposureManifest,
    results: &ExposureResults,
) -> Vec<String> {
    let mut violations = Vec::new();
    let mut strict_decrease = false;
    for metric in &exposure.maintenance.non_increasing_metrics {
        if let Some((baseline, candidate)) = maintenance_metric_pair(Some(results), metric) {
            if candidate > baseline {
                violations.push(format!(
                    "maintenance metric `{metric}` increases from {baseline} to {candidate}"
                ));
            }
            strict_decrease |= candidate < baseline;
        }
    }
    if exposure.maintenance.require_strict_decrease && !strict_decrease {
        violations
            .push("maintenance results require at least one strict structural decrease".to_owned());
    }
    if exposure
        .maintenance
        .require_no_increase_manual_raw_pointer_fields
        && results.candidate_manual_raw_pointer_fields > results.baseline_manual_raw_pointer_fields
    {
        violations.push("exposure results increase manual raw-pointer fields".to_owned());
    }
    if exposure.maintenance.require_no_new_public_api && results.new_public_api_count != 0 {
        violations.push("exposure results introduce new public API".to_owned());
    }
    if exposure.maintenance.require_no_new_mojom_methods && results.new_mojom_method_count != 0 {
        violations.push("exposure results introduce new Mojom methods".to_owned());
    }
    violations
}

fn check_platform_evidence(
    label: &str,
    evidence: &BTreeMap<String, String>,
    require_complete: bool,
    errors: &mut Vec<String>,
) {
    let required = BTreeSet::from(["linux", "mac", "win"]);
    let actual: BTreeSet<_> = evidence.keys().map(String::as_str).collect();
    for (platform, digest) in evidence {
        if !required.contains(platform.as_str()) {
            errors.push(format!(
                "{label} evidence contains unknown platform `{platform}`"
            ));
        }
        check_sha256(&format!("{label} `{platform}` evidence"), digest, errors);
    }
    if require_complete && actual != required {
        errors.push(format!(
            "{label} pass requires evidence for linux, mac, and win exactly"
        ));
    }
}

fn check_sha256(label: &str, value: &str, errors: &mut Vec<String>) {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        errors.push(format!(
            "{label} must be a 64-character lowercase SHA-256 digest"
        ));
    }
}

fn as_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_path_rejects_traversal() {
        assert!(is_plain_toml_filename("parity.toml"));
        assert!(!is_plain_toml_filename("../parity.toml"));
        assert!(!is_plain_toml_filename("nested/parity.toml"));
        assert!(!is_plain_toml_filename("parity.json"));
        assert!(is_plain_patch_filename("chromium.patch"));
        assert!(!is_plain_patch_filename("../chromium.patch"));
        assert!(!is_plain_patch_filename("nested/chromium.patch"));
        assert!(!is_plain_patch_filename("chromium.diff"));
    }

    #[test]
    fn evidence_status_satisfaction_is_explicit() {
        assert!(EvidenceStatus::Passed.is_satisfied());
        assert!(!EvidenceStatus::Verified.is_satisfied());
        assert!(!EvidenceStatus::PassedLinux.is_satisfied());
        assert!(!EvidenceStatus::Partial.is_satisfied());
        assert!(!EvidenceStatus::DefinedNotMeasured.is_satisfied());
        assert!(!EvidenceStatus::Pending.is_satisfied());
    }
}
