#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;

use chromifer_migration::{MigrationEvidence, PilotStatus, exposure_measure::ExposureSourceSpec};

fn migrations_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations")
}

fn ukm_pilot() -> MigrationEvidence {
    MigrationEvidence::load(migrations_root().join("services-metrics-ukm-recorder"))
        .expect("load UKM pilot")
}

#[test]
fn committed_migration_records_validate() {
    let migrations = migrations_root();
    let mut pilots = 0usize;

    for entry in fs::read_dir(&migrations).expect("read migrations directory") {
        let entry = entry.expect("read migrations entry");
        let path = entry.path();
        if !path.is_dir() || !path.join("pilot.toml").is_file() {
            continue;
        }
        let evidence = MigrationEvidence::load(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let source_inventory = path.join(&evidence.exposure.evidence.source_inventory);
        ExposureSourceSpec::load(&source_inventory)
            .unwrap_or_else(|error| panic!("{}: {error}", source_inventory.display()));
        pilots += 1;
    }

    assert!(
        pilots > 0,
        "expected at least one committed migration pilot"
    );
}

#[test]
fn incomplete_pilot_cannot_claim_complete() {
    let mut evidence = ukm_pilot();
    evidence.pilot.status = PilotStatus::Complete;

    let errors = evidence
        .validate()
        .expect_err("incomplete M3 evidence must not validate as complete");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("complete pilot requires satisfied feature parity")),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn performance_revision_must_match_pilot_revision() {
    let mut evidence = ukm_pilot();
    evidence.performance.comparison.upstream_revision = "0".repeat(40);

    let errors = evidence
        .validate()
        .expect_err("cross-revision performance evidence must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "performance revision does not match pilot revision"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn verified_rollback_requires_dependency_clean_fallback() {
    let mut evidence = ukm_pilot();
    let fallback = evidence
        .pilot
        .verification
        .iter_mut()
        .find(|item| item.configuration.as_deref() == Some("use_rust_ukm_recorder=false"))
        .expect("fallback verification");
    fallback.rust_receiver_dependencies_present = Some(true);

    let errors = evidence
        .validate()
        .expect_err("fallback retaining Rust receiver dependencies must be rejected");
    assert!(
        errors.0.iter().any(|error| {
            error.contains(
                "verified rollback requires passed Rust and dependency-clean fallback configurations",
            )
        }),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn parity_methods_must_match_pinned_boundary() {
    let mut evidence = ukm_pilot();
    evidence
        .parity
        .interface
        .methods
        .push("UnknownMethod".to_owned());

    let errors = evidence
        .validate()
        .expect_err("parity method drift must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "parity methods do not match pilot boundary methods"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn linked_status_must_match_evidence_record() {
    let mut evidence = ukm_pilot();
    evidence.performance.status = chromifer_migration::EvidenceStatus::Passed;

    let errors = evidence
        .validate()
        .expect_err("linked status drift must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("linked performance status")),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn parity_requires_at_least_one_upstream_suite() {
    let mut evidence = ukm_pilot();
    evidence.parity.upstream_suites.clear();

    let errors = evidence
        .validate()
        .expect_err("empty upstream suite set must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "parity upstream suite list must not be empty"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn passed_rollback_requires_full_desktop_matrix() {
    let mut evidence = ukm_pilot();
    evidence.pilot.m3_acceptance.rollback = chromifer_migration::EvidenceStatus::Passed;

    let errors = evidence
        .validate()
        .expect_err("aggregate rollback must not pass before every desktop row passes");
    assert!(
        errors.0.iter().any(|error| {
            error == "passed M3 rollback requires linux, mac, and win rollback rows to pass"
        }),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn passed_performance_requires_measured_results() {
    let mut evidence = ukm_pilot();
    evidence.performance.status = chromifer_migration::EvidenceStatus::Passed;
    evidence.pilot.performance.status = chromifer_migration::EvidenceStatus::Passed;

    let errors = evidence
        .validate()
        .expect_err("performance cannot pass without measured results");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "passed performance record requires measured results"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn passed_exposure_requires_measured_results() {
    let mut evidence = ukm_pilot();
    evidence.exposure.status = chromifer_migration::EvidenceStatus::Passed;
    evidence.pilot.exposure.status = chromifer_migration::EvidenceStatus::Passed;

    let errors = evidence
        .validate()
        .expect_err("exposure cannot pass without measured results");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "passed exposure record requires measured results"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn exposure_configuration_must_match_rollback_pair() {
    let mut evidence = ukm_pilot();
    evidence.exposure.comparison.candidate_configuration = "use_rust_ukm_recorder=false".to_owned();

    let errors = evidence
        .validate()
        .expect_err("exposure candidate config drift must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "exposure candidate does not match Rust configuration"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn linked_evidence_ids_must_belong_to_pilot() {
    let mut evidence = ukm_pilot();
    evidence.performance.id = "other-migration-performance".to_owned();

    let errors = evidence
        .validate()
        .expect_err("cross-pilot linked evidence must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("performance evidence id")),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn maintenance_non_increasing_metrics_must_be_reported_and_supported() {
    let mut evidence = ukm_pilot();
    evidence
        .exposure
        .maintenance
        .non_increasing_metrics
        .push("invented_metric".to_owned());

    let errors = evidence
        .validate()
        .expect_err("unknown maintenance metric must be rejected");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("invented_metric")),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn verified_rollback_requires_exact_shared_contract_target() {
    let mut evidence = ukm_pilot();
    let fallback = evidence
        .pilot
        .verification
        .iter_mut()
        .find(|item| item.configuration.as_deref() == Some("use_rust_ukm_recorder=false"))
        .expect("fallback verification");
    fallback.target = "//unrelated:test".to_owned();
    let errors = evidence
        .validate()
        .expect_err("unrelated fallback test must not verify rollback");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("verified rollback requires"))
    );
}

#[test]
fn feature_parity_pass_requires_digested_contract_and_platform_evidence() {
    let mut evidence = ukm_pilot();
    evidence.pilot.m3_acceptance.feature_parity = chromifer_migration::EvidenceStatus::Passed;
    for case in &mut evidence.parity.contract_cases {
        case.status = chromifer_migration::EvidenceStatus::Passed;
    }
    evidence.parity.desktop_matrix.linux = chromifer_migration::EvidenceStatus::Passed;
    evidence.parity.desktop_matrix.mac = chromifer_migration::EvidenceStatus::Passed;
    evidence.parity.desktop_matrix.win = chromifer_migration::EvidenceStatus::Passed;
    let errors = evidence
        .validate()
        .expect_err("feature parity cannot pass without evidence digests");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("requires evidence"))
    );
}

#[test]
fn upstream_parity_pass_requires_suite_evidence_digest() {
    let mut evidence = ukm_pilot();
    evidence.pilot.m3_acceptance.upstream_test_parity = chromifer_migration::EvidenceStatus::Passed;
    for suite in &mut evidence.parity.upstream_suites {
        suite.status = chromifer_migration::EvidenceStatus::Passed;
    }
    let errors = evidence
        .validate()
        .expect_err("upstream parity cannot pass without suite evidence");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("requires evidence for suite"))
    );
}

#[test]
fn rollback_pass_requires_platform_evidence_digests() {
    let mut evidence = ukm_pilot();
    evidence.pilot.m3_acceptance.rollback = chromifer_migration::EvidenceStatus::Passed;
    evidence.parity.rollback_matrix.linux = chromifer_migration::EvidenceStatus::Passed;
    evidence.parity.rollback_matrix.mac = chromifer_migration::EvidenceStatus::Passed;
    evidence.parity.rollback_matrix.win = chromifer_migration::EvidenceStatus::Passed;
    let errors = evidence
        .validate()
        .expect_err("rollback cannot pass without platform evidence");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("rollback pass requires evidence"))
    );
}

#[test]
fn implementation_cannot_pass_without_patch_artifact() {
    let mut evidence = ukm_pilot();
    evidence.pilot.implementation.status = chromifer_migration::EvidenceStatus::Passed;
    evidence.pilot.implementation.patch = None;

    let errors = evidence
        .validate()
        .expect_err("implementation cannot pass without a patch artifact");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error == "passed implementation evidence requires a patch artifact"),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn complete_pilot_requires_passed_patch_artifact() {
    let mut evidence = ukm_pilot();
    evidence.pilot.status = PilotStatus::Complete;
    evidence.pilot.implementation.status = chromifer_migration::EvidenceStatus::Pending;
    evidence.pilot.implementation.patch = None;

    let errors = evidence
        .validate()
        .expect_err("complete pilot cannot omit implementation patch evidence");
    assert!(
        errors
            .0
            .iter()
            .any(|error| error.contains("complete pilot requires passed implementation patch")),
        "unexpected validation errors: {:?}",
        errors.0
    );
}

#[test]
fn exposure_source_inventory_path_must_stay_inside_migration_directory() {
    let mut evidence = ukm_pilot();
    evidence.exposure.evidence.source_inventory = "../escape.toml".to_owned();

    let errors = evidence
        .validate()
        .expect_err("exposure source inventory traversal must be rejected");
    assert!(
        errors.0.iter().any(|error| {
            error.contains("exposure source inventory path")
                && error.contains("must be a plain .toml filename")
        }),
        "unexpected validation errors: {:?}",
        errors.0
    );
}
