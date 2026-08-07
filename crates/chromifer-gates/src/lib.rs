#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chromifer_build::BridgeProvenance;
use chromifer_cabi::CAbiProvenance;
use chromifer_checkout::{CheckoutContract, CheckoutReport, MetadataMode};
use chromifer_coverage::{CoverageReport, verify_report_manifest};
use chromifer_integration::IntegrationContract;
use chromifer_manifest::{
    CompatibilityGate, GateExecution, GateInput, Manifest, ValidationErrors,
    normalize_repo_relative_path,
};
use chromifer_mojo::MojoProvenance;
use chromifer_safety::UnsafeAuditReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTRACT_SCHEMA_VERSION: u32 = 1;
const BUILD_PROVENANCE_SCHEMA_VERSION: u32 = 4;
const C_ABI_PROVENANCE_SCHEMA_VERSION: u32 = 1;
const MOJO_PROVENANCE_SCHEMA_VERSION: u32 = 1;
const UNSAFE_REPORT_SCHEMA_VERSION: u32 = 1;
const CHECKOUT_CONTRACT_SCHEMA_VERSION: u32 = 1;
const CHECKOUT_REPORT_SCHEMA_VERSION: u32 = 1;
const COVERAGE_REPORT_SCHEMA_VERSION: u32 = 1;
const INTEGRATION_CONTRACT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveGateOptions {
    pub repo_root: PathBuf,
    pub manifest: PathBuf,
    pub contract: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedGateManifest {
    pub manifest_toml: String,
    pub summary: DeriveGateSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeriveGateSummary {
    pub source_manifest: String,
    pub contract: String,
    pub output: String,
    pub generated_gates: usize,
    pub attached_modules: usize,
    pub declared_inputs: usize,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateContract {
    pub schema_version: u32,
    #[serde(default)]
    pub runner: GateRunner,
    pub checks: Vec<GateCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRunner {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
}

impl Default for GateRunner {
    fn default() -> Self {
        Self {
            program: "chromifer".to_owned(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GateCheck {
    RustGn {
        id: String,
        cargo_manifest: String,
        provenance: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    CAbi {
        id: String,
        package_root: String,
        provenance: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    Mojo {
        id: String,
        package_root: String,
        provenance: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    Unsafe {
        id: String,
        workspace_root: String,
        report: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    Checkout {
        id: String,
        workspace_root: String,
        contract: String,
        report: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    Integration {
        id: String,
        source_root: String,
        contract: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
    Coverage {
        id: String,
        manifest: String,
        source_root: String,
        export: String,
        report: String,
        #[serde(default)]
        modules: Vec<String>,
        #[serde(default)]
        targets: Vec<String>,
    },
}

impl GateCheck {
    fn id(&self) -> &str {
        match self {
            Self::RustGn { id, .. }
            | Self::CAbi { id, .. }
            | Self::Mojo { id, .. }
            | Self::Unsafe { id, .. }
            | Self::Checkout { id, .. }
            | Self::Integration { id, .. }
            | Self::Coverage { id, .. } => id,
        }
    }

    fn modules(&self) -> &[String] {
        match self {
            Self::RustGn { modules, .. }
            | Self::CAbi { modules, .. }
            | Self::Mojo { modules, .. }
            | Self::Unsafe { modules, .. }
            | Self::Checkout { modules, .. }
            | Self::Integration { modules, .. }
            | Self::Coverage { modules, .. } => modules,
        }
    }

    fn targets(&self) -> &[String] {
        match self {
            Self::RustGn { targets, .. }
            | Self::CAbi { targets, .. }
            | Self::Mojo { targets, .. }
            | Self::Unsafe { targets, .. }
            | Self::Checkout { targets, .. }
            | Self::Integration { targets, .. }
            | Self::Coverage { targets, .. } => targets,
        }
    }
}

#[derive(Debug, Error)]
pub enum GateDeriveError {
    #[error("repository root `{0}` is not an accessible directory")]
    InvalidRepoRoot(String),
    #[error("path `{0}` must be a repository-relative path without traversal")]
    InvalidRelativePath(String),
    #[error("path `{0}` is outside the repository root")]
    PathOutsideRepo(String),
    #[error("required file `{0}` does not exist")]
    MissingFile(String),
    #[error("gate input `{0}` must not be a symlink")]
    InputSymlink(String),
    #[error("output `{0}` must be a .toml file inside an existing repository directory")]
    InvalidOutput(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse source manifest TOML: {0}")]
    ParseManifest(#[from] toml::de::Error),
    #[error("failed to parse or encode JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to encode generated manifest TOML: {0}")]
    EncodeManifest(#[from] toml::ser::Error),
    #[error("unsupported gate contract schema version {found}; supported version is {supported}")]
    UnsupportedContractSchema { found: u32, supported: u32 },
    #[error("gate contract contains no checks")]
    EmptyContract,
    #[error("gate runner program must not be empty or contain NUL")]
    InvalidRunnerProgram,
    #[error("gate runner arguments must not contain NUL")]
    InvalidRunnerArgument,
    #[error("gate check id `{0}` is empty or duplicated")]
    InvalidGateId(String),
    #[error("gate check `{gate}` contains duplicate module `{module}`")]
    DuplicateModule { gate: String, module: String },
    #[error("gate check `{gate}` contains duplicate target `{target}`")]
    DuplicateTarget { gate: String, target: String },
    #[error("gate `{gate}` references unknown module `{module}`")]
    UnknownModule { gate: String, module: String },
    #[error("source manifest already contains gate `{0}`")]
    ExistingGate(String),
    #[error(
        "unsupported {kind} provenance schema version {found}; supported version is {supported}"
    )]
    UnsupportedProvenanceSchema {
        kind: &'static str,
        found: u32,
        supported: u32,
    },
    #[error("digest mismatch for `{path}`: expected {expected}, found {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("provenance `{0}` is not in the expected package directory")]
    InvalidProvenanceLocation(String),
    #[error("coverage evidence is invalid: {0}")]
    InvalidCoverageEvidence(String),
    #[error("generated C++ consumer header `{0}` is outside its package")]
    HeaderOutsidePackage(String),
    #[error("generated manifest is invalid: {0}")]
    ManifestValidation(#[from] ValidationErrors),
    #[error("generated file `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("generated file `{0}` is missing or differs from the gate contract")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn derive_and_write(
    options: &DeriveGateOptions,
) -> Result<GeneratedGateManifest, GateDeriveError> {
    let generated = derive_gate_manifest(options)?;
    let (_, output_path, _) = output_path(options)?;
    if options.check {
        let actual = fs::read(&output_path)
            .map_err(|_| GateDeriveError::Drift(output_path.display().to_string()))?;
        if actual != generated.manifest_toml.as_bytes() {
            return Err(GateDeriveError::Drift(output_path.display().to_string()));
        }
        return Ok(generated);
    }
    if output_path.exists() && !options.force {
        return Err(GateDeriveError::OutputExists(
            output_path.display().to_string(),
        ));
    }
    fs::write(&output_path, generated.manifest_toml.as_bytes()).map_err(|source| {
        GateDeriveError::WriteFile {
            path: output_path.display().to_string(),
            source,
        }
    })?;
    Ok(generated)
}

pub fn derive_gate_manifest(
    options: &DeriveGateOptions,
) -> Result<GeneratedGateManifest, GateDeriveError> {
    let root = canonical_root(&options.repo_root)?;
    let (manifest_path, manifest_relative) = existing_repo_file(&root, &options.manifest)?;
    let (contract_path, contract_relative) = existing_repo_file(&root, &options.contract)?;
    let (_, _, output_relative) = output_path(options)?;

    let manifest_bytes = read_file(&manifest_path)?;
    let contract_bytes = read_file(&contract_path)?;
    let mut manifest: Manifest = toml::from_str(&String::from_utf8_lossy(&manifest_bytes))?;
    let mut contract: GateContract = serde_json::from_slice(&contract_bytes)?;
    normalize_contract(&mut contract)?;

    let common_inputs = [
        GateInput {
            path: manifest_relative.clone(),
            sha256: sha256_hex(&manifest_bytes),
        },
        GateInput {
            path: contract_relative.clone(),
            sha256: sha256_hex(&contract_bytes),
        },
    ];

    let existing: BTreeSet<_> = manifest.gates.iter().map(|gate| gate.id.clone()).collect();
    let mut generated = Vec::new();
    let mut attached_modules = BTreeSet::new();
    let mut declared_inputs = 0;
    for check in &contract.checks {
        if existing.contains(check.id()) {
            return Err(GateDeriveError::ExistingGate(check.id().to_owned()));
        }
        let mut gate = derive_check(&root, &contract.runner, check)?;
        let mut inputs: BTreeMap<_, _> = gate
            .inputs
            .into_iter()
            .map(|input| (input.path.clone(), input))
            .collect();
        for input in &common_inputs {
            inputs.insert(input.path.clone(), input.clone());
        }
        gate.inputs = inputs.into_values().collect();
        declared_inputs += gate.inputs.len();
        generated.push(gate);

        for module_id in check.modules() {
            let Some(module) = manifest
                .modules
                .iter_mut()
                .find(|module| module.id == *module_id)
            else {
                return Err(GateDeriveError::UnknownModule {
                    gate: check.id().to_owned(),
                    module: module_id.clone(),
                });
            };
            module.gates.push(check.id().to_owned());
            module.gates.sort();
            module.gates.dedup();
            attached_modules.insert(module_id.clone());
        }
    }

    manifest.gates.extend(generated);
    manifest.gates.sort_by(|left, right| left.id.cmp(&right.id));
    manifest.validate()?;
    let manifest_toml = toml::to_string_pretty(&manifest)?;
    let summary = DeriveGateSummary {
        source_manifest: manifest_relative,
        contract: contract_relative,
        output: output_relative,
        generated_gates: contract.checks.len(),
        attached_modules: attached_modules.len(),
        declared_inputs,
        checked: options.check,
    };
    Ok(GeneratedGateManifest {
        manifest_toml,
        summary,
    })
}

fn normalize_contract(contract: &mut GateContract) -> Result<(), GateDeriveError> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(GateDeriveError::UnsupportedContractSchema {
            found: contract.schema_version,
            supported: CONTRACT_SCHEMA_VERSION,
        });
    }
    if contract.checks.is_empty() {
        return Err(GateDeriveError::EmptyContract);
    }
    if contract.runner.program.trim().is_empty()
        || contract.runner.program.trim() != contract.runner.program
        || contract.runner.program.contains('\0')
    {
        return Err(GateDeriveError::InvalidRunnerProgram);
    }
    if contract
        .runner
        .args
        .iter()
        .any(|argument| argument.contains('\0'))
    {
        return Err(GateDeriveError::InvalidRunnerArgument);
    }

    let mut ids = BTreeSet::new();
    for check in &mut contract.checks {
        let id = check.id();
        if id.trim().is_empty() || id.trim() != id || !ids.insert(id.to_owned()) {
            return Err(GateDeriveError::InvalidGateId(id.to_owned()));
        }
        normalize_check_paths(check)?;
        normalize_unique(check.id(), check.modules(), "module")?;
        normalize_unique(check.id(), check.targets(), "target")?;
    }
    contract
        .checks
        .sort_by(|left, right| left.id().cmp(right.id()));
    Ok(())
}

fn normalize_unique(
    gate: &str,
    values: &[String],
    kind: &'static str,
) -> Result<(), GateDeriveError> {
    let mut found = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || value.trim() != value || !found.insert(value) {
            return match kind {
                "module" => Err(GateDeriveError::DuplicateModule {
                    gate: gate.to_owned(),
                    module: value.clone(),
                }),
                _ => Err(GateDeriveError::DuplicateTarget {
                    gate: gate.to_owned(),
                    target: value.clone(),
                }),
            };
        }
    }
    Ok(())
}

fn normalize_check_paths(check: &mut GateCheck) -> Result<(), GateDeriveError> {
    match check {
        GateCheck::RustGn {
            cargo_manifest,
            provenance,
            modules,
            targets,
            ..
        } => {
            *cargo_manifest = exact_file_path(cargo_manifest)?;
            *provenance = exact_file_path(provenance)?;
            modules.sort();
            targets.sort();
        }
        GateCheck::CAbi {
            package_root,
            provenance,
            modules,
            targets,
            ..
        }
        | GateCheck::Mojo {
            package_root,
            provenance,
            modules,
            targets,
            ..
        } => {
            *package_root = exact_dir_path(package_root)?;
            *provenance = exact_file_path(provenance)?;
            modules.sort();
            targets.sort();
        }
        GateCheck::Unsafe {
            workspace_root,
            report,
            modules,
            targets,
            ..
        } => {
            *workspace_root = exact_dir_path(workspace_root)?;
            *report = exact_file_path(report)?;
            modules.sort();
            targets.sort();
        }
        GateCheck::Checkout {
            workspace_root,
            contract,
            report,
            modules,
            targets,
            ..
        } => {
            *workspace_root = exact_dir_path(workspace_root)?;
            *contract = exact_file_path(contract)?;
            *report = exact_file_path(report)?;
            modules.sort();
            targets.sort();
        }
        GateCheck::Integration {
            source_root,
            contract,
            modules,
            targets,
            ..
        } => {
            *source_root = exact_dir_path(source_root)?;
            *contract = exact_file_path(contract)?;
            modules.sort();
            targets.sort();
        }
        GateCheck::Coverage {
            manifest,
            source_root,
            export,
            report,
            modules,
            targets,
            ..
        } => {
            *manifest = exact_file_path(manifest)?;
            *source_root = exact_dir_path(source_root)?;
            *export = exact_file_path(export)?;
            *report = exact_file_path(report)?;
            modules.sort();
            targets.sort();
        }
    }
    Ok(())
}

fn derive_check(
    root: &Path,
    runner: &GateRunner,
    check: &GateCheck,
) -> Result<CompatibilityGate, GateDeriveError> {
    let mut inputs = InputSet::new(root);
    let mut args = runner.args.clone();
    match check {
        GateCheck::RustGn {
            cargo_manifest,
            provenance,
            ..
        } => derive_rust_gn(root, cargo_manifest, provenance, &mut args, &mut inputs)?,
        GateCheck::CAbi {
            package_root,
            provenance,
            ..
        } => derive_c_abi(root, package_root, provenance, &mut args, &mut inputs)?,
        GateCheck::Mojo {
            package_root,
            provenance,
            ..
        } => derive_mojo(root, package_root, provenance, &mut args, &mut inputs)?,
        GateCheck::Unsafe {
            workspace_root,
            report,
            ..
        } => derive_unsafe(root, workspace_root, report, &mut args, &mut inputs)?,
        GateCheck::Checkout {
            workspace_root,
            contract,
            report,
            ..
        } => derive_checkout(
            root,
            workspace_root,
            contract,
            report,
            &mut args,
            &mut inputs,
        )?,
        GateCheck::Integration {
            source_root,
            contract,
            ..
        } => derive_integration(root, source_root, contract, &mut args, &mut inputs)?,
        GateCheck::Coverage {
            manifest,
            source_root,
            export,
            report,
            ..
        } => derive_coverage(
            manifest,
            source_root,
            export,
            report,
            &mut args,
            &mut inputs,
        )?,
    }
    Ok(CompatibilityGate {
        id: check.id().to_owned(),
        execution: GateExecution::Direct {
            program: runner.program.clone(),
            args,
        },
        inputs: inputs.finish(),
        targets: check.targets().to_vec(),
    })
}

fn derive_rust_gn(
    root: &Path,
    cargo_manifest: &str,
    provenance_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let provenance_bytes = inputs.add(provenance_path, None)?;
    let provenance: BridgeProvenance = serde_json::from_slice(&provenance_bytes)?;
    check_schema(
        "Rust GN",
        provenance.schema_version,
        BUILD_PROVENANCE_SCHEMA_VERSION,
    )?;
    inputs.add(cargo_manifest, Some(&provenance.cargo_manifest_sha256))?;
    let package_root = parent_path(provenance_path)?;
    let build_gn = join_path(&package_root, "BUILD.gn")?;
    inputs.add(&build_gn, Some(&provenance.build_gn_sha256))?;
    for source in &provenance.sources {
        inputs.add(&join_path(&package_root, source)?, None)?;
    }
    add_nearest_cargo_lock(root, cargo_manifest, inputs)?;

    args.extend([
        "generate-gn".into(),
        cargo_manifest.into(),
        build_gn,
        "--package".into(),
        provenance.package.clone(),
        "--target-name".into(),
        provenance.target_name.clone(),
    ]);
    for dependency in &provenance.dependencies {
        args.push(if dependency.public {
            "--public-dep".into()
        } else {
            "--dep".into()
        });
        args.push(format!("{}={}", dependency.cargo_name, dependency.gn_label));
    }
    append_repeated(args, "--gn-dep", &provenance.additional_deps);
    append_repeated(args, "--gn-public-dep", &provenance.additional_public_deps);
    append_repeated(args, "--visibility", &provenance.visibility);
    append_repeated(args, "--feature", &provenance.features);
    if provenance.no_default_features {
        args.push("--no-default-features".into());
    }
    let crate_dir = parent_path(&provenance.crate_root)?;
    for source in &provenance.sources {
        if !path_is_within(source, &crate_dir) && source != &provenance.crate_root {
            args.extend(["--extra-source".into(), source.clone()]);
        }
    }
    if provenance.allow_unsafe {
        args.push("--allow-unsafe".into());
    }
    if let Some(package_path) = &provenance.gn_package_path {
        args.extend(["--gn-package-path".into(), package_path.clone()]);
    }
    let generated: BTreeSet<_> = provenance.generated_cxx_headers.iter().collect();
    for consumer in provenance
        .consumer
        .iter()
        .chain(provenance.additional_consumers.iter())
    {
        for source in &consumer.sources {
            let path = join_path(&package_root, source)?;
            inputs.add(&path, None)?;
        }
        for header in &consumer.required_headers {
            if generated.contains(header) {
                continue;
            }
            inputs.add(header, None)?;
        }
    }
    if let Some(contract) = &provenance.consumer_contract {
        let contract_path = join_path(&package_root, &contract.path)?;
        inputs.add(&contract_path, Some(&contract.sha256))?;
        args.extend(["--consumer-contract".into(), contract_path]);
    } else if let Some(consumer) = &provenance.consumer {
        args.extend(["--consumer-target".into(), consumer.target_name.clone()]);
        for source in &consumer.sources {
            args.extend(["--consumer-source".into(), source.clone()]);
        }
        for binding in &consumer.cxx_bindings {
            args.extend(["--consumer-cxx-binding".into(), binding.clone()]);
        }
        for header in &consumer.required_headers {
            if generated.contains(header) {
                continue;
            }
            let relative = strip_package_path(header, &package_root)
                .ok_or_else(|| GateDeriveError::HeaderOutsidePackage(header.clone()))?;
            args.extend(["--consumer-header".into(), relative]);
        }
        let automatic = format!(":{}", provenance.target_name);
        for dependency in &consumer.deps {
            if dependency != &automatic {
                args.extend(["--consumer-dep".into(), dependency.clone()]);
            }
        }
        append_repeated(args, "--consumer-public-dep", &consumer.public_deps);
        append_repeated(args, "--consumer-visibility", &consumer.visibility);
    }
    args.push("--check".into());
    Ok(())
}

fn derive_c_abi(
    _root: &Path,
    package_root: &str,
    provenance_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let provenance_bytes = inputs.add(provenance_path, None)?;
    let provenance: CAbiProvenance = serde_json::from_slice(&provenance_bytes)?;
    check_schema(
        "C ABI",
        provenance.schema_version,
        C_ABI_PROVENANCE_SCHEMA_VERSION,
    )?;
    let contract = join_path(package_root, &provenance.contract_path)?;
    let header = join_path(package_root, &provenance.header_path)?;
    inputs.add(&contract, Some(&provenance.contract_sha256))?;
    inputs.add(&header, Some(&provenance.header_sha256))?;
    for source in &provenance.sources {
        inputs.add(
            &join_path(package_root, &source.source)?,
            Some(&source.sha256),
        )?;
    }

    args.extend([
        "generate-c-abi".into(),
        display_dir(package_root),
        contract,
        header,
    ]);
    for source in &provenance.sources {
        if !path_is_within(&source.source, "src") {
            args.extend(["--extra-source".into(), source.source.clone()]);
        }
    }
    args.push("--check".into());
    Ok(())
}

fn derive_mojo(
    _root: &Path,
    package_root: &str,
    provenance_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let provenance_bytes = inputs.add(provenance_path, None)?;
    let provenance: MojoProvenance = serde_json::from_slice(&provenance_bytes)?;
    check_schema(
        "Mojo",
        provenance.schema_version,
        MOJO_PROVENANCE_SCHEMA_VERSION,
    )?;
    let contract = join_path(package_root, &provenance.contract_path)?;
    let build_gn = join_path(package_root, &provenance.build_gn_path)?;
    inputs.add(&contract, Some(&provenance.contract_sha256))?;
    inputs.add(&build_gn, Some(&provenance.build_gn_sha256))?;
    for target in &provenance.targets {
        for source in &target.sources {
            inputs.add(
                &join_path(package_root, &source.source)?,
                Some(&source.sha256),
            )?;
        }
    }
    args.extend([
        "generate-mojo".into(),
        display_dir(package_root),
        contract,
        build_gn,
        "--check".into(),
    ]);
    Ok(())
}

fn derive_unsafe(
    _root: &Path,
    workspace_root: &str,
    report_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let report_bytes = inputs.add(report_path, None)?;
    let report: UnsafeAuditReport = serde_json::from_slice(&report_bytes)?;
    check_schema(
        "unsafe audit",
        report.schema_version,
        UNSAFE_REPORT_SCHEMA_VERSION,
    )?;
    let cargo_manifest = join_path(workspace_root, &report.cargo_manifest_path)?;
    let policy = join_path(workspace_root, &report.policy_path)?;
    inputs.add(&cargo_manifest, Some(&report.cargo_manifest_sha256))?;
    inputs.add(&policy, Some(&report.policy_sha256))?;
    if let (Some(path), Some(digest)) = (&report.cargo_lock_path, &report.cargo_lock_sha256) {
        inputs.add(&join_path(workspace_root, path)?, Some(digest))?;
    }
    for package in &report.packages {
        inputs.add(
            &join_path(workspace_root, &package.manifest_path)?,
            Some(&package.manifest_sha256),
        )?;
        let package_root = parent_path(&package.manifest_path)?;
        for source in &package.sources {
            inputs.add(
                &join_path(workspace_root, &join_path(&package_root, &source.source)?)?,
                Some(&source.sha256),
            )?;
        }
    }
    args.extend([
        "audit-unsafe".into(),
        cargo_manifest,
        policy,
        report_path.into(),
        "--check".into(),
    ]);
    Ok(())
}

fn derive_checkout(
    _root: &Path,
    workspace_root: &str,
    contract_path: &str,
    report_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let contract_bytes = inputs.add(contract_path, None)?;
    let contract: CheckoutContract = serde_json::from_slice(&contract_bytes)?;
    check_schema(
        "checkout contract",
        contract.schema_version,
        CHECKOUT_CONTRACT_SCHEMA_VERSION,
    )?;

    let report_bytes = inputs.add(report_path, None)?;
    let report: CheckoutReport = serde_json::from_slice(&report_bytes)?;
    check_schema(
        "checkout report",
        report.schema_version,
        CHECKOUT_REPORT_SCHEMA_VERSION,
    )?;
    let actual_contract_digest = sha256_hex(&contract_bytes);
    if report.contract_sha256 != actual_contract_digest {
        return Err(GateDeriveError::DigestMismatch {
            path: contract_path.to_owned(),
            expected: report.contract_sha256,
            actual: actual_contract_digest,
        });
    }

    for metadata in &report.metadata_files {
        let path = join_path(workspace_root, &metadata.path)?;
        let expected = (metadata.mode == MetadataMode::Raw).then_some(metadata.sha256.as_str());
        inputs.add(&path, expected)?;
    }
    for output in &report.gn_outputs {
        inputs.add(
            &join_path(workspace_root, &output.args.path)?,
            Some(&output.args.sha256),
        )?;
        inputs.add(
            &join_path(workspace_root, &output.build.path)?,
            Some(&output.build.sha256),
        )?;
        inputs.add(&join_path(workspace_root, &output.project_file)?, None)?;
    }

    args.extend([
        "audit-checkout".into(),
        display_dir(workspace_root),
        contract_path.into(),
        report_path.into(),
        "--check".into(),
    ]);
    Ok(())
}

fn derive_integration(
    _root: &Path,
    source_root: &str,
    contract_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let contract_bytes = inputs.add(contract_path, None)?;
    let contract: IntegrationContract = serde_json::from_slice(&contract_bytes)?;
    check_schema(
        "GN integration contract",
        contract.schema_version,
        INTEGRATION_CONTRACT_SCHEMA_VERSION,
    )?;

    for source in &contract.source_inputs {
        inputs.add(&join_path(source_root, source)?, None)?;
    }

    let package_root = exact_dir_path(&contract.package_root)?;
    let build_bytes = inputs.add(&contract.build_provenance, None)?;
    let build: BridgeProvenance = serde_json::from_slice(&build_bytes)?;
    check_schema(
        "Rust GN build",
        build.schema_version,
        BUILD_PROVENANCE_SCHEMA_VERSION,
    )?;
    inputs.add(
        &join_path(&package_root, "BUILD.gn")?,
        Some(&build.build_gn_sha256),
    )?;
    for source in &build.sources {
        inputs.add(&join_path(&package_root, source)?, None)?;
    }
    if let Some(consumer) = &build.consumer {
        for source in &consumer.sources {
            inputs.add(&join_path(&package_root, source)?, None)?;
        }
        let destination_prefix = format!("{}/", contract.destination);
        for header in &consumer.required_headers {
            let relative = header
                .strip_prefix(&destination_prefix)
                .ok_or_else(|| GateDeriveError::HeaderOutsidePackage(header.clone()))?;
            inputs.add(&join_path(&package_root, relative)?, None)?;
        }
    }

    let c_abi_bytes = inputs.add(&contract.c_abi_provenance, None)?;
    let c_abi: CAbiProvenance = serde_json::from_slice(&c_abi_bytes)?;
    check_schema(
        "C ABI",
        c_abi.schema_version,
        C_ABI_PROVENANCE_SCHEMA_VERSION,
    )?;
    inputs.add(
        &join_path(&package_root, &c_abi.contract_path)?,
        Some(&c_abi.contract_sha256),
    )?;
    inputs.add(
        &join_path(&package_root, &c_abi.header_path)?,
        Some(&c_abi.header_sha256),
    )?;
    for source in &c_abi.sources {
        inputs.add(
            &join_path(&package_root, &source.source)?,
            Some(&source.sha256),
        )?;
    }
    inputs.add(&join_path(&package_root, &contract.endpoint_source)?, None)?;

    args.extend([
        "run-gn-integration".into(),
        ".".into(),
        display_dir(source_root),
        contract_path.into(),
    ]);
    Ok(())
}

fn derive_coverage(
    manifest_path: &str,
    source_root: &str,
    export_path: &str,
    report_path: &str,
    args: &mut Vec<String>,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let manifest_bytes = inputs.add(manifest_path, None)?;
    let manifest: Manifest = toml::from_str(&String::from_utf8_lossy(&manifest_bytes))?;
    manifest.validate()?;

    let report_bytes = inputs.add(report_path, None)?;
    let report: CoverageReport = serde_json::from_slice(&report_bytes)?;
    check_schema(
        "coverage report",
        report.schema_version,
        COVERAGE_REPORT_SCHEMA_VERSION,
    )?;
    verify_report_manifest(&report, &manifest, &manifest_bytes).map_err(|error| {
        GateDeriveError::InvalidCoverageEvidence(format!(
            "coverage report `{report_path}` does not match `{manifest_path}`: {error}"
        ))
    })?;
    inputs.add(export_path, Some(&report.llvm_export_sha256))?;
    for module in &manifest.modules {
        for source in &module.sources {
            inputs.add(&join_path(source_root, source)?, None)?;
        }
    }

    args.extend([
        "summarize-coverage".into(),
        manifest_path.into(),
        display_dir(source_root),
        export_path.into(),
        report_path.into(),
        "--check".into(),
    ]);
    Ok(())
}

fn check_schema(kind: &'static str, found: u32, supported: u32) -> Result<(), GateDeriveError> {
    if found != supported {
        return Err(GateDeriveError::UnsupportedProvenanceSchema {
            kind,
            found,
            supported,
        });
    }
    Ok(())
}

fn append_repeated(args: &mut Vec<String>, flag: &str, values: &[String]) {
    for value in values {
        args.extend([flag.to_owned(), value.clone()]);
    }
}

struct InputSet<'a> {
    root: &'a Path,
    inputs: BTreeMap<String, GateInput>,
}

impl<'a> InputSet<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            inputs: BTreeMap::new(),
        }
    }

    fn add(&mut self, relative: &str, expected: Option<&str>) -> Result<Vec<u8>, GateDeriveError> {
        let relative = exact_file_path(relative)?;
        let path = self.root.join(&relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| GateDeriveError::MissingFile(relative.clone()))?;
        if metadata.file_type().is_symlink() {
            return Err(GateDeriveError::InputSymlink(relative));
        }
        let canonical = path
            .canonicalize()
            .map_err(|_| GateDeriveError::MissingFile(relative.clone()))?;
        if !canonical.starts_with(self.root) || !canonical.is_file() {
            return Err(GateDeriveError::PathOutsideRepo(relative));
        }
        if !metadata.is_file() {
            return Err(GateDeriveError::MissingFile(relative));
        }
        let bytes = read_file(&canonical)?;
        let actual = sha256_hex(&bytes);
        if let Some(expected) = expected {
            if actual != expected {
                return Err(GateDeriveError::DigestMismatch {
                    path: relative,
                    expected: expected.to_owned(),
                    actual,
                });
            }
        }
        self.inputs.insert(
            relative.clone(),
            GateInput {
                path: relative,
                sha256: actual,
            },
        );
        Ok(bytes)
    }

    fn finish(self) -> Vec<GateInput> {
        self.inputs.into_values().collect()
    }
}

fn add_nearest_cargo_lock(
    root: &Path,
    manifest: &str,
    inputs: &mut InputSet<'_>,
) -> Result<(), GateDeriveError> {
    let mut directory = Path::new(manifest).parent().unwrap_or(Path::new(""));
    loop {
        let candidate = if directory.as_os_str().is_empty() {
            "Cargo.lock".to_owned()
        } else {
            format!(
                "{}/Cargo.lock",
                directory.to_string_lossy().replace('\\', "/")
            )
        };
        if root.join(&candidate).is_file() {
            inputs.add(&candidate, None)?;
            return Ok(());
        }
        let Some(parent) = directory.parent() else {
            return Ok(());
        };
        if parent == directory {
            return Ok(());
        }
        directory = parent;
    }
}

fn output_path(options: &DeriveGateOptions) -> Result<(PathBuf, PathBuf, String), GateDeriveError> {
    let root = canonical_root(&options.repo_root)?;
    let relative = relative_output_path(&root, &options.output)?;
    if Path::new(&relative)
        .extension()
        .and_then(|value| value.to_str())
        != Some("toml")
    {
        return Err(GateDeriveError::InvalidOutput(
            options.output.display().to_string(),
        ));
    }
    let path = root.join(&relative);
    let parent = path.parent().unwrap_or(&root);
    if !parent.is_dir() {
        return Err(GateDeriveError::InvalidOutput(path.display().to_string()));
    }
    Ok((root, path, relative))
}

fn canonical_root(path: &Path) -> Result<PathBuf, GateDeriveError> {
    path.canonicalize()
        .ok()
        .filter(|path| path.is_dir())
        .ok_or_else(|| GateDeriveError::InvalidRepoRoot(path.display().to_string()))
}

fn existing_repo_file(root: &Path, path: &Path) -> Result<(PathBuf, String), GateDeriveError> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|_| GateDeriveError::MissingFile(path.display().to_string()))?;
    if !canonical.is_file() {
        return Err(GateDeriveError::MissingFile(path.display().to_string()));
    }
    let relative = canonical
        .strip_prefix(root)
        .map_err(|_| GateDeriveError::PathOutsideRepo(path.display().to_string()))?;
    let relative = relative.to_string_lossy().replace('\\', "/");
    Ok((canonical, exact_file_path(&relative)?))
}

fn relative_output_path(root: &Path, path: &Path) -> Result<String, GateDeriveError> {
    if path.is_absolute() {
        let parent = path
            .parent()
            .ok_or_else(|| GateDeriveError::InvalidOutput(path.display().to_string()))?;
        let parent = parent
            .canonicalize()
            .map_err(|_| GateDeriveError::InvalidOutput(path.display().to_string()))?;
        let filename = path
            .file_name()
            .ok_or_else(|| GateDeriveError::InvalidOutput(path.display().to_string()))?;
        let candidate = parent.join(filename);
        let relative = candidate
            .strip_prefix(root)
            .map_err(|_| GateDeriveError::PathOutsideRepo(path.display().to_string()))?;
        return exact_file_path(&relative.to_string_lossy().replace('\\', "/"));
    }
    exact_file_path(&path.to_string_lossy().replace('\\', "/"))
}

fn exact_file_path(value: &str) -> Result<String, GateDeriveError> {
    let normalized = normalize_repo_relative_path(value)
        .ok_or_else(|| GateDeriveError::InvalidRelativePath(value.to_owned()))?;
    if normalized != value.replace('\\', "/") {
        return Err(GateDeriveError::InvalidRelativePath(value.to_owned()));
    }
    Ok(normalized)
}

fn exact_dir_path(value: &str) -> Result<String, GateDeriveError> {
    if value == "." || value.is_empty() {
        return Ok(String::new());
    }
    exact_file_path(value)
}

fn join_path(base: &str, child: &str) -> Result<String, GateDeriveError> {
    let child = exact_file_path(child)?;
    if base.is_empty() {
        return Ok(child);
    }
    exact_file_path(&format!("{base}/{child}"))
}

fn parent_path(value: &str) -> Result<String, GateDeriveError> {
    let value = exact_file_path(value)?;
    Ok(Path::new(&value)
        .parent()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default())
}

fn display_dir(value: &str) -> String {
    if value.is_empty() {
        ".".to_owned()
    } else {
        value.to_owned()
    }
}

fn path_is_within(path: &str, directory: &str) -> bool {
    directory.is_empty()
        || path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn strip_package_path(path: &str, package_root: &str) -> Option<String> {
    if package_root.is_empty() {
        return Some(path.to_owned());
    }
    path.strip_prefix(package_root)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .map(str::to_owned)
}

fn read_file(path: &Path) -> Result<Vec<u8>, GateDeriveError> {
    fs::read(path).map_err(|source| GateDeriveError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chromifer_coverage::{CoverageTotals, FileCoverage, LineCoverage, ModuleCoverage};
    use chromifer_manifest::{MigrationState, Module, Project, Target};

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-gates-{}-{id}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            Self { root }
        }

        fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn base_manifest(tree: &TempTree) {
        let manifest = Manifest {
            schema_version: 1,
            project: Project {
                name: "fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![Target {
                id: "linux".into(),
                description: "Linux".into(),
                required: true,
            }],
            gates: vec![],
            modules: vec![Module {
                id: "service".into(),
                path: "service".into(),
                owner: "owner".into(),
                ownership: None,
                source_label: None,
                source_type: None,
                sources: vec![],
                state: MigrationState::LegacyCpp,
                gates: vec![],
                reviews: vec![],
                dependencies: vec![],
            }],
        };
        tree.write("base.toml", toml::to_string_pretty(&manifest).unwrap());
    }

    fn options(tree: &TempTree) -> DeriveGateOptions {
        DeriveGateOptions {
            repo_root: tree.root.clone(),
            manifest: PathBuf::from("base.toml"),
            contract: PathBuf::from("gates.json"),
            output: PathBuf::from("generated.toml"),
            force: false,
            check: false,
        }
    }

    fn c_abi_fixture(tree: &TempTree) {
        tree.write("bridge/src/lib.rs", "pub fn value() {}\n");
        tree.write("bridge/c-abi.json", "{}\n");
        tree.write("bridge/include/api.h", "int value(void);\n");
        let provenance = CAbiProvenance {
            schema_version: 1,
            contract_sha256: sha256_hex(b"{}\n"),
            contract_path: "c-abi.json".into(),
            header_sha256: sha256_hex(b"int value(void);\n"),
            header_path: "include/api.h".into(),
            header_guard: "API_H_".into(),
            sources: vec![chromifer_cabi::SourceDigest {
                source: "src/lib.rs".into(),
                sha256: sha256_hex(b"pub fn value() {}\n"),
            }],
            symbols: vec![],
        };
        tree.write(
            "bridge/include/api.h.chromifer.json",
            format!("{}\n", serde_json::to_string_pretty(&provenance).unwrap()),
        );
    }

    #[test]
    fn derives_direct_gate_and_attaches_it_to_modules() {
        let tree = TempTree::new();
        base_manifest(&tree);
        c_abi_fixture(&tree);
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "runner": {"program": "cargo", "args": ["run", "--", "chromifer"]},
  "checks": [{
    "kind": "c_abi",
    "id": "c-abi-current",
    "package_root": "bridge",
    "provenance": "bridge/include/api.h.chromifer.json",
    "modules": ["service"],
    "targets": ["linux"]
  }]
}
"#,
        );

        let generated = derive_and_write(&options(&tree)).unwrap();
        let manifest: Manifest = toml::from_str(&generated.manifest_toml).unwrap();
        assert_eq!(manifest.modules[0].gates, vec!["c-abi-current"]);
        assert_eq!(manifest.gates.len(), 1);
        let GateExecution::Direct { program, args } = &manifest.gates[0].execution else {
            panic!("expected direct gate");
        };
        assert_eq!(program, "cargo");
        assert_eq!(&args[..3], ["run", "--", "chromifer"]);
        assert_eq!(args[3], "generate-c-abi");
        assert!(args.ends_with(&["--check".into()]));
        assert!(
            manifest.gates[0]
                .inputs
                .iter()
                .any(|input| input.path == "bridge/src/lib.rs")
        );
        assert_eq!(generated.summary.generated_gates, 1);
        assert!(tree.root.join("generated.toml").is_file());
    }

    #[test]
    fn rejects_provenance_digest_drift_and_unknown_modules() {
        let tree = TempTree::new();
        base_manifest(&tree);
        c_abi_fixture(&tree);
        tree.write("bridge/include/api.h", "changed\n");
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "c_abi",
    "id": "c-abi-current",
    "package_root": "bridge",
    "provenance": "bridge/include/api.h.chromifer.json",
    "modules": ["missing"]
  }]
}
"#,
        );
        assert!(matches!(
            derive_gate_manifest(&options(&tree)),
            Err(GateDeriveError::DigestMismatch { .. })
        ));

        tree.write("bridge/include/api.h", "int value(void);\n");
        assert!(matches!(
            derive_gate_manifest(&options(&tree)),
            Err(GateDeriveError::UnknownModule { module, .. }) if module == "missing"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_provenance_inputs() {
        use std::os::unix::fs::symlink;

        let tree = TempTree::new();
        let outside = TempTree::new();
        base_manifest(&tree);
        c_abi_fixture(&tree);
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "c_abi",
    "id": "c-abi-current",
    "package_root": "bridge",
    "provenance": "bridge/include/api.h.chromifer.json"
  }]
}
"#,
        );
        outside.write("api.h", "int value(void);\n");
        fs::remove_file(tree.root.join("bridge/include/api.h")).unwrap();
        symlink(
            outside.root.join("api.h"),
            tree.root.join("bridge/include/api.h"),
        )
        .unwrap();

        assert!(matches!(
            derive_gate_manifest(&options(&tree)),
            Err(GateDeriveError::InputSymlink(path))
                if path == "bridge/include/api.h"
        ));
    }

    #[test]
    fn derives_checkout_gate_from_lock_report() {
        let tree = TempTree::new();
        base_manifest(&tree);
        tree.write("workspace/.gclient", "solutions = []\n");
        tree.write("workspace/.gclient_entries", "entries = {}\n");
        tree.write("workspace/src/out/Default/args.gn", "is_debug = false\n");
        tree.write("workspace/src/out/Default/build.ninja", "rule noop\n");
        tree.write(
            "workspace/src/out/Default/project.json",
            "{\"build_settings\":{},\"targets\":{}}\n",
        );
        let checkout_contract = br#"{
  "schema_version": 1,
  "source_dir": "src",
  "revision": "0000000000000000000000000000000000000000",
  "require_clean": true,
  "metadata_files": [
    {"path": ".gclient"},
    {"path": ".gclient_entries", "mode": "workspace_text"}
  ],
  "gn_outputs": [{
    "id": "linux",
    "directory": "src/out/Default",
    "required_targets": ["//app:browser"]
  }]
}
"#;
        tree.write("workspace/checkout.json", checkout_contract);
        let report = serde_json::json!({
            "schema_version": 1,
            "contract_sha256": sha256_hex(checkout_contract),
            "source": {
                "source_dir": "src",
                "revision": "0000000000000000000000000000000000000000",
                "clean": true,
                "status_sha256": sha256_hex(b""),
                "status_entries": 0,
                "submodule_status_sha256": sha256_hex(b"")
            },
            "metadata_files": [
                {
                    "path": ".gclient",
                    "mode": "raw",
                    "sha256": sha256_hex(b"solutions = []\n"),
                    "bytes": 15
                },
                {
                    "path": ".gclient_entries",
                    "mode": "workspace_text",
                    "sha256": sha256_hex(b"entries = {}\n"),
                    "bytes": 13
                }
            ],
            "gn_outputs": [{
                "id": "linux",
                "directory": "src/out/Default",
                "args": {
                    "path": "src/out/Default/args.gn",
                    "mode": "raw",
                    "sha256": sha256_hex(b"is_debug = false\n"),
                    "bytes": 17
                },
                "build": {
                    "path": "src/out/Default/build.ninja",
                    "mode": "raw",
                    "sha256": sha256_hex(b"rule noop\n"),
                    "bytes": 10
                },
                "project_file": "src/out/Default/project.json",
                "project_semantic_sha256": sha256_hex(b"semantic"),
                "project_semantic_bytes": 8,
                "build_dir": "//out/Default/",
                "default_toolchain": "//build/toolchain:default",
                "target_count": 1,
                "required_targets": []
            }]
        });
        tree.write(
            "workspace/checkout-lock.json",
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
        );
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "checkout",
    "id": "checkout-current",
    "workspace_root": "workspace",
    "contract": "workspace/checkout.json",
    "report": "workspace/checkout-lock.json",
    "modules": ["service"],
    "targets": ["linux"]
  }]
}
"#,
        );

        let generated = derive_gate_manifest(&options(&tree)).unwrap();
        let manifest: Manifest = toml::from_str(&generated.manifest_toml).unwrap();
        let gate = &manifest.gates[0];
        let GateExecution::Direct { program, args } = &gate.execution else {
            panic!("expected direct checkout gate");
        };
        assert_eq!(program, "chromifer");
        assert_eq!(
            args,
            &[
                "audit-checkout",
                "workspace",
                "workspace/checkout.json",
                "workspace/checkout-lock.json",
                "--check"
            ]
        );
        let inputs: BTreeSet<_> = gate
            .inputs
            .iter()
            .map(|input| input.path.as_str())
            .collect();
        for expected in [
            "workspace/.gclient",
            "workspace/.gclient_entries",
            "workspace/checkout-lock.json",
            "workspace/checkout.json",
            "workspace/src/out/Default/args.gn",
            "workspace/src/out/Default/build.ninja",
            "workspace/src/out/Default/project.json",
        ] {
            assert!(
                inputs.contains(expected),
                "missing checkout input {expected}"
            );
        }
        assert_eq!(manifest.modules[0].gates, vec!["checkout-current"]);
    }

    #[test]
    fn derives_coverage_gate_with_export_and_source_inputs() {
        let tree = TempTree::new();
        base_manifest(&tree);
        tree.write(
            "coverage/source/service/value.cc",
            "int Value() { return 1; }\n",
        );
        let coverage_manifest = r#"schema_version = 1

[project]
name = "coverage"
upstream = "fixture"
baseline = "fixture"

[[modules]]
id = "covered"
path = "service"
owner = "owner"
sources = ["service/value.cc"]
state = "legacy_cpp"
"#;
        tree.write("coverage/manifest.toml", coverage_manifest);
        let export = br#"{"data":[],"type":"llvm.coverage.json.export","version":"2.0.1"}
"#;
        tree.write("coverage/export.json", export);
        let report = CoverageReport {
            schema_version: 1,
            manifest_sha256: sha256_hex(coverage_manifest.as_bytes()),
            baseline: "fixture".into(),
            llvm_export_sha256: sha256_hex(export),
            llvm_export_version: "2.0.1".into(),
            files: vec![FileCoverage {
                path: "service/value.cc".into(),
                lines: LineCoverage {
                    count: 1,
                    covered: 1,
                    basis_points: 10_000,
                },
            }],
            modules: vec![ModuleCoverage {
                module: "covered".into(),
                total_sources: 1,
                measured_sources: 1,
                missing_sources: vec![],
                lines: LineCoverage {
                    count: 1,
                    covered: 1,
                    basis_points: 10_000,
                },
            }],
            totals: CoverageTotals {
                manifest_sources: 1,
                measured_sources: 1,
                missing_sources: vec![],
                lines: LineCoverage {
                    count: 1,
                    covered: 1,
                    basis_points: 10_000,
                },
            },
        };
        tree.write(
            "coverage/report.json",
            format!("{}\n", serde_json::to_string_pretty(&report).unwrap()),
        );
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "coverage",
    "id": "coverage-current",
    "manifest": "coverage/manifest.toml",
    "source_root": "coverage/source",
    "export": "coverage/export.json",
    "report": "coverage/report.json",
    "modules": ["service"],
    "targets": ["linux"]
  }]
}
"#,
        );

        let generated = derive_gate_manifest(&options(&tree)).unwrap();
        let manifest: Manifest = toml::from_str(&generated.manifest_toml).unwrap();
        let gate = &manifest.gates[0];
        let GateExecution::Direct { args, .. } = &gate.execution else {
            panic!("expected direct coverage gate");
        };
        assert_eq!(
            args,
            &[
                "summarize-coverage",
                "coverage/manifest.toml",
                "coverage/source",
                "coverage/export.json",
                "coverage/report.json",
                "--check"
            ]
        );
        let inputs: BTreeSet<_> = gate
            .inputs
            .iter()
            .map(|input| input.path.as_str())
            .collect();
        for expected in [
            "coverage/manifest.toml",
            "coverage/export.json",
            "coverage/report.json",
            "coverage/source/service/value.cc",
        ] {
            assert!(
                inputs.contains(expected),
                "missing coverage input {expected}"
            );
        }
        assert_eq!(manifest.modules[0].gates, vec!["coverage-current"]);
    }

    #[test]
    fn derives_gn_integration_gate_with_complete_inputs() {
        let tree = TempTree::new();
        base_manifest(&tree);
        tree.write("fixture/.gn", "buildconfig = \"//build/BUILDCONFIG.gn\"\n");
        tree.write("fixture/BUILD.gn", "group(\"default\") {}\n");
        tree.write("bridge/BUILD.gn", "group(\"bridge\") {}\n");
        tree.write("bridge/src/lib.rs", "pub fn value() {}\n");
        tree.write("bridge/consumer/smoke.cc", "int smoke() { return 0; }\n");
        tree.write("bridge/consumer/main.cc", "int main() { return 0; }\n");
        tree.write("bridge/include/api.h", "int value(void);\n");
        tree.write("bridge/c-abi.json", "{}\n");

        let build = serde_json::json!({
            "schema_version": 4,
            "package": "bridge",
            "version": "0.1.0",
            "cargo_manifest_sha256": sha256_hex(b""),
            "target_name": "bridge",
            "crate_root": "src/lib.rs",
            "edition": "2024",
            "sources": ["src/lib.rs"],
            "cxx_bindings": [],
            "gn_package_path": "//bridge",
            "generated_cxx_headers": [],
            "features": [],
            "no_default_features": false,
            "dependencies": [],
            "additional_deps": [],
            "additional_public_deps": [],
            "visibility": [],
            "allow_unsafe": true,
            "consumer": {
                "target_name": "consumer",
                "sources": ["consumer/smoke.cc"],
                "required_headers": ["bridge/include/api.h"],
                "deps": [":bridge"],
                "public_deps": [],
                "visibility": ["//bridge:*"],
                "header_includes": []
            },
            "build_gn_sha256": sha256_hex(b"group(\"bridge\") {}\n")
        });
        tree.write(
            "bridge/chromifer-build.json",
            format!("{}\n", serde_json::to_string_pretty(&build).unwrap()),
        );
        let c_abi = serde_json::json!({
            "schema_version": 1,
            "contract_sha256": sha256_hex(b"{}\n"),
            "contract_path": "c-abi.json",
            "header_sha256": sha256_hex(b"int value(void);\n"),
            "header_path": "include/api.h",
            "header_guard": "BRIDGE_H_",
            "sources": [{
                "source": "src/lib.rs",
                "sha256": sha256_hex(b"pub fn value() {}\n")
            }],
            "symbols": []
        });
        tree.write(
            "bridge/include/api.h.chromifer.json",
            format!("{}\n", serde_json::to_string_pretty(&c_abi).unwrap()),
        );
        tree.write(
            "integration.json",
            r#"{
  "schema_version": 1,
  "package_root": "bridge",
  "build_provenance": "bridge/chromifer-build.json",
  "c_abi_provenance": "bridge/include/api.h.chromifer.json",
  "destination": "bridge",
  "source_inputs": [".gn", "BUILD.gn"],
  "endpoint_source": "consumer/main.cc",
  "endpoint_target": "endpoint",
  "integration_target": "integration",
  "out_dir": "out/integration",
  "rust_template": "host_adapter",
  "expected_exit_code": 0
}
"#,
        );
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "integration",
    "id": "integration-current",
    "source_root": "fixture",
    "contract": "integration.json",
    "modules": ["service"],
    "targets": ["linux"]
  }]
}
"#,
        );

        let generated = derive_gate_manifest(&options(&tree)).unwrap();
        let manifest: Manifest = toml::from_str(&generated.manifest_toml).unwrap();
        let gate = &manifest.gates[0];
        let GateExecution::Direct { args, .. } = &gate.execution else {
            panic!("expected direct integration gate");
        };
        assert_eq!(
            args,
            &["run-gn-integration", ".", "fixture", "integration.json"]
        );
        let inputs: BTreeSet<_> = gate
            .inputs
            .iter()
            .map(|input| input.path.as_str())
            .collect();
        for expected in [
            "fixture/.gn",
            "fixture/BUILD.gn",
            "integration.json",
            "bridge/BUILD.gn",
            "bridge/chromifer-build.json",
            "bridge/include/api.h.chromifer.json",
            "bridge/c-abi.json",
            "bridge/include/api.h",
            "bridge/src/lib.rs",
            "bridge/consumer/smoke.cc",
            "bridge/consumer/main.cc",
        ] {
            assert!(
                inputs.contains(expected),
                "missing integration input {expected}"
            );
        }
    }

    #[test]
    fn check_mode_detects_generated_manifest_drift() {
        let tree = TempTree::new();
        base_manifest(&tree);
        c_abi_fixture(&tree);
        tree.write(
            "gates.json",
            r#"{
  "schema_version": 1,
  "checks": [{
    "kind": "c_abi",
    "id": "c-abi-current",
    "package_root": "bridge",
    "provenance": "bridge/include/api.h.chromifer.json"
  }]
}
"#,
        );
        derive_and_write(&options(&tree)).unwrap();
        let mut check = options(&tree);
        check.check = true;
        assert!(derive_and_write(&check).is_ok());
        fs::write(tree.root.join("generated.toml"), "changed").unwrap();
        assert!(matches!(
            derive_and_write(&check),
            Err(GateDeriveError::Drift(_))
        ));
    }
}
