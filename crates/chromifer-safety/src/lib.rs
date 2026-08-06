#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chromifer_manifest::normalize_repo_relative_path;
use proc_macro2::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, ExprUnsafe, ForeignItemFn, ForeignItemStatic, ImplItemFn, ItemFn, ItemForeignMod,
    ItemImpl, ItemMacro, ItemMod, ItemStatic, ItemTrait, Macro, TraitItemFn,
};
use thiserror::Error;

const POLICY_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOptions {
    pub cargo: PathBuf,
    pub cargo_manifest: PathBuf,
    pub policy: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAudit {
    pub report_json: String,
    pub summary: AuditSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditSummary {
    pub workspace_packages: usize,
    pub safe_packages: usize,
    pub bridge_packages: usize,
    pub source_files: usize,
    pub crate_roots: usize,
    pub unsafe_occurrences: usize,
    pub lint_allowances: usize,
    pub output: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsafePolicy {
    pub schema_version: u32,
    pub packages: Vec<PackagePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackagePolicy {
    pub package: String,
    pub mode: PackageMode,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageMode {
    Safe,
    Bridge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsafeAuditReport {
    pub schema_version: u32,
    pub cargo_manifest_sha256: String,
    pub cargo_manifest_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_lock_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_lock_path: Option<String>,
    pub policy_sha256: String,
    pub policy_path: String,
    pub packages: Vec<PackageAudit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageAudit {
    pub package: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub mode: PackageMode,
    pub allowed_sources: Vec<String>,
    pub crate_roots: Vec<CrateRootEvidence>,
    pub sources: Vec<SourceEvidence>,
    pub unsafe_occurrences: Vec<UnsafeOccurrence>,
    pub lint_allowances: Vec<LintAllowanceEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CrateRootEvidence {
    pub source: String,
    pub targets: Vec<String>,
    pub unsafe_code_lint: RootLintLevel,
    pub unsafe_op_in_unsafe_fn_lint: RootLintLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootLintLevel {
    Forbid,
    Deny,
    Warn,
    Allow,
    Expect,
    Missing,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceEvidence {
    pub source: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnsafeOccurrence {
    pub source: String,
    pub line: usize,
    pub column: usize,
    pub kind: UnsafeKind,
    pub context: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowance_context: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeKind {
    Function,
    Block,
    Impl,
    Trait,
    ExternBlock,
    MutableStatic,
    MacroToken,
    Attribute,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LintAllowanceEvidence {
    pub source: String,
    pub line: usize,
    pub column: usize,
    pub context: String,
    pub used: bool,
}

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("Cargo manifest `{0}` does not exist")]
    MissingCargoManifest(String),
    #[error("failed to run Cargo metadata with `{cargo}`: {source}")]
    RunCargo {
        cargo: String,
        #[source]
        source: std::io::Error,
    },
    #[error("Cargo metadata failed with status {status}: {stderr}")]
    CargoMetadataFailed { status: String, stderr: String },
    #[error("failed to decode Cargo metadata: {0}")]
    DecodeMetadata(#[from] serde_json::Error),
    #[error("workspace root `{0}` is not an accessible directory")]
    InvalidWorkspaceRoot(String),
    #[error("policy `{0}` must be a JSON file inside the Cargo workspace")]
    InvalidPolicyPath(String),
    #[error("output `{0}` must be a JSON file inside an existing workspace directory")]
    InvalidOutputPath(String),
    #[error("unsupported unsafe policy schema version {found}; supported version is {supported}")]
    UnsupportedPolicySchema { found: u32, supported: u32 },
    #[error("unsafe policy contains no packages")]
    EmptyPolicy,
    #[error("unsafe policy contains duplicate package `{0}`")]
    DuplicatePolicyPackage(String),
    #[error("Cargo workspace contains multiple packages named `{0}`")]
    DuplicateWorkspacePackage(String),
    #[error("workspace package `{0}` is missing from the unsafe policy")]
    MissingPackagePolicy(String),
    #[error("unsafe policy names package `{0}` that is absent from the Cargo workspace")]
    UnknownPolicyPackage(String),
    #[error("safe package `{package}` may not declare allowed unsafe source `{source_path}`")]
    SafePackageAllowance {
        package: String,
        source_path: String,
    },
    #[error("bridge package `{0}` must list at least one allowed unsafe source")]
    EmptyBridgeAllowance(String),
    #[error("package `{package}` has invalid allowed source path `{source_path}`")]
    InvalidAllowedSource {
        package: String,
        source_path: String,
    },
    #[error("package `{package}` allowed source `{source_path}` does not exist")]
    MissingAllowedSource {
        package: String,
        source_path: String,
    },
    #[error("package `{package}` source `{source_path}` is outside its package root")]
    SourceOutsidePackage {
        package: String,
        source_path: String,
    },
    #[error(
        "Rust source inventory contains symbolic link `{0}`; symlinked code cannot be audited deterministically"
    )]
    UnsupportedSourceSymlink(String),
    #[error(
        "package `{package}` uses include! at {source_path}:{line}; injected Rust code must be materialized as an audited source file"
    )]
    UnsupportedCodeInclude {
        package: String,
        source_path: String,
        line: usize,
    },
    #[error("failed to inspect source directory `{path}`: {source}")]
    ReadDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse Rust source `{path}`: {source}")]
    ParseRust {
        path: String,
        #[source]
        source: syn::Error,
    },
    #[error(
        "crate root `{source_path}` in safe package `{package}` must contain exactly one crate-level forbid(unsafe_code); found {found:?}"
    )]
    UnsafeSafeRoot {
        package: String,
        source_path: String,
        found: RootLintLevel,
    },
    #[error(
        "crate root `{source_path}` in bridge package `{package}` must use deny(unsafe_code) or forbid(unsafe_code); found {found:?}"
    )]
    UnsafeBridgeRoot {
        package: String,
        source_path: String,
        found: RootLintLevel,
    },
    #[error(
        "crate root `{source_path}` in bridge package `{package}` must use deny(unsafe_op_in_unsafe_fn) or forbid(unsafe_op_in_unsafe_fn); found {found:?}"
    )]
    UnsafeBridgeOperationRoot {
        package: String,
        source_path: String,
        found: RootLintLevel,
    },
    #[error("bridge package `{0}` contains unsafe syntax but no crate root uses deny(unsafe_code)")]
    MissingBridgeDenyRoot(String),
    #[error("safe package `{package}` contains unsafe {kind:?} at {source_path}:{line}")]
    UnsafeInSafePackage {
        package: String,
        source_path: String,
        line: usize,
        kind: UnsafeKind,
    },
    #[error(
        "bridge package `{package}` contains unsafe {kind:?} in unlisted source `{source_path}` at line {line}"
    )]
    UnsafeOutsideAllowedSource {
        package: String,
        source_path: String,
        line: usize,
        kind: UnsafeKind,
    },
    #[error(
        "bridge package `{package}` contains unsafe {kind:?} at {source_path}:{line} without a local allow(unsafe_code) scope"
    )]
    UnscopedBridgeUnsafe {
        package: String,
        source_path: String,
        line: usize,
        kind: UnsafeKind,
    },
    #[error("safe package `{package}` contains allow(unsafe_code) at {source_path}:{line}")]
    UnsafeAllowanceInSafePackage {
        package: String,
        source_path: String,
        line: usize,
    },
    #[error(
        "bridge package `{package}` contains allow(unsafe_code) in unlisted source `{source_path}` at line {line}"
    )]
    AllowanceOutsideAllowedSource {
        package: String,
        source_path: String,
        line: usize,
    },
    #[error(
        "bridge package `{package}` contains unused allow(unsafe_code) at {source_path}:{line}"
    )]
    StaleLintAllowance {
        package: String,
        source_path: String,
        line: usize,
    },
    #[error(
        "bridge package `{package}` allowed source `{source_path}` contains no unsafe occurrence"
    )]
    StaleAllowedSource {
        package: String,
        source_path: String,
    },
    #[error("bridge package `{0}` contains no unsafe occurrence and should use safe mode")]
    EmptyBridgePackage(String),
    #[error("generated file `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("generated file `{0}` is missing or differs from the unsafe audit")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    workspace_root: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    manifest_path: PathBuf,
    targets: Vec<CargoTarget>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    src_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LintDirective {
    Forbid,
    Deny,
    Warn,
    Allow,
    Expect,
}

#[derive(Debug, Clone)]
struct AllowanceState {
    evidence: LintAllowanceEvidence,
}

#[derive(Debug, Clone)]
struct ScopeState {
    active_allowances: Vec<usize>,
    forbid_active: bool,
}

struct UnsafeScanner<'a> {
    source: &'a str,
    occurrences: Vec<UnsafeOccurrence>,
    allowances: Vec<AllowanceState>,
    allowance_by_location: BTreeMap<(usize, usize), usize>,
    active_allowances: Vec<usize>,
    forbid_active: bool,
    contexts: Vec<String>,
    code_includes: Vec<CodeInclude>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodeInclude {
    line: usize,
}

pub fn audit_and_write(options: &AuditOptions) -> Result<GeneratedAudit, SafetyError> {
    let generated = audit_workspace(options)?;
    if options.check {
        check_file(&options.output, generated.report_json.as_bytes())?;
        return Ok(generated);
    }
    if options.output.exists() && !options.force {
        return Err(SafetyError::OutputExists(
            options.output.display().to_string(),
        ));
    }
    write_file(&options.output, generated.report_json.as_bytes())?;
    Ok(generated)
}

pub fn audit_workspace(options: &AuditOptions) -> Result<GeneratedAudit, SafetyError> {
    if !options.cargo_manifest.is_file() {
        return Err(SafetyError::MissingCargoManifest(
            options.cargo_manifest.display().to_string(),
        ));
    }
    let metadata = cargo_metadata(options)?;
    let workspace_root = metadata.workspace_root.canonicalize().map_err(|_| {
        SafetyError::InvalidWorkspaceRoot(metadata.workspace_root.display().to_string())
    })?;
    let (manifest_path, manifest_relative) =
        workspace_file(&workspace_root, &options.cargo_manifest, true, "Cargo.toml")?;
    let (policy_path, policy_relative) =
        workspace_json_file(&workspace_root, &options.policy, true)?;
    workspace_json_file(&workspace_root, &options.output, false)?;

    let manifest_bytes = read_file(&manifest_path)?;
    let policy_bytes = read_file(&policy_path)?;
    let cargo_lock_path = workspace_root.join("Cargo.lock");
    let (cargo_lock_path, cargo_lock_sha256) = if cargo_lock_path.is_file() {
        (
            Some("Cargo.lock".to_owned()),
            Some(sha256_hex(&read_file(&cargo_lock_path)?)),
        )
    } else {
        (None, None)
    };
    let mut policy: UnsafePolicy = serde_json::from_slice(&policy_bytes)?;
    normalize_policy(&mut policy)?;

    let workspace_ids: BTreeSet<_> = metadata.workspace_members.into_iter().collect();
    let mut workspace_packages: Vec<_> = metadata
        .packages
        .into_iter()
        .filter(|package| workspace_ids.contains(&package.id))
        .collect();
    workspace_packages.sort_by(|left, right| left.name.cmp(&right.name));

    let mut names = BTreeSet::new();
    for package in &workspace_packages {
        if !names.insert(package.name.clone()) {
            return Err(SafetyError::DuplicateWorkspacePackage(package.name.clone()));
        }
    }
    let policy_by_name: BTreeMap<_, _> = policy
        .packages
        .iter()
        .map(|package| (package.package.as_str(), package))
        .collect();
    for package in &workspace_packages {
        if !policy_by_name.contains_key(package.name.as_str()) {
            return Err(SafetyError::MissingPackagePolicy(package.name.clone()));
        }
    }
    for package in &policy.packages {
        if !names.contains(&package.package) {
            return Err(SafetyError::UnknownPolicyPackage(package.package.clone()));
        }
    }

    let mut package_audits = Vec::new();
    for package in &workspace_packages {
        let package_policy = policy_by_name[package.name.as_str()];
        package_audits.push(audit_package(&workspace_root, package, package_policy)?);
    }
    package_audits.sort_by(|left, right| left.package.cmp(&right.package));

    let report = UnsafeAuditReport {
        schema_version: REPORT_SCHEMA_VERSION,
        cargo_manifest_sha256: sha256_hex(&manifest_bytes),
        cargo_manifest_path: manifest_relative,
        cargo_lock_sha256,
        cargo_lock_path,
        policy_sha256: sha256_hex(&policy_bytes),
        policy_path: policy_relative,
        packages: package_audits,
    };
    let report_json = format!("{}\n", serde_json::to_string_pretty(&report)?);
    let summary = AuditSummary {
        workspace_packages: report.packages.len(),
        safe_packages: report
            .packages
            .iter()
            .filter(|package| package.mode == PackageMode::Safe)
            .count(),
        bridge_packages: report
            .packages
            .iter()
            .filter(|package| package.mode == PackageMode::Bridge)
            .count(),
        source_files: report
            .packages
            .iter()
            .map(|package| package.sources.len())
            .sum(),
        crate_roots: report
            .packages
            .iter()
            .map(|package| package.crate_roots.len())
            .sum(),
        unsafe_occurrences: report
            .packages
            .iter()
            .map(|package| package.unsafe_occurrences.len())
            .sum(),
        lint_allowances: report
            .packages
            .iter()
            .map(|package| package.lint_allowances.len())
            .sum(),
        output: options.output.display().to_string(),
        checked: options.check,
    };
    Ok(GeneratedAudit {
        report_json,
        summary,
    })
}

fn audit_package(
    workspace_root: &Path,
    package: &CargoPackage,
    policy: &PackagePolicy,
) -> Result<PackageAudit, SafetyError> {
    let manifest = package.manifest_path.canonicalize().map_err(|_| {
        SafetyError::MissingCargoManifest(package.manifest_path.display().to_string())
    })?;
    let package_root = manifest
        .parent()
        .ok_or_else(|| SafetyError::InvalidWorkspaceRoot(manifest.display().to_string()))?
        .to_path_buf();
    let manifest_relative = relative_path(workspace_root, &manifest).ok_or_else(|| {
        SafetyError::SourceOutsidePackage {
            package: package.name.clone(),
            source_path: manifest.display().to_string(),
        }
    })?;
    let manifest_sha256 = sha256_hex(&read_file(&manifest)?);

    let mut source_paths = BTreeSet::new();
    collect_rust_sources(&package_root, &package_root, &mut source_paths)?;
    let allowed: BTreeSet<_> = policy.allowed_sources.iter().cloned().collect();
    for source in &allowed {
        if !source_paths.contains(source) {
            return Err(SafetyError::MissingAllowedSource {
                package: package.name.clone(),
                source_path: source.clone(),
            });
        }
    }

    let mut parsed = BTreeMap::new();
    let mut sources = Vec::new();
    let mut occurrences = Vec::new();
    let mut allowances = Vec::new();
    for source in &source_paths {
        let bytes = read_file(&package_root.join(source))?;
        sources.push(SourceEvidence {
            source: source.clone(),
            sha256: sha256_hex(&bytes),
        });
        let syntax = syn::parse_file(&String::from_utf8_lossy(&bytes)).map_err(|error| {
            SafetyError::ParseRust {
                path: format!("{}/{}", package.name, source),
                source: error,
            }
        })?;
        let scan = scan_source(source, &syntax);
        occurrences.extend(scan.0);
        allowances.extend(scan.1);
        if let Some(include) = scan.2.first() {
            return Err(SafetyError::UnsupportedCodeInclude {
                package: package.name.clone(),
                source_path: source.clone(),
                line: include.line,
            });
        }
        parsed.insert(source.clone(), syntax);
    }
    sources.sort();
    occurrences.sort();
    allowances.sort_by(|left, right| {
        (
            left.source.as_str(),
            left.line,
            left.column,
            left.context.as_str(),
        )
            .cmp(&(
                right.source.as_str(),
                right.line,
                right.column,
                right.context.as_str(),
            ))
    });

    let mut roots: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for target in &package.targets {
        let canonical =
            target
                .src_path
                .canonicalize()
                .map_err(|_| SafetyError::SourceOutsidePackage {
                    package: package.name.clone(),
                    source_path: target.src_path.display().to_string(),
                })?;
        let source = relative_path(&package_root, &canonical).ok_or_else(|| {
            SafetyError::SourceOutsidePackage {
                package: package.name.clone(),
                source_path: canonical.display().to_string(),
            }
        })?;
        let target_description = if target.kind.is_empty() {
            target.name.clone()
        } else {
            format!("{} ({})", target.name, target.kind.join(","))
        };
        roots.entry(source).or_default().insert(target_description);
    }
    let mut crate_roots = Vec::new();
    for (source, targets) in roots {
        let syntax = parsed
            .get(&source)
            .ok_or_else(|| SafetyError::SourceOutsidePackage {
                package: package.name.clone(),
                source_path: source.clone(),
            })?;
        crate_roots.push(CrateRootEvidence {
            source,
            targets: targets.into_iter().collect(),
            unsafe_code_lint: root_lint_level(&syntax.attrs, "unsafe_code"),
            unsafe_op_in_unsafe_fn_lint: root_lint_level(&syntax.attrs, "unsafe_op_in_unsafe_fn"),
        });
    }
    crate_roots.sort();

    validate_package_policy(
        &package.name,
        policy,
        &crate_roots,
        &occurrences,
        &allowances,
    )?;

    Ok(PackageAudit {
        package: package.name.clone(),
        manifest_path: manifest_relative,
        manifest_sha256,
        mode: policy.mode,
        allowed_sources: policy.allowed_sources.clone(),
        crate_roots,
        sources,
        unsafe_occurrences: occurrences,
        lint_allowances: allowances,
    })
}

fn validate_package_policy(
    package: &str,
    policy: &PackagePolicy,
    roots: &[CrateRootEvidence],
    occurrences: &[UnsafeOccurrence],
    allowances: &[LintAllowanceEvidence],
) -> Result<(), SafetyError> {
    let allowed: BTreeSet<_> = policy.allowed_sources.iter().map(String::as_str).collect();
    match policy.mode {
        PackageMode::Safe => {
            for root in roots {
                if root.unsafe_code_lint != RootLintLevel::Forbid {
                    return Err(SafetyError::UnsafeSafeRoot {
                        package: package.to_owned(),
                        source_path: root.source.clone(),
                        found: root.unsafe_code_lint,
                    });
                }
            }
            if let Some(occurrence) = occurrences.first() {
                return Err(SafetyError::UnsafeInSafePackage {
                    package: package.to_owned(),
                    source_path: occurrence.source.clone(),
                    line: occurrence.line,
                    kind: occurrence.kind,
                });
            }
            if let Some(allowance) = allowances.first() {
                return Err(SafetyError::UnsafeAllowanceInSafePackage {
                    package: package.to_owned(),
                    source_path: allowance.source.clone(),
                    line: allowance.line,
                });
            }
        }
        PackageMode::Bridge => {
            for root in roots {
                if !matches!(
                    root.unsafe_code_lint,
                    RootLintLevel::Deny | RootLintLevel::Forbid
                ) {
                    return Err(SafetyError::UnsafeBridgeRoot {
                        package: package.to_owned(),
                        source_path: root.source.clone(),
                        found: root.unsafe_code_lint,
                    });
                }
                if !matches!(
                    root.unsafe_op_in_unsafe_fn_lint,
                    RootLintLevel::Deny | RootLintLevel::Forbid
                ) {
                    return Err(SafetyError::UnsafeBridgeOperationRoot {
                        package: package.to_owned(),
                        source_path: root.source.clone(),
                        found: root.unsafe_op_in_unsafe_fn_lint,
                    });
                }
            }
            if occurrences.is_empty() {
                return Err(SafetyError::EmptyBridgePackage(package.to_owned()));
            }
            if !roots
                .iter()
                .any(|root| root.unsafe_code_lint == RootLintLevel::Deny)
            {
                return Err(SafetyError::MissingBridgeDenyRoot(package.to_owned()));
            }
            for occurrence in occurrences {
                if !allowed.contains(occurrence.source.as_str()) {
                    return Err(SafetyError::UnsafeOutsideAllowedSource {
                        package: package.to_owned(),
                        source_path: occurrence.source.clone(),
                        line: occurrence.line,
                        kind: occurrence.kind,
                    });
                }
                if occurrence.allowance_line.is_none() {
                    return Err(SafetyError::UnscopedBridgeUnsafe {
                        package: package.to_owned(),
                        source_path: occurrence.source.clone(),
                        line: occurrence.line,
                        kind: occurrence.kind,
                    });
                }
            }
            for allowance in allowances {
                if !allowed.contains(allowance.source.as_str()) {
                    return Err(SafetyError::AllowanceOutsideAllowedSource {
                        package: package.to_owned(),
                        source_path: allowance.source.clone(),
                        line: allowance.line,
                    });
                }
                if !allowance.used {
                    return Err(SafetyError::StaleLintAllowance {
                        package: package.to_owned(),
                        source_path: allowance.source.clone(),
                        line: allowance.line,
                    });
                }
            }
            for source in &policy.allowed_sources {
                if !occurrences
                    .iter()
                    .any(|occurrence| &occurrence.source == source)
                {
                    return Err(SafetyError::StaleAllowedSource {
                        package: package.to_owned(),
                        source_path: source.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn normalize_policy(policy: &mut UnsafePolicy) -> Result<(), SafetyError> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(SafetyError::UnsupportedPolicySchema {
            found: policy.schema_version,
            supported: POLICY_SCHEMA_VERSION,
        });
    }
    if policy.packages.is_empty() {
        return Err(SafetyError::EmptyPolicy);
    }
    let mut names = BTreeSet::new();
    for package in &mut policy.packages {
        if !names.insert(package.package.clone()) {
            return Err(SafetyError::DuplicatePolicyPackage(package.package.clone()));
        }
        let mut normalized = BTreeSet::new();
        for source in &package.allowed_sources {
            let source = normalize_repo_relative_path(source).ok_or_else(|| {
                SafetyError::InvalidAllowedSource {
                    package: package.package.clone(),
                    source_path: source.clone(),
                }
            })?;
            if Path::new(&source)
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("rs")
            {
                return Err(SafetyError::InvalidAllowedSource {
                    package: package.package.clone(),
                    source_path: source,
                });
            }
            normalized.insert(source);
        }
        package.allowed_sources = normalized.into_iter().collect();
        match package.mode {
            PackageMode::Safe if !package.allowed_sources.is_empty() => {
                return Err(SafetyError::SafePackageAllowance {
                    package: package.package.clone(),
                    source_path: package.allowed_sources[0].clone(),
                });
            }
            PackageMode::Bridge if package.allowed_sources.is_empty() => {
                return Err(SafetyError::EmptyBridgeAllowance(package.package.clone()));
            }
            _ => {}
        }
    }
    policy
        .packages
        .sort_by(|left, right| left.package.cmp(&right.package));
    Ok(())
}

fn cargo_metadata(options: &AuditOptions) -> Result<CargoMetadata, SafetyError> {
    let output = Command::new(&options.cargo)
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(&options.cargo_manifest)
        .output()
        .map_err(|source| SafetyError::RunCargo {
            cargo: options.cargo.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(SafetyError::CargoMetadataFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn collect_rust_sources(
    package_root: &Path,
    directory: &Path,
    sources: &mut BTreeSet<String>,
) -> Result<(), SafetyError> {
    let entries = fs::read_dir(directory).map_err(|source| SafetyError::ReadDirectory {
        path: directory.display().to_string(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(
            entry
                .map_err(|source| SafetyError::ReadDirectory {
                    path: directory.display().to_string(),
                    source,
                })?
                .path(),
        );
    }
    paths.sort();
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|source| SafetyError::ReadFile {
            path: path.display().to_string(),
            source,
        })?;
        if metadata.file_type().is_symlink() {
            return Err(SafetyError::UnsupportedSourceSymlink(
                path.display().to_string(),
            ));
        }
        if metadata.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if matches!(name, ".git" | "target") {
                continue;
            }
            if path != package_root && path.join("Cargo.toml").is_file() {
                continue;
            }
            collect_rust_sources(package_root, &path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            let source = relative_path(package_root, &path).ok_or_else(|| {
                SafetyError::SourceOutsidePackage {
                    package: package_root.display().to_string(),
                    source_path: path.display().to_string(),
                }
            })?;
            sources.insert(source);
        }
    }
    Ok(())
}

fn scan_source(
    source: &str,
    syntax: &syn::File,
) -> (
    Vec<UnsafeOccurrence>,
    Vec<LintAllowanceEvidence>,
    Vec<CodeInclude>,
) {
    let mut collector = AllowanceCollector::default();
    collector.visit_file(syntax);
    let mut allowances: Vec<_> = collector
        .locations
        .into_iter()
        .map(|(line, column)| AllowanceState {
            evidence: LintAllowanceEvidence {
                source: source.to_owned(),
                line,
                column,
                context: "<unresolved>".to_owned(),
                used: false,
            },
        })
        .collect();
    allowances.sort_by_key(|allowance| (allowance.evidence.line, allowance.evidence.column));
    let allowance_by_location = allowances
        .iter()
        .enumerate()
        .map(|(index, allowance)| ((allowance.evidence.line, allowance.evidence.column), index))
        .collect();
    let mut scanner = UnsafeScanner {
        source,
        occurrences: Vec::new(),
        allowances,
        allowance_by_location,
        active_allowances: Vec::new(),
        forbid_active: false,
        contexts: vec!["<crate>".to_owned()],
        code_includes: Vec::new(),
    };
    let saved = scanner.enter_attributes(&syntax.attrs, "<file>");
    for item in &syntax.items {
        scanner.visit_item(item);
    }
    scanner.exit_attributes(saved);
    scanner.occurrences.sort();
    let mut evidence: Vec<_> = scanner
        .allowances
        .into_iter()
        .map(|allowance| allowance.evidence)
        .collect();
    evidence.sort();
    (scanner.occurrences, evidence, scanner.code_includes)
}

#[derive(Default)]
struct AllowanceCollector {
    locations: BTreeSet<(usize, usize)>,
}

impl<'ast> Visit<'ast> for AllowanceCollector {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if lint_directive(attribute) == Some(LintDirective::Allow) {
            self.locations.insert(span_location(attribute.span()));
        }
        visit::visit_attribute(self, attribute);
    }
}

impl UnsafeScanner<'_> {
    fn enter_attributes(&mut self, attributes: &[Attribute], context: &str) -> ScopeState {
        let saved = ScopeState {
            active_allowances: self.active_allowances.clone(),
            forbid_active: self.forbid_active,
        };
        self.contexts.push(context.to_owned());
        let has_forbid = attributes
            .iter()
            .any(|attribute| lint_directive(attribute) == Some(LintDirective::Forbid));
        let has_deny = attributes
            .iter()
            .any(|attribute| lint_directive(attribute) == Some(LintDirective::Deny));
        if has_forbid {
            self.forbid_active = true;
            self.active_allowances.clear();
        } else if has_deny {
            self.active_allowances.clear();
        }
        for attribute in attributes {
            if !self.forbid_active && lint_directive(attribute) == Some(LintDirective::Allow) {
                let location = span_location(attribute.span());
                if let Some(index) = self.allowance_by_location.get(&location).copied() {
                    self.allowances[index].evidence.context = self.context();
                    self.active_allowances.push(index);
                }
            }
        }
        self.scan_unsafe_attributes(attributes);
        saved
    }

    fn exit_attributes(&mut self, saved: ScopeState) {
        self.active_allowances = saved.active_allowances;
        self.forbid_active = saved.forbid_active;
        self.contexts.pop();
    }

    fn scan_unsafe_attributes(&mut self, attributes: &[Attribute]) {
        for attribute in attributes {
            let path = attribute
                .path()
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if path == "unsafe"
                || matches!(
                    path.as_str(),
                    "no_mangle" | "export_name" | "link_section" | "naked"
                )
                || path == "cfg_attr"
                    && matches!(
                        &attribute.meta,
                        syn::Meta::List(list)
                            if token_stream_contains_any_ident(
                                list.tokens.clone(),
                                &["unsafe", "no_mangle", "export_name", "link_section", "naked"]
                            )
                    )
            {
                self.record(
                    UnsafeKind::Attribute,
                    attribute.span(),
                    format!("attribute `{path}`"),
                );
            }
        }
    }

    fn record(&mut self, kind: UnsafeKind, span: Span, detail: String) {
        let (line, column) = span_location(span);
        let allowance = self.active_allowances.last().copied();
        if let Some(index) = allowance {
            self.allowances[index].evidence.used = true;
        }
        self.occurrences.push(UnsafeOccurrence {
            source: self.source.to_owned(),
            line,
            column,
            kind,
            context: self.context(),
            detail,
            allowance_line: allowance.map(|index| self.allowances[index].evidence.line),
            allowance_context: allowance
                .map(|index| self.allowances[index].evidence.context.clone()),
        });
    }

    fn context(&self) -> String {
        self.contexts.join("::")
    }
}

impl<'ast> Visit<'ast> for UnsafeScanner<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let saved = self.enter_attributes(&node.attrs, &format!("fn {}", node.sig.ident));
        if let Some(token) = &node.sig.unsafety {
            self.record(
                UnsafeKind::Function,
                token.span,
                "unsafe function".to_owned(),
            );
        }
        visit::visit_item_fn(self, node);
        self.exit_attributes(saved);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let saved = self.enter_attributes(&node.attrs, &format!("fn {}", node.sig.ident));
        if let Some(token) = &node.sig.unsafety {
            self.record(
                UnsafeKind::Function,
                token.span,
                "unsafe impl method".to_owned(),
            );
        }
        visit::visit_impl_item_fn(self, node);
        self.exit_attributes(saved);
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        let saved = self.enter_attributes(&node.attrs, &format!("fn {}", node.sig.ident));
        if let Some(token) = &node.sig.unsafety {
            self.record(
                UnsafeKind::Function,
                token.span,
                "unsafe trait method".to_owned(),
            );
        }
        visit::visit_trait_item_fn(self, node);
        self.exit_attributes(saved);
    }

    fn visit_foreign_item_fn(&mut self, node: &'ast ForeignItemFn) {
        let saved = self.enter_attributes(&node.attrs, &format!("fn {}", node.sig.ident));
        if let Some(token) = &node.sig.unsafety {
            self.record(
                UnsafeKind::Function,
                token.span,
                "unsafe foreign function".to_owned(),
            );
        }
        visit::visit_foreign_item_fn(self, node);
        self.exit_attributes(saved);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast ExprUnsafe) {
        self.record(
            UnsafeKind::Block,
            node.unsafe_token.span,
            "unsafe block".to_owned(),
        );
        visit::visit_expr_unsafe(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        let saved = self.enter_attributes(&node.attrs, "impl");
        if let Some(token) = &node.unsafety {
            self.record(UnsafeKind::Impl, token.span, "unsafe impl".to_owned());
        }
        visit::visit_item_impl(self, node);
        self.exit_attributes(saved);
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        let saved = self.enter_attributes(&node.attrs, &format!("trait {}", node.ident));
        if let Some(token) = &node.unsafety {
            self.record(UnsafeKind::Trait, token.span, "unsafe trait".to_owned());
        }
        visit::visit_item_trait(self, node);
        self.exit_attributes(saved);
    }

    fn visit_item_foreign_mod(&mut self, node: &'ast ItemForeignMod) {
        let saved = self.enter_attributes(&node.attrs, "extern block");
        let (span, detail) = node.unsafety.as_ref().map_or_else(
            || (node.abi.extern_token.span, "implicit unsafe extern block"),
            |token| (token.span, "unsafe extern block"),
        );
        self.record(UnsafeKind::ExternBlock, span, detail.to_owned());
        visit::visit_item_foreign_mod(self, node);
        self.exit_attributes(saved);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let saved = self.enter_attributes(&node.attrs, &format!("mod {}", node.ident));
        visit::visit_item_mod(self, node);
        self.exit_attributes(saved);
    }

    fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
        let name = node
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                node.mac
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_else(|| "macro".to_owned())
            });
        let saved = self.enter_attributes(&node.attrs, &format!("macro {name}"));
        visit::visit_item_macro(self, node);
        self.exit_attributes(saved);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        let saved = self.enter_attributes(&node.attrs, &format!("static {}", node.ident));
        if let syn::StaticMutability::Mut(token) = &node.mutability {
            self.record(
                UnsafeKind::MutableStatic,
                token.span,
                "mutable static".to_owned(),
            );
        }
        visit::visit_item_static(self, node);
        self.exit_attributes(saved);
    }

    fn visit_foreign_item_static(&mut self, node: &'ast ForeignItemStatic) {
        let saved = self.enter_attributes(&node.attrs, &format!("static {}", node.ident));
        if let syn::StaticMutability::Mut(token) = &node.mutability {
            self.record(
                UnsafeKind::MutableStatic,
                token.span,
                "mutable foreign static".to_owned(),
            );
        }
        visit::visit_foreign_item_static(self, node);
        self.exit_attributes(saved);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "include")
        {
            self.code_includes.push(CodeInclude {
                line: node.path.span().start().line,
            });
        }
        if token_stream_contains_ident(node.tokens.clone(), "unsafe") {
            self.record(
                UnsafeKind::MacroToken,
                node.span(),
                "macro token `unsafe`".to_owned(),
            );
        }
        visit::visit_macro(self, node);
    }
}

fn root_lint_level(attributes: &[Attribute], lint: &str) -> RootLintLevel {
    let levels: Vec<_> = attributes
        .iter()
        .filter_map(|attribute| lint_directive_for(attribute, lint))
        .collect();
    if levels.len() > 1 {
        return RootLintLevel::Conflict;
    }
    match levels.first().copied() {
        Some(LintDirective::Forbid) => RootLintLevel::Forbid,
        Some(LintDirective::Deny) => RootLintLevel::Deny,
        Some(LintDirective::Warn) => RootLintLevel::Warn,
        Some(LintDirective::Allow) => RootLintLevel::Allow,
        Some(LintDirective::Expect) => RootLintLevel::Expect,
        None => RootLintLevel::Missing,
    }
}

fn lint_directive(attribute: &Attribute) -> Option<LintDirective> {
    lint_directive_for(attribute, "unsafe_code")
}

fn lint_directive_for(attribute: &Attribute, lint: &str) -> Option<LintDirective> {
    let directive = if attribute.path().is_ident("forbid") {
        LintDirective::Forbid
    } else if attribute.path().is_ident("deny") {
        LintDirective::Deny
    } else if attribute.path().is_ident("warn") {
        LintDirective::Warn
    } else if attribute.path().is_ident("allow") {
        LintDirective::Allow
    } else if attribute.path().is_ident("expect") {
        LintDirective::Expect
    } else {
        return None;
    };
    let syn::Meta::List(list) = &attribute.meta else {
        return None;
    };
    token_stream_contains_ident(list.tokens.clone(), lint).then_some(directive)
}

fn token_stream_contains_ident(tokens: proc_macro2::TokenStream, expected: &str) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => identifier == expected,
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_ident(group.stream(), expected)
        }
        _ => false,
    })
}

fn token_stream_contains_any_ident(tokens: proc_macro2::TokenStream, expected: &[&str]) -> bool {
    tokens.into_iter().any(|token| match token {
        proc_macro2::TokenTree::Ident(identifier) => {
            expected.iter().any(|value| identifier == *value)
        }
        proc_macro2::TokenTree::Group(group) => {
            token_stream_contains_any_ident(group.stream(), expected)
        }
        _ => false,
    })
}

fn span_location(span: Span) -> (usize, usize) {
    let start = span.start();
    (start.line, start.column + 1)
}

fn workspace_file(
    root: &Path,
    path: &Path,
    must_exist: bool,
    expected_name: &str,
) -> Result<(PathBuf, String), SafetyError> {
    if path.file_name().and_then(|name| name.to_str()) != Some(expected_name) {
        return Err(SafetyError::MissingCargoManifest(
            path.display().to_string(),
        ));
    }
    let canonical = if must_exist {
        path.canonicalize()
            .map_err(|_| SafetyError::MissingCargoManifest(path.display().to_string()))?
    } else {
        path.to_path_buf()
    };
    let relative = relative_path(root, &canonical)
        .ok_or_else(|| SafetyError::MissingCargoManifest(path.display().to_string()))?;
    Ok((canonical, relative))
}

fn workspace_json_file(
    root: &Path,
    path: &Path,
    must_exist: bool,
) -> Result<(PathBuf, String), SafetyError> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
        return if must_exist {
            Err(SafetyError::InvalidPolicyPath(path.display().to_string()))
        } else {
            Err(SafetyError::InvalidOutputPath(path.display().to_string()))
        };
    }
    let canonical = if must_exist {
        path.canonicalize()
            .map_err(|_| SafetyError::InvalidPolicyPath(path.display().to_string()))?
    } else {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .map_err(|_| SafetyError::InvalidOutputPath(path.display().to_string()))?;
        parent.join(path.file_name().unwrap_or_default())
    };
    let Some(relative) = relative_path(root, &canonical) else {
        return if must_exist {
            Err(SafetyError::InvalidPolicyPath(path.display().to_string()))
        } else {
            Err(SafetyError::InvalidOutputPath(path.display().to_string()))
        };
    };
    Ok((canonical, relative))
}

fn relative_path(root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(root).ok()?;
    normalize_repo_relative_path(&relative.to_string_lossy())
}

fn read_file(path: &Path) -> Result<Vec<u8>, SafetyError> {
    fs::read(path).map_err(|source| SafetyError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), SafetyError> {
    fs::write(path, bytes).map_err(|source| SafetyError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), SafetyError> {
    let actual = fs::read(path).map_err(|_| SafetyError::Drift(path.display().to_string()))?;
    if actual != expected {
        return Err(SafetyError::Drift(path.display().to_string()));
    }
    Ok(())
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

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-safety-{}-{id}", std::process::id()));
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

    fn package(tree: &TempTree, source: &str) {
        tree.write(
            "Cargo.toml",
            "[package]\nname='fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
        );
        tree.write("src/lib.rs", source);
    }

    fn policy(tree: &TempTree, mode: &str, allowed: &[&str]) {
        tree.write(
            "unsafe-policy.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "packages": [{
                    "package": "fixture",
                    "mode": mode,
                    "allowed_sources": allowed
                }]
            }))
            .unwrap(),
        );
    }

    fn options(tree: &TempTree) -> AuditOptions {
        AuditOptions {
            cargo: PathBuf::from("cargo"),
            cargo_manifest: tree.root.join("Cargo.toml"),
            policy: tree.root.join("unsafe-policy.json"),
            output: tree.root.join("chromifer-unsafe.json"),
            force: false,
            check: false,
        }
    }

    #[test]
    fn audits_a_fully_safe_package() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![forbid(unsafe_code)]\npub fn add(left: i32, right: i32) -> i32 { left + right }\n",
        );
        policy(&tree, "safe", &[]);
        let generated = audit_and_write(&options(&tree)).unwrap();
        assert_eq!(generated.summary.safe_packages, 1);
        assert_eq!(generated.summary.unsafe_occurrences, 0);
        assert!(tree.root.join("chromifer-unsafe.json").is_file());
    }

    #[test]
    fn audits_a_scoped_bridge_package() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n#[allow(unsafe_code)]\n#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn boundary(input: *const u8) -> bool { unsafe { !input.is_null() } }\n",
        );
        policy(&tree, "bridge", &["src/lib.rs"]);
        let generated = audit_workspace(&options(&tree)).unwrap();
        assert_eq!(generated.summary.bridge_packages, 1);
        assert_eq!(generated.summary.unsafe_occurrences, 3);
        assert_eq!(generated.summary.lint_allowances, 1);
        let report: UnsafeAuditReport = serde_json::from_str(&generated.report_json).unwrap();
        assert!(
            report.packages[0]
                .unsafe_occurrences
                .iter()
                .all(|occurrence| occurrence.allowance_line == Some(3))
        );
    }

    #[test]
    fn rejects_unsafe_syntax_in_safe_packages() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![forbid(unsafe_code)]\npub unsafe fn boundary() {}\n",
        );
        policy(&tree, "safe", &[]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsafeInSafePackage { .. })
        ));
    }

    #[test]
    fn rejects_unscoped_or_unlisted_bridge_unsafe() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\npub unsafe fn boundary() {}\n",
        );
        policy(&tree, "bridge", &["src/lib.rs"]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnscopedBridgeUnsafe { .. })
        ));

        tree.write(
            "src/lib.rs",
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\nmod ffi;\n",
        );
        tree.write(
            "src/ffi.rs",
            "#![allow(unsafe_code)]\npub unsafe fn boundary() {}\n",
        );
        policy(&tree, "bridge", &["src/lib.rs"]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsafeOutsideAllowedSource { source_path, .. })
                if source_path == "src/ffi.rs"
        ));
    }

    #[test]
    fn rejects_stale_source_and_lint_allowances() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n#[allow(unsafe_code)]\npub fn safe() {}\n",
        );
        policy(&tree, "bridge", &["src/lib.rs"]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::EmptyBridgePackage(_)) | Err(SafetyError::StaleLintAllowance { .. })
        ));

        tree.write(
            "src/lib.rs",
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n#[allow(unsafe_code)]\npub unsafe fn boundary() {}\n",
        );
        tree.write("src/unused.rs", "pub fn unused() {}\n");
        policy(&tree, "bridge", &["src/lib.rs", "src/unused.rs"]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::StaleAllowedSource { source_path, .. })
                if source_path == "src/unused.rs"
        ));
    }

    #[test]
    fn requires_complete_workspace_policy_and_root_lints() {
        let tree = TempTree::new();
        package(&tree, "pub fn safe() {}\n");
        policy(&tree, "safe", &[]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsafeSafeRoot {
                found: RootLintLevel::Missing,
                ..
            })
        ));

        tree.write(
            "unsafe-policy.json",
            "{\"schema_version\":1,\"packages\":[{\"package\":\"other\",\"mode\":\"safe\"}]}",
        );
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::MissingPackagePolicy(name)) if name == "fixture"
        ));
    }

    #[test]
    fn inventories_all_unsafe_forms_and_nested_allowance_scopes() {
        let syntax = syn::parse_file(
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n#[allow(unsafe_code)]\nmod ffi {\n    pub unsafe trait Trait {}\n    unsafe impl Trait for () {}\n    extern \"C\" { pub unsafe fn foreign(); }\n    static mut VALUE: i32 = 0;\n    pub fn call() { unsafe {} }\n}\n",
        )
        .unwrap();
        let (occurrences, allowances, includes) = scan_source("src/lib.rs", &syntax);
        assert_eq!(occurrences.len(), 6);
        assert_eq!(allowances.len(), 1);
        assert!(includes.is_empty());
        assert!(allowances[0].used);
        let kinds: BTreeSet<_> = occurrences
            .iter()
            .map(|occurrence| occurrence.kind)
            .collect();
        assert!(kinds.contains(&UnsafeKind::Trait));
        assert!(kinds.contains(&UnsafeKind::Impl));
        assert!(kinds.contains(&UnsafeKind::ExternBlock));
        assert!(kinds.contains(&UnsafeKind::Function));
        assert!(kinds.contains(&UnsafeKind::Block));
        assert!(kinds.contains(&UnsafeKind::MutableStatic));
    }

    #[test]
    fn inventories_macro_tokens_and_cfg_attr_unsafe_attributes() {
        let syntax = syn::parse_file(
            "#![deny(unsafe_code)]\n#![deny(unsafe_op_in_unsafe_fn)]\n#[allow(unsafe_code)]\nmacro_rules! boundary { () => { unsafe { 1 } } }\n#[allow(unsafe_code)]\n#[cfg_attr(unix, unsafe(no_mangle))]\npub extern \"C\" fn exported() {}\n",
        )
        .unwrap();
        let (occurrences, allowances, includes) = scan_source("src/lib.rs", &syntax);
        assert!(includes.is_empty());
        assert_eq!(occurrences.len(), 2);
        assert_eq!(allowances.len(), 2);
        assert!(allowances.iter().all(|allowance| allowance.used));
        assert!(
            occurrences
                .iter()
                .any(|occurrence| occurrence.kind == UnsafeKind::MacroToken)
        );
        assert!(
            occurrences
                .iter()
                .any(|occurrence| occurrence.kind == UnsafeKind::Attribute)
        );
        assert!(
            occurrences
                .iter()
                .all(|occurrence| occurrence.allowance_line.is_some())
        );
    }

    #[test]
    fn forbid_scope_cannot_be_reopened_and_duplicate_root_lints_conflict() {
        let syntax = syn::parse_file(
            "#![forbid(unsafe_code)]\n#[allow(unsafe_code)]\npub unsafe fn boundary() {}\n",
        )
        .unwrap();
        let (occurrences, allowances, includes) = scan_source("src/lib.rs", &syntax);
        assert!(includes.is_empty());
        assert_eq!(occurrences.len(), 1);
        assert_eq!(occurrences[0].allowance_line, None);
        assert_eq!(allowances.len(), 1);
        assert!(!allowances[0].used);

        let tree = TempTree::new();
        package(
            &tree,
            "#![forbid(unsafe_code)]\n#![forbid(unsafe_code)]\npub fn safe() {}\n",
        );
        policy(&tree, "safe", &[]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsafeSafeRoot {
                found: RootLintLevel::Conflict,
                ..
            })
        ));
    }

    #[test]
    fn rejects_include_macro_source_injection() {
        let tree = TempTree::new();
        package(
            &tree,
            "#![forbid(unsafe_code)]\ninclude!(\"generated.rs\");\n",
        );
        tree.write("src/generated.rs", "pub fn generated() {}\n");
        policy(&tree, "safe", &[]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsupportedCodeInclude { source_path, line, .. })
                if source_path == "src/lib.rs" && line == 2
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_source_inventory() {
        use std::os::unix::fs::symlink;

        let tree = TempTree::new();
        package(&tree, "#![forbid(unsafe_code)]\npub fn safe() {}\n");
        tree.write("shared.rs", "pub fn linked() {}\n");
        symlink(tree.root.join("shared.rs"), tree.root.join("src/linked.rs")).unwrap();
        policy(&tree, "safe", &[]);
        assert!(matches!(
            audit_workspace(&options(&tree)),
            Err(SafetyError::UnsupportedSourceSymlink(path))
                if path.ends_with("src/linked.rs")
        ));
    }

    #[test]
    fn check_mode_detects_report_drift() {
        let tree = TempTree::new();
        package(&tree, "#![forbid(unsafe_code)]\npub fn safe() {}\n");
        policy(&tree, "safe", &[]);
        audit_and_write(&options(&tree)).unwrap();
        let mut check = options(&tree);
        check.check = true;
        assert!(audit_and_write(&check).is_ok());
        fs::write(tree.root.join("chromifer-unsafe.json"), "changed").unwrap();
        assert!(matches!(
            audit_and_write(&check),
            Err(SafetyError::Drift(_))
        ));
    }
}
