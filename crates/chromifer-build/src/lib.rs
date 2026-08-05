#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chromifer_manifest::normalize_repo_relative_path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PROVENANCE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateOptions {
    pub cargo: PathBuf,
    pub cargo_manifest: PathBuf,
    pub output: PathBuf,
    pub package: Option<String>,
    pub target_name: Option<String>,
    pub dependency_mappings: BTreeMap<String, String>,
    pub public_dependency_mappings: BTreeMap<String, String>,
    pub additional_deps: Vec<String>,
    pub additional_public_deps: Vec<String>,
    pub visibility: Vec<String>,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub extra_sources: Vec<String>,
    pub allow_unsafe: bool,
    pub gn_package_path: Option<String>,
    pub consumer: Option<ConsumerOptions>,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerOptions {
    pub target_name: String,
    pub sources: Vec<String>,
    pub deps: Vec<String>,
    pub public_deps: Vec<String>,
    pub visibility: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GenerateSummary {
    pub package: String,
    pub version: String,
    pub target_name: String,
    pub edition: String,
    pub crate_root: String,
    pub source_count: usize,
    pub cxx_binding_count: usize,
    pub mapped_dependency_count: usize,
    pub allow_unsafe: bool,
    pub generated_cxx_header_count: usize,
    pub consumer_target: Option<String>,
    pub consumer_source_count: usize,
    pub output: String,
    pub provenance: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedBridge {
    pub build_gn: String,
    pub provenance_json: String,
    pub summary: GenerateSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeProvenance {
    pub schema_version: u32,
    pub package: String,
    pub version: String,
    pub cargo_manifest_sha256: String,
    pub target_name: String,
    pub crate_root: String,
    pub edition: String,
    pub sources: Vec<String>,
    pub cxx_bindings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gn_package_path: Option<String>,
    pub generated_cxx_headers: Vec<String>,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub dependencies: Vec<MappedDependency>,
    pub additional_deps: Vec<String>,
    pub additional_public_deps: Vec<String>,
    pub visibility: Vec<String>,
    pub allow_unsafe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<ConsumerProvenance>,
    pub build_gn_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsumerProvenance {
    pub target_name: String,
    pub sources: Vec<String>,
    pub deps: Vec<String>,
    pub public_deps: Vec<String>,
    pub visibility: Vec<String>,
    pub generated_header_includes: Vec<HeaderIncludeEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct HeaderIncludeEvidence {
    pub generated_header: String,
    pub source: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MappedDependency {
    pub cargo_name: String,
    pub package_name: String,
    pub gn_label: String,
    pub public: bool,
}

#[derive(Debug, Error)]
pub enum BuildBridgeError {
    #[error("Cargo manifest `{0}` does not exist")]
    MissingManifest(String),
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
    #[error("Cargo metadata did not contain package `{0}`")]
    UnknownPackage(String),
    #[error("Cargo manifest belongs to a virtual workspace; pass --package")]
    PackageRequired,
    #[error("Cargo manifest path `{0}` has no package directory")]
    InvalidManifestPath(String),
    #[error("package `{0}` has no supported library target")]
    MissingLibraryTarget(String),
    #[error("package `{0}` has multiple supported library targets")]
    AmbiguousLibraryTarget(String),
    #[error("package `{0}` uses build.rs, which cannot yet be translated into Chromium GN")]
    UnsupportedBuildScript(String),
    #[error("library crate root `{0}` is outside the package directory")]
    CrateRootOutsidePackage(String),
    #[error("output must be `<package root>/BUILD.gn`; found `{0}`")]
    InvalidOutputLocation(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect source directory `{path}`: {source}")]
    ReadDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("extra source `{0}` is not a safe package-relative path")]
    InvalidExtraSource(String),
    #[error("source `{0}` does not exist")]
    MissingSource(String),
    #[error("discovered source `{0}` is outside the selected package")]
    SourceOutsidePackage(String),
    #[error("selected Cargo feature `{0}` does not exist")]
    UnknownFeature(String),
    #[error("active Cargo dependency `{0}` lacks a GN label mapping")]
    UnmappedDependency(String),
    #[error("GN mapping `{0}` does not refer to an active Cargo dependency")]
    UnusedDependencyMapping(String),
    #[error("dependency `{0}` is mapped as both private and public")]
    ConflictingDependencyMapping(String),
    #[error("GN dependency `{0}` appears in both deps and public_deps")]
    ConflictingGnDependency(String),
    #[error("target-specific Cargo dependency `{dependency}` (`{target}`) is not supported yet")]
    TargetSpecificDependency { dependency: String, target: String },
    #[error(
        "Cargo dependency `{dependency}` changes dependency features, which cannot yet be represented by a GN label"
    )]
    DependencyFeatureConfiguration { dependency: String },
    #[error(
        "Cargo feature `{feature}` forwards dependency feature `{value}`, which cannot yet be represented by a GN label"
    )]
    DependencyFeatureForwarding { feature: String, value: String },
    #[error("invalid GN label `{0}`")]
    InvalidGnLabel(String),
    #[error("invalid GN target name `{0}`")]
    InvalidTargetName(String),
    #[error("invalid Chromium GN package path `{0}`; expected `//path/to/package`")]
    InvalidGnPackagePath(String),
    #[error(
        "C++ consumer configuration requires --consumer-target, --consumer-source, and --gn-package-path together"
    )]
    IncompleteConsumerConfiguration,
    #[error("C++ consumer target `{0}` must differ from the Rust target name")]
    ConsumerTargetCollision(String),
    #[error("C++ consumer source `{0}` is not a safe package-relative path")]
    InvalidConsumerSource(String),
    #[error("C++ consumer source `{0}` does not exist")]
    MissingConsumerSource(String),
    #[error("C++ consumer requires at least one compilable .cc, .cpp, .cxx, or .mm source")]
    MissingConsumerCompilationUnit,
    #[error("C++ consumer was requested for a Rust crate without any CXX bridge")]
    ConsumerWithoutCxxBridge,
    #[error("C++ consumer does not include generated CXX header `{0}`")]
    MissingGeneratedHeaderInclude(String),
    #[error("unsupported Rust edition `{0}`")]
    UnsupportedEdition(String),
    #[error("generated file `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("generated file `{0}` is missing or differs from Cargo metadata")]
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
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    manifest_path: PathBuf,
    edition: String,
    targets: Vec<CargoTarget>,
    dependencies: Vec<CargoDependency>,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
    crate_types: Vec<String>,
    src_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    name: String,
    rename: Option<String>,
    kind: Option<String>,
    optional: bool,
    target: Option<String>,
    #[serde(default = "default_true")]
    uses_default_features: bool,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug)]
struct ResolvedFeatures {
    enabled: Vec<String>,
    active_optional_dependencies: BTreeSet<String>,
}

#[derive(Debug)]
struct SelectedPackage<'a> {
    package: &'a CargoPackage,
    target: &'a CargoTarget,
    root: PathBuf,
    crate_root: String,
}

struct RenderInputs<'a> {
    target_name: &'a str,
    crate_root: &'a str,
    edition: &'a str,
    sources: &'a [String],
    cxx_bindings: &'a [String],
    features: &'a [String],
    dependencies: &'a [MappedDependency],
    additional_deps: &'a [String],
    additional_public_deps: &'a [String],
    visibility: &'a [String],
    allow_unsafe: bool,
    consumer: Option<&'a ConsumerProvenance>,
}

pub fn generate_and_write(options: &GenerateOptions) -> Result<GeneratedBridge, BuildBridgeError> {
    let generated = generate_bridge(options)?;
    let provenance = provenance_path(&options.output);
    if options.check {
        check_file(&options.output, generated.build_gn.as_bytes())?;
        check_file(&provenance, generated.provenance_json.as_bytes())?;
        return Ok(generated);
    }

    for path in [&options.output, &provenance] {
        if path.exists() && !options.force {
            return Err(BuildBridgeError::OutputExists(path.display().to_string()));
        }
    }
    write_file(&options.output, generated.build_gn.as_bytes())?;
    write_file(&provenance, generated.provenance_json.as_bytes())?;
    Ok(generated)
}

pub fn generate_bridge(options: &GenerateOptions) -> Result<GeneratedBridge, BuildBridgeError> {
    if !options.cargo_manifest.is_file() {
        return Err(BuildBridgeError::MissingManifest(
            options.cargo_manifest.display().to_string(),
        ));
    }
    let metadata = cargo_metadata(options)?;
    let selected = select_package(&metadata, options)?;
    validate_output_location(&selected.root, &options.output)?;

    let edition = selected.package.edition.clone();
    if !matches!(edition.as_str(), "2015" | "2018" | "2021" | "2024") {
        return Err(BuildBridgeError::UnsupportedEdition(edition));
    }
    let target_name = options
        .target_name
        .clone()
        .unwrap_or_else(|| sanitize_target_name(&selected.target.name));
    if !valid_target_name(&target_name) {
        return Err(BuildBridgeError::InvalidTargetName(target_name));
    }

    let mut sources = discover_rust_sources(&selected.root, &selected.crate_root)?;
    for extra in &options.extra_sources {
        let relative = normalize_repo_relative_path(extra)
            .ok_or_else(|| BuildBridgeError::InvalidExtraSource(extra.clone()))?;
        if !selected.root.join(&relative).is_file() {
            return Err(BuildBridgeError::MissingSource(relative));
        }
        sources.insert(relative);
    }
    sources.insert(selected.crate_root.clone());
    let sources: Vec<_> = sources.into_iter().collect();
    let cxx_bindings = detect_cxx_bindings(&selected.root, &sources)?;
    let allow_unsafe = options.allow_unsafe || !cxx_bindings.is_empty();

    let resolved_features = resolve_features(
        selected.package,
        &options.features,
        options.no_default_features,
    )?;
    let active_dependencies = active_dependencies(
        selected.package,
        &resolved_features.active_optional_dependencies,
    )?;
    let dependencies = map_dependencies(
        &active_dependencies,
        &options.dependency_mappings,
        &options.public_dependency_mappings,
        !cxx_bindings.is_empty(),
    )?;
    let additional_deps = normalize_labels(&options.additional_deps)?;
    let additional_public_deps = normalize_labels(&options.additional_public_deps)?;
    let visibility = normalize_labels(&options.visibility)?;
    validate_dependency_partition(&dependencies, &additional_deps, &additional_public_deps)?;
    let features = resolved_features.enabled;
    let gn_package_path = options
        .gn_package_path
        .as_deref()
        .map(normalize_gn_package_path)
        .transpose()?;
    let generated_cxx_headers = generated_cxx_headers(
        gn_package_path.as_deref(),
        &cxx_bindings,
        options.consumer.is_some(),
    )?;
    let consumer = prepare_consumer(
        &selected.root,
        &target_name,
        options.consumer.as_ref(),
        &cxx_bindings,
        &generated_cxx_headers,
    )?;

    let build_gn = render_build_gn(&RenderInputs {
        target_name: &target_name,
        crate_root: &selected.crate_root,
        edition: &edition,
        sources: &sources,
        cxx_bindings: &cxx_bindings,
        features: &features,
        dependencies: &dependencies,
        additional_deps: &additional_deps,
        additional_public_deps: &additional_public_deps,
        visibility: &visibility,
        allow_unsafe,
        consumer: consumer.as_ref(),
    });
    let manifest_bytes = read_file(&options.cargo_manifest)?;
    let provenance = BridgeProvenance {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        package: selected.package.name.clone(),
        version: selected.package.version.clone(),
        cargo_manifest_sha256: sha256_hex(&manifest_bytes),
        target_name: target_name.clone(),
        crate_root: selected.crate_root.clone(),
        edition: edition.clone(),
        sources: sources.clone(),
        cxx_bindings: cxx_bindings.clone(),
        gn_package_path: gn_package_path.clone(),
        generated_cxx_headers: generated_cxx_headers.clone(),
        features: features.clone(),
        no_default_features: options.no_default_features,
        dependencies: dependencies.clone(),
        additional_deps: additional_deps.clone(),
        additional_public_deps: additional_public_deps.clone(),
        visibility: visibility.clone(),
        allow_unsafe,
        consumer: consumer.clone(),
        build_gn_sha256: sha256_hex(build_gn.as_bytes()),
    };
    let provenance_json = format!("{}\n", serde_json::to_string_pretty(&provenance)?);
    let summary = GenerateSummary {
        package: selected.package.name.clone(),
        version: selected.package.version.clone(),
        target_name,
        edition,
        crate_root: selected.crate_root.clone(),
        source_count: sources.len(),
        cxx_binding_count: cxx_bindings.len(),
        mapped_dependency_count: dependencies.len(),
        allow_unsafe,
        generated_cxx_header_count: generated_cxx_headers.len(),
        consumer_target: consumer
            .as_ref()
            .map(|consumer| consumer.target_name.clone()),
        consumer_source_count: consumer
            .as_ref()
            .map_or(0, |consumer| consumer.sources.len()),
        output: options.output.display().to_string(),
        provenance: provenance_path(&options.output).display().to_string(),
        checked: options.check,
    };
    Ok(GeneratedBridge {
        build_gn,
        provenance_json,
        summary,
    })
}

fn cargo_metadata(options: &GenerateOptions) -> Result<CargoMetadata, BuildBridgeError> {
    let output = Command::new(&options.cargo)
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(&options.cargo_manifest)
        .output()
        .map_err(|source| BuildBridgeError::RunCargo {
            cargo: options.cargo.display().to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(BuildBridgeError::CargoMetadataFailed {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn select_package<'a>(
    metadata: &'a CargoMetadata,
    options: &GenerateOptions,
) -> Result<SelectedPackage<'a>, BuildBridgeError> {
    let manifest = options.cargo_manifest.canonicalize().map_err(|_| {
        BuildBridgeError::MissingManifest(options.cargo_manifest.display().to_string())
    })?;
    let package = if let Some(name) = &options.package {
        metadata
            .packages
            .iter()
            .find(|package| package.name == *name)
            .ok_or_else(|| BuildBridgeError::UnknownPackage(name.clone()))?
    } else {
        metadata
            .packages
            .iter()
            .find(|package| {
                package
                    .manifest_path
                    .canonicalize()
                    .is_ok_and(|path| path == manifest)
            })
            .ok_or(BuildBridgeError::PackageRequired)?
    };
    let root = package
        .manifest_path
        .parent()
        .ok_or_else(|| {
            BuildBridgeError::InvalidManifestPath(package.manifest_path.display().to_string())
        })?
        .canonicalize()
        .map_err(|_| {
            BuildBridgeError::MissingManifest(package.manifest_path.display().to_string())
        })?;
    if package
        .targets
        .iter()
        .any(|target| target.kind.iter().any(|kind| kind == "custom-build"))
    {
        return Err(BuildBridgeError::UnsupportedBuildScript(
            package.name.clone(),
        ));
    }
    let targets: Vec<_> = package
        .targets
        .iter()
        .filter(|target| {
            target.kind.iter().any(|kind| kind == "lib")
                && target
                    .crate_types
                    .iter()
                    .any(|kind| matches!(kind.as_str(), "lib" | "rlib" | "staticlib"))
        })
        .collect();
    let target = match targets.as_slice() {
        [] => return Err(BuildBridgeError::MissingLibraryTarget(package.name.clone())),
        [target] => *target,
        _ => {
            return Err(BuildBridgeError::AmbiguousLibraryTarget(
                package.name.clone(),
            ));
        }
    };
    let crate_root_path = target
        .src_path
        .canonicalize()
        .map_err(|_| BuildBridgeError::MissingSource(target.src_path.display().to_string()))?;
    let relative = crate_root_path.strip_prefix(&root).map_err(|_| {
        BuildBridgeError::CrateRootOutsidePackage(target.src_path.display().to_string())
    })?;
    let crate_root =
        normalize_repo_relative_path(&relative.to_string_lossy()).ok_or_else(|| {
            BuildBridgeError::CrateRootOutsidePackage(target.src_path.display().to_string())
        })?;
    Ok(SelectedPackage {
        package,
        target,
        root,
        crate_root,
    })
}

fn validate_output_location(root: &Path, output: &Path) -> Result<(), BuildBridgeError> {
    if output.file_name().and_then(|name| name.to_str()) != Some("BUILD.gn") {
        return Err(BuildBridgeError::InvalidOutputLocation(
            output.display().to_string(),
        ));
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.exists() {
        parent.canonicalize().ok()
    } else {
        None
    };
    if parent.as_deref() != Some(root) {
        return Err(BuildBridgeError::InvalidOutputLocation(
            output.display().to_string(),
        ));
    }
    Ok(())
}

fn discover_rust_sources(
    root: &Path,
    crate_root: &str,
) -> Result<BTreeSet<String>, BuildBridgeError> {
    let crate_root_path = root.join(crate_root);
    let source_root = crate_root_path.parent().unwrap_or(root);
    let mut sources = BTreeSet::new();
    collect_rust_sources(root, source_root, &mut sources)?;
    Ok(sources)
}

fn collect_rust_sources(
    package_root: &Path,
    directory: &Path,
    sources: &mut BTreeSet<String>,
) -> Result<(), BuildBridgeError> {
    let entries = fs::read_dir(directory).map_err(|source| BuildBridgeError::ReadDirectory {
        path: directory.display().to_string(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| BuildBridgeError::ReadDirectory {
            path: directory.display().to_string(),
            source,
        })?;
        paths.push(entry.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if matches!(name, "target" | "tests" | "examples" | "benches") {
                continue;
            }
            if path.join("Cargo.toml").is_file() {
                continue;
            }
            collect_rust_sources(package_root, &path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            let relative = path
                .strip_prefix(package_root)
                .map_err(|_| BuildBridgeError::SourceOutsidePackage(path.display().to_string()))?;
            let relative =
                normalize_repo_relative_path(&relative.to_string_lossy()).ok_or_else(|| {
                    BuildBridgeError::SourceOutsidePackage(path.display().to_string())
                })?;
            sources.insert(relative);
        }
    }
    Ok(())
}

fn detect_cxx_bindings(root: &Path, sources: &[String]) -> Result<Vec<String>, BuildBridgeError> {
    let mut bindings = Vec::new();
    for source in sources {
        let bytes = read_file(&root.join(source))?;
        let text = String::from_utf8_lossy(&bytes);
        if text
            .lines()
            .map(str::trim_start)
            .any(|line| line.starts_with("#[cxx::bridge"))
        {
            bindings.push(source.clone());
        }
    }
    Ok(bindings)
}

fn normalize_gn_package_path(value: &str) -> Result<String, BuildBridgeError> {
    let Some(relative) = value.strip_prefix("//") else {
        return Err(BuildBridgeError::InvalidGnPackagePath(value.to_owned()));
    };
    if relative.contains(':')
        || !relative.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '.' | '+')
        })
    {
        return Err(BuildBridgeError::InvalidGnPackagePath(value.to_owned()));
    }
    let normalized = normalize_repo_relative_path(relative)
        .ok_or_else(|| BuildBridgeError::InvalidGnPackagePath(value.to_owned()))?;
    Ok(format!("//{normalized}"))
}

fn generated_cxx_headers(
    gn_package_path: Option<&str>,
    cxx_bindings: &[String],
    consumer_requested: bool,
) -> Result<Vec<String>, BuildBridgeError> {
    if consumer_requested && cxx_bindings.is_empty() {
        return Err(BuildBridgeError::ConsumerWithoutCxxBridge);
    }
    if cxx_bindings.is_empty() {
        return Ok(Vec::new());
    }
    let Some(package_path) = gn_package_path else {
        if consumer_requested {
            return Err(BuildBridgeError::IncompleteConsumerConfiguration);
        }
        return Ok(Vec::new());
    };
    let package_path = package_path.trim_start_matches("//");
    Ok(cxx_bindings
        .iter()
        .map(|binding| format!("{package_path}/{binding}.h"))
        .collect())
}

fn prepare_consumer(
    package_root: &Path,
    rust_target_name: &str,
    options: Option<&ConsumerOptions>,
    cxx_bindings: &[String],
    generated_headers: &[String],
) -> Result<Option<ConsumerProvenance>, BuildBridgeError> {
    let Some(options) = options else {
        return Ok(None);
    };
    if cxx_bindings.is_empty() {
        return Err(BuildBridgeError::ConsumerWithoutCxxBridge);
    }
    if generated_headers.is_empty() || options.sources.is_empty() {
        return Err(BuildBridgeError::IncompleteConsumerConfiguration);
    }
    if !valid_target_name(&options.target_name) {
        return Err(BuildBridgeError::InvalidTargetName(
            options.target_name.clone(),
        ));
    }
    if options.target_name == rust_target_name {
        return Err(BuildBridgeError::ConsumerTargetCollision(
            options.target_name.clone(),
        ));
    }

    let mut sources = BTreeSet::new();
    for source in &options.sources {
        let relative = normalize_repo_relative_path(source)
            .ok_or_else(|| BuildBridgeError::InvalidConsumerSource(source.clone()))?;
        if !package_root.join(&relative).is_file() {
            return Err(BuildBridgeError::MissingConsumerSource(relative));
        }
        sources.insert(relative);
    }
    if !sources.iter().any(|source| is_cpp_compilation_unit(source)) {
        return Err(BuildBridgeError::MissingConsumerCompilationUnit);
    }
    let sources: Vec<_> = sources.into_iter().collect();

    let mut deps = normalize_labels(&options.deps)?;
    deps.push(format!(":{rust_target_name}"));
    deps.sort_by(|left, right| gn_label_cmp(left, right));
    deps.dedup();
    let public_deps = normalize_labels(&options.public_deps)?;
    let visibility = normalize_labels(&options.visibility)?;
    validate_label_partition(&deps, &public_deps)?;

    let mut include_evidence = Vec::new();
    for source in &sources {
        let bytes = read_file(&package_root.join(source))?;
        let content = String::from_utf8_lossy(&bytes);
        for (index, line) in content.lines().enumerate() {
            if let Some(include) = cpp_include_path(line) {
                if generated_headers.iter().any(|header| header == include) {
                    include_evidence.push(HeaderIncludeEvidence {
                        generated_header: include.to_owned(),
                        source: source.clone(),
                        line: index + 1,
                    });
                }
            }
        }
    }
    include_evidence.sort();
    for header in generated_headers {
        if !include_evidence
            .iter()
            .any(|evidence| evidence.generated_header == *header)
        {
            return Err(BuildBridgeError::MissingGeneratedHeaderInclude(
                header.clone(),
            ));
        }
    }

    Ok(Some(ConsumerProvenance {
        target_name: options.target_name.clone(),
        sources,
        deps,
        public_deps,
        visibility,
        generated_header_includes: include_evidence,
    }))
}

fn is_cpp_compilation_unit(source: &str) -> bool {
    matches!(
        Path::new(source)
            .extension()
            .and_then(|extension| extension.to_str()),
        Some("cc" | "cpp" | "cxx" | "mm")
    )
}

fn cpp_include_path(line: &str) -> Option<&str> {
    let suffix = line.trim_start().strip_prefix("#include")?.trim_start();
    let (opening, closing) = match suffix.as_bytes().first()? {
        b'"' => ('"', '"'),
        b'<' => ('<', '>'),
        _ => return None,
    };
    let inner = &suffix[opening.len_utf8()..];
    let end = inner.find(closing)?;
    Some(&inner[..end])
}

fn active_dependencies<'a>(
    package: &'a CargoPackage,
    active_optional: &BTreeSet<String>,
) -> Result<Vec<(&'a CargoDependency, String)>, BuildBridgeError> {
    let mut result = Vec::new();
    for dependency in &package.dependencies {
        if dependency
            .kind
            .as_deref()
            .is_some_and(|kind| kind != "normal")
        {
            continue;
        }
        let cargo_name = dependency
            .rename
            .clone()
            .unwrap_or_else(|| dependency.name.clone());
        if dependency.optional && !active_optional.contains(&cargo_name) {
            continue;
        }
        if let Some(target) = &dependency.target {
            return Err(BuildBridgeError::TargetSpecificDependency {
                dependency: cargo_name,
                target: target.clone(),
            });
        }
        if !dependency.uses_default_features || !dependency.features.is_empty() {
            return Err(BuildBridgeError::DependencyFeatureConfiguration {
                dependency: cargo_name,
            });
        }
        result.push((dependency, cargo_name));
    }
    result.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(result)
}

fn resolve_features(
    package: &CargoPackage,
    selected_features: &[String],
    no_default_features: bool,
) -> Result<ResolvedFeatures, BuildBridgeError> {
    let dependency_names: BTreeSet<_> = package
        .dependencies
        .iter()
        .filter(|dependency| dependency.optional)
        .map(|dependency| {
            dependency
                .rename
                .clone()
                .unwrap_or_else(|| dependency.name.clone())
        })
        .collect();
    let mut queue = VecDeque::new();
    if !no_default_features && package.features.contains_key("default") {
        queue.push_back("default".to_owned());
    }
    queue.extend(selected_features.iter().cloned());

    let mut enabled = BTreeSet::new();
    let mut active_optional_dependencies = BTreeSet::new();
    while let Some(feature) = queue.pop_front() {
        if !enabled.insert(feature.clone()) {
            continue;
        }
        let values = package
            .features
            .get(&feature)
            .ok_or_else(|| BuildBridgeError::UnknownFeature(feature.clone()))?;
        if dependency_names.contains(&feature) {
            active_optional_dependencies.insert(feature.clone());
        }
        for value in values {
            if let Some(dependency) = value.strip_prefix("dep:") {
                active_optional_dependencies.insert(dependency.to_owned());
            } else if value.contains('/') {
                return Err(BuildBridgeError::DependencyFeatureForwarding {
                    feature: feature.clone(),
                    value: value.clone(),
                });
            } else if package.features.contains_key(value) {
                queue.push_back(value.clone());
            } else if dependency_names.contains(value) {
                active_optional_dependencies.insert(value.clone());
            }
        }
    }

    Ok(ResolvedFeatures {
        enabled: enabled.into_iter().collect(),
        active_optional_dependencies,
    })
}

fn map_dependencies(
    active: &[(&CargoDependency, String)],
    private: &BTreeMap<String, String>,
    public: &BTreeMap<String, String>,
    has_cxx_bindings: bool,
) -> Result<Vec<MappedDependency>, BuildBridgeError> {
    for name in private.keys() {
        if public.contains_key(name) {
            return Err(BuildBridgeError::ConflictingDependencyMapping(name.clone()));
        }
    }
    let active_names: BTreeSet<_> = active.iter().map(|(_, name)| name.clone()).collect();
    for name in private.keys().chain(public.keys()) {
        if !active_names.contains(name) {
            return Err(BuildBridgeError::UnusedDependencyMapping(name.clone()));
        }
    }

    let mut mapped = Vec::new();
    for (dependency, cargo_name) in active {
        if has_cxx_bindings && cargo_name == "cxx" {
            continue;
        }
        let (label, is_public) = if let Some(label) = public.get(cargo_name) {
            (label, true)
        } else if let Some(label) = private.get(cargo_name) {
            (label, false)
        } else {
            return Err(BuildBridgeError::UnmappedDependency(cargo_name.clone()));
        };
        validate_label(label)?;
        mapped.push(MappedDependency {
            cargo_name: cargo_name.clone(),
            package_name: dependency.name.clone(),
            gn_label: label.clone(),
            public: is_public,
        });
    }
    mapped.sort();
    Ok(mapped)
}

fn render_build_gn(inputs: &RenderInputs<'_>) -> String {
    let mut private_deps: Vec<_> = inputs
        .dependencies
        .iter()
        .filter(|dependency| !dependency.public)
        .map(|dependency| dependency.gn_label.clone())
        .collect();
    private_deps.extend(inputs.additional_deps.iter().cloned());
    private_deps.sort_by(|left, right| gn_label_cmp(left, right));
    private_deps.dedup();
    let mut public_deps: Vec<_> = inputs
        .dependencies
        .iter()
        .filter(|dependency| dependency.public)
        .map(|dependency| dependency.gn_label.clone())
        .collect();
    public_deps.extend(inputs.additional_public_deps.iter().cloned());
    public_deps.sort_by(|left, right| gn_label_cmp(left, right));
    public_deps.dedup();

    let mut output = String::from(
        "# Generated by Chromifer from Cargo metadata.\n# Re-run `chromifer generate-gn` instead of editing this file.\n\nimport(\"//build/rust/rust_static_library.gni\")\n\n",
    );
    output.push_str(&format!(
        "rust_static_library(\"{}\") {{\n",
        escape_gn(inputs.target_name)
    ));
    output.push_str(&format!(
        "  crate_root = \"{}\"\n",
        escape_gn(inputs.crate_root)
    ));
    output.push_str(&format!("  edition = \"{}\"\n", escape_gn(inputs.edition)));
    render_list(
        &mut output,
        "sources",
        inputs.sources.iter().map(String::as_str),
    );
    if !inputs.cxx_bindings.is_empty() {
        render_list(
            &mut output,
            "cxx_bindings",
            inputs.cxx_bindings.iter().map(String::as_str),
        );
    }
    if inputs.allow_unsafe {
        output.push_str("  allow_unsafe = true\n");
    }
    if !inputs.features.is_empty() {
        render_list(
            &mut output,
            "features",
            inputs.features.iter().map(String::as_str),
        );
    }
    if !private_deps.is_empty() {
        render_list(&mut output, "deps", private_deps.iter().map(String::as_str));
    }
    if !public_deps.is_empty() {
        render_list(
            &mut output,
            "public_deps",
            public_deps.iter().map(String::as_str),
        );
    }
    if !inputs.visibility.is_empty() {
        render_list(
            &mut output,
            "visibility",
            inputs.visibility.iter().map(String::as_str),
        );
    }
    output.push_str("}\n");
    if let Some(consumer) = inputs.consumer {
        output.push('\n');
        output.push_str(&format!(
            "source_set(\"{}\") {{\n",
            escape_gn(&consumer.target_name)
        ));
        render_list(
            &mut output,
            "sources",
            consumer.sources.iter().map(String::as_str),
        );
        if !consumer.deps.is_empty() {
            render_list(
                &mut output,
                "deps",
                consumer.deps.iter().map(String::as_str),
            );
        }
        if !consumer.public_deps.is_empty() {
            render_list(
                &mut output,
                "public_deps",
                consumer.public_deps.iter().map(String::as_str),
            );
        }
        if !consumer.visibility.is_empty() {
            render_list(
                &mut output,
                "visibility",
                consumer.visibility.iter().map(String::as_str),
            );
        }
        output.push_str("}\n");
    }
    output
}

fn render_list<'a>(output: &mut String, name: &str, values: impl Iterator<Item = &'a str>) {
    let values: Vec<_> = values.collect();
    if let [value] = values.as_slice() {
        output.push_str(&format!("  {name} = [ \"{}\" ]\n", escape_gn(value)));
        return;
    }
    output.push_str(&format!("  {name} = [\n"));
    for value in values {
        output.push_str(&format!("    \"{}\",\n", escape_gn(value)));
    }
    output.push_str("  ]\n");
}

fn normalize_labels(values: &[String]) -> Result<Vec<String>, BuildBridgeError> {
    let mut values = sorted_unique(values);
    for label in &values {
        validate_label(label)?;
    }
    values.sort_by(|left, right| gn_label_cmp(left, right));
    Ok(values)
}

fn gn_label_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let left_kind = usize::from(!left.starts_with(':'));
    let right_kind = usize::from(!right.starts_with(':'));
    left_kind.cmp(&right_kind).then(left.cmp(right))
}

fn validate_dependency_partition(
    dependencies: &[MappedDependency],
    additional_deps: &[String],
    additional_public_deps: &[String],
) -> Result<(), BuildBridgeError> {
    let mut private: BTreeSet<_> = dependencies
        .iter()
        .filter(|dependency| !dependency.public)
        .map(|dependency| dependency.gn_label.as_str())
        .collect();
    private.extend(additional_deps.iter().map(String::as_str));
    let mut public: BTreeSet<_> = dependencies
        .iter()
        .filter(|dependency| dependency.public)
        .map(|dependency| dependency.gn_label.as_str())
        .collect();
    public.extend(additional_public_deps.iter().map(String::as_str));
    validate_label_partition(
        &private.into_iter().map(str::to_owned).collect::<Vec<_>>(),
        &public.into_iter().map(str::to_owned).collect::<Vec<_>>(),
    )
}

fn validate_label_partition(private: &[String], public: &[String]) -> Result<(), BuildBridgeError> {
    let private: BTreeSet<_> = private.iter().map(String::as_str).collect();
    let public: BTreeSet<_> = public.iter().map(String::as_str).collect();
    if let Some(label) = private.intersection(&public).next() {
        return Err(BuildBridgeError::ConflictingGnDependency(
            (*label).to_owned(),
        ));
    }
    Ok(())
}

fn validate_label(label: &str) -> Result<(), BuildBridgeError> {
    if !(label.starts_with("//") || label.starts_with(':'))
        || !label.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '/' | ':' | '_' | '-' | '.' | '*' | '+' | '(' | ')'
                )
        })
    {
        return Err(BuildBridgeError::InvalidGnLabel(label.to_owned()));
    }
    Ok(())
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sanitize_target_name(name: &str) -> String {
    let mut output = String::new();
    for character in name.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            output.push(character.to_ascii_lowercase());
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    output.trim_matches('_').to_owned()
}

fn valid_target_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        && !name.as_bytes()[0].is_ascii_digit()
}

fn escape_gn(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('$', "\\$")
        .replace('"', "\\\"")
}

fn provenance_path(output: &Path) -> PathBuf {
    output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("chromifer-build.json")
}

fn read_file(path: &Path) -> Result<Vec<u8>, BuildBridgeError> {
    fs::read(path).map_err(|source| BuildBridgeError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), BuildBridgeError> {
    fs::write(path, bytes).map_err(|source| BuildBridgeError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), BuildBridgeError> {
    let actual = fs::read(path).map_err(|_| BuildBridgeError::Drift(path.display().to_string()))?;
    if actual != expected {
        return Err(BuildBridgeError::Drift(path.display().to_string()));
    }
    Ok(())
}

fn default_true() -> bool {
    true
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
                std::env::temp_dir().join(format!("chromifer-build-{}-{id}", std::process::id()));
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

    fn package(tree: &TempTree, manifest: &str, lib: &str) {
        tree.write("Cargo.toml", manifest);
        tree.write("src/lib.rs", lib);
    }

    fn options(tree: &TempTree) -> GenerateOptions {
        GenerateOptions {
            cargo: PathBuf::from("cargo"),
            cargo_manifest: tree.root.join("Cargo.toml"),
            output: tree.root.join("BUILD.gn"),
            package: None,
            target_name: None,
            dependency_mappings: BTreeMap::new(),
            public_dependency_mappings: BTreeMap::new(),
            additional_deps: vec![],
            additional_public_deps: vec![],
            visibility: vec![],
            features: vec![],
            no_default_features: false,
            extra_sources: vec![],
            allow_unsafe: false,
            gn_package_path: None,
            consumer: None,
            force: false,
            check: false,
        }
    }

    #[test]
    fn generates_deterministic_first_party_rust_static_library() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='demo-service'\nversion='1.2.3'\nedition='2024'\n",
            "mod worker;\npub fn run() {}\n",
        );
        tree.write("src/worker.rs", "pub fn work() {}\n");
        let generated = generate_and_write(&options(&tree)).unwrap();
        assert!(
            generated
                .build_gn
                .contains("rust_static_library(\"demo_service\")")
        );
        assert!(generated.build_gn.contains("edition = \"2024\""));
        assert!(generated.build_gn.contains("\"src/lib.rs\""));
        assert!(generated.build_gn.contains("\"src/worker.rs\""));
        assert!(!generated.build_gn.contains("allow_unsafe"));
        assert!(tree.root.join("BUILD.gn").is_file());
        assert!(tree.root.join("chromifer-build.json").is_file());

        let second = generate_bridge(&options(&tree)).unwrap();
        assert_eq!(generated.build_gn, second.build_gn);
        assert_eq!(generated.provenance_json, second.provenance_json);
    }

    #[test]
    fn detects_cxx_bridge_and_automatically_allows_bridge_unsafe() {
        let tree = TempTree::new();
        tree.write(
            "cxx/Cargo.toml",
            "[package]\nname='cxx'\nversion='1.0.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
        );
        tree.write("cxx/lib.rs", "pub fn placeholder() {}\n");
        package(
            &tree,
            "[package]\nname='bridge'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncxx={path='cxx'}\n",
            "#[cxx::bridge]\nmod ffi {}\n",
        );
        let generated = generate_bridge(&options(&tree)).unwrap();
        assert!(generated.build_gn.contains("cxx_bindings = ["));
        assert!(generated.build_gn.contains("allow_unsafe = true"));
        assert!(!generated.build_gn.contains("third_party/rust/cxx"));
        assert_eq!(generated.summary.mapped_dependency_count, 0);
    }

    #[test]
    fn requires_every_active_dependency_to_have_an_explicit_gn_mapping() {
        let tree = TempTree::new();
        tree.write(
            "dep/Cargo.toml",
            "[package]\nname='dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        tree.write("dep/src/lib.rs", "pub fn dep() {}\n");
        package(
            &tree,
            "[package]\nname='consumer'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ndep={path='dep'}\n",
            "pub fn consumer() {}\n",
        );
        assert!(matches!(
            generate_bridge(&options(&tree)),
            Err(BuildBridgeError::UnmappedDependency(name)) if name == "dep"
        ));

        let mut options = options(&tree);
        options
            .dependency_mappings
            .insert("dep".into(), "//components/dep:rust".into());
        let generated = generate_bridge(&options).unwrap();
        assert!(generated.build_gn.contains("\"//components/dep:rust\""));
        assert_eq!(generated.summary.mapped_dependency_count, 1);
    }

    #[test]
    fn activates_optional_dependencies_only_through_selected_features() {
        let tree = TempTree::new();
        tree.write(
            "optional/Cargo.toml",
            "[package]\nname='optional-dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        tree.write("optional/src/lib.rs", "pub fn optional() {}\n");
        package(
            &tree,
            "[package]\nname='feature-demo'\nversion='0.1.0'\nedition='2021'\n[dependencies]\noptional_dep={package='optional-dep',path='optional',optional=true}\n[features]\nwith_optional=['dep:optional_dep']\n",
            "pub fn feature_demo() {}\n",
        );
        generate_bridge(&options(&tree)).unwrap();

        let mut options = options(&tree);
        options.features.push("with_optional".into());
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::UnmappedDependency(name)) if name == "optional_dep"
        ));
        options.public_dependency_mappings.insert(
            "optional_dep".into(),
            "//third_party/rust/optional/v1:lib".into(),
        );
        let generated = generate_bridge(&options).unwrap();
        assert!(generated.build_gn.contains("public_deps = ["));
        assert!(generated.build_gn.contains("features = ["));
    }

    #[test]
    fn expands_default_and_nested_local_features_unless_disabled() {
        let tree = TempTree::new();
        tree.write(
            "optional/Cargo.toml",
            "[package]\nname='optional-dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        tree.write("optional/src/lib.rs", "pub fn optional() {}\n");
        package(
            &tree,
            "[package]\nname='defaults'\nversion='0.1.0'\nedition='2021'\n[dependencies]\noptional_dep={package='optional-dep',path='optional',optional=true}\n[features]\ndefault=['full']\nfull=['dep:optional_dep']\n",
            "pub fn defaults() {}\n",
        );
        let mut options = options(&tree);
        options.dependency_mappings.insert(
            "optional_dep".into(),
            "//third_party/rust/optional/v1:lib".into(),
        );
        let generated = generate_bridge(&options).unwrap();
        assert!(generated.build_gn.contains("\"default\""));
        assert!(generated.build_gn.contains("\"full\""));

        options.no_default_features = true;
        options.dependency_mappings.clear();
        let generated = generate_bridge(&options).unwrap();
        assert!(!generated.build_gn.contains("features ="));
    }

    #[test]
    fn rejects_dependency_feature_configuration_and_forwarding() {
        let tree = TempTree::new();
        tree.write(
            "dep/Cargo.toml",
            "[package]\nname='dep'\nversion='0.1.0'\nedition='2021'\n[features]\nderive=[]\n",
        );
        tree.write("dep/src/lib.rs", "pub fn dep() {}\n");
        package(
            &tree,
            "[package]\nname='feature-config'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ndep={path='dep',default-features=false}\n",
            "pub fn feature_config() {}\n",
        );
        assert!(matches!(
            generate_bridge(&options(&tree)),
            Err(BuildBridgeError::DependencyFeatureConfiguration { dependency }) if dependency == "dep"
        ));

        tree.write(
            "Cargo.toml",
            "[package]\nname='feature-forward'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ndep={path='dep'}\n[features]\nforward=['dep/derive']\n",
        );
        let mut options = options(&tree);
        options.features.push("forward".into());
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::DependencyFeatureForwarding { feature, value })
                if feature == "forward" && value == "dep/derive"
        ));
    }

    #[test]
    fn rejects_build_scripts_and_ignores_commented_cxx_markers() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='build-script'\nversion='0.1.0'\nedition='2021'\nbuild='build.rs'\n",
            "// #[cxx::bridge]\npub fn library() {}\n",
        );
        tree.write("build.rs", "fn main() {}\n");
        assert!(matches!(
            generate_bridge(&options(&tree)),
            Err(BuildBridgeError::UnsupportedBuildScript(name)) if name == "build-script"
        ));

        tree.write(
            "Cargo.toml",
            "[package]\nname='comment-only'\nversion='0.1.0'\nedition='2021'\n",
        );
        fs::remove_file(tree.root.join("build.rs")).unwrap();
        let generated = generate_bridge(&options(&tree)).unwrap();
        assert_eq!(generated.summary.cxx_binding_count, 0);
        assert!(!generated.summary.allow_unsafe);
    }

    #[test]
    fn rejects_target_specific_dependencies_until_conditions_can_be_preserved() {
        let tree = TempTree::new();
        tree.write(
            "dep/Cargo.toml",
            "[package]\nname='dep'\nversion='0.1.0'\nedition='2021'\n",
        );
        tree.write("dep/src/lib.rs", "pub fn dep() {}\n");
        package(
            &tree,
            "[package]\nname='conditional'\nversion='0.1.0'\nedition='2021'\n[target.'cfg(unix)'.dependencies]\ndep={path='dep'}\n",
            "pub fn conditional() {}\n",
        );
        assert!(matches!(
            generate_bridge(&options(&tree)),
            Err(BuildBridgeError::TargetSpecificDependency { dependency, .. }) if dependency == "dep"
        ));
    }

    #[test]
    fn check_mode_detects_build_or_provenance_drift() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='drift'\nversion='0.1.0'\nedition='2021'\n",
            "pub fn drift() {}\n",
        );
        generate_and_write(&options(&tree)).unwrap();
        let mut check = options(&tree);
        check.check = true;
        assert!(generate_and_write(&check).is_ok());
        fs::write(tree.root.join("BUILD.gn"), "changed").unwrap();
        assert!(matches!(
            generate_and_write(&check),
            Err(BuildBridgeError::Drift(_))
        ));
    }

    #[test]
    fn rejects_outputs_outside_the_selected_package_root() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='location'\nversion='0.1.0'\nedition='2021'\n",
            "pub fn location() {}\n",
        );
        let mut options = options(&tree);
        options.output = tree.root.join("subdir/BUILD.gn");
        fs::create_dir_all(tree.root.join("subdir")).unwrap();
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::InvalidOutputLocation(_))
        ));
    }

    #[test]
    fn selects_a_package_from_a_virtual_workspace() {
        let tree = TempTree::new();
        tree.write(
            "Cargo.toml",
            "[workspace]\nmembers=['member']\nresolver='3'\n",
        );
        tree.write(
            "member/Cargo.toml",
            "[package]\nname='workspace-member'\nversion='0.1.0'\nedition='2024'\n",
        );
        tree.write("member/src/lib.rs", "pub fn member() {}\n");
        let mut options = options(&tree);
        options.package = Some("workspace-member".into());
        options.output = tree.root.join("member/BUILD.gn");
        let generated = generate_bridge(&options).unwrap();
        assert_eq!(generated.summary.package, "workspace-member");
        assert_eq!(generated.summary.crate_root, "src/lib.rs");
    }

    #[test]
    fn rejects_cross_partition_and_malformed_gn_labels() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='labels'\nversion='0.1.0'\nedition='2021'\n",
            "pub fn labels() {}\n",
        );
        let mut options = options(&tree);
        options.additional_deps.push("//base".into());
        options.additional_public_deps.push("//base".into());
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::ConflictingGnDependency(label)) if label == "//base"
        ));

        options.additional_public_deps.clear();
        options.additional_deps = vec!["//base:$expanded".into()];
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::InvalidGnLabel(_))
        ));
    }

    #[test]
    fn gn_string_escaping_preserves_literal_dollar_signs() {
        assert_eq!(escape_gn("src/$generated.rs"), "src/\\$generated.rs");
    }

    #[test]
    fn generates_cpp_consumer_and_records_generated_header_contract() {
        let tree = TempTree::new();
        tree.write(
            "cxx/Cargo.toml",
            "[package]\nname='cxx'\nversion='1.0.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
        );
        tree.write("cxx/lib.rs", "pub fn placeholder() {}\n");
        package(
            &tree,
            "[package]\nname='bridge'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncxx={path='cxx'}\n",
            "#[cxx::bridge]\nmod ffi {}\n",
        );
        tree.write(
            "consumer/bridge.cc",
            "#include \"services/network/rust/src/lib.rs.h\"\nint UseBridge() { return 0; }\n",
        );
        tree.write("consumer/bridge.h", "int UseBridge();\n");
        let mut options = options(&tree);
        options.gn_package_path = Some("//services/network/rust".into());
        options.consumer = Some(ConsumerOptions {
            target_name: "bridge_cpp".into(),
            sources: vec!["consumer/bridge.h".into(), "consumer/bridge.cc".into()],
            deps: vec!["//base".into()],
            public_deps: vec![],
            visibility: vec!["//services/network:*".into()],
        });

        let generated = generate_bridge(&options).unwrap();
        assert!(generated.build_gn.contains("source_set(\"bridge_cpp\")"));
        assert!(generated.build_gn.contains("\":bridge\""));
        assert_eq!(generated.summary.generated_cxx_header_count, 1);
        assert_eq!(generated.summary.consumer_source_count, 2);
        let consumer = generated
            .provenance_json
            .contains("services/network/rust/src/lib.rs.h");
        assert!(consumer);
        assert!(generated.build_gn.contains("\"//base\""));
    }

    #[test]
    fn rejects_missing_generated_header_include_and_missing_package_path() {
        let tree = TempTree::new();
        tree.write(
            "cxx/Cargo.toml",
            "[package]\nname='cxx'\nversion='1.0.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
        );
        tree.write("cxx/lib.rs", "pub fn placeholder() {}\n");
        package(
            &tree,
            "[package]\nname='bridge'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncxx={path='cxx'}\n",
            "#[cxx::bridge]\nmod ffi {}\n",
        );
        tree.write("consumer.cc", "int UseBridge() { return 0; }\n");
        let mut options = options(&tree);
        options.consumer = Some(ConsumerOptions {
            target_name: "bridge_cpp".into(),
            sources: vec!["consumer.cc".into()],
            deps: vec![],
            public_deps: vec![],
            visibility: vec![],
        });
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::IncompleteConsumerConfiguration)
        ));

        options.gn_package_path = Some("//services/network/rust".into());
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::MissingGeneratedHeaderInclude(header))
                if header == "services/network/rust/src/lib.rs.h"
        ));
    }

    #[test]
    fn rejects_consumer_without_cxx_or_compilation_unit() {
        let tree = TempTree::new();
        package(
            &tree,
            "[package]\nname='pure-rust'\nversion='0.1.0'\nedition='2021'\n",
            "pub fn pure() {}\n",
        );
        tree.write("consumer.cc", "int UseBridge() { return 0; }\n");
        let mut options = options(&tree);
        options.gn_package_path = Some("//services/example/rust".into());
        options.consumer = Some(ConsumerOptions {
            target_name: "consumer".into(),
            sources: vec!["consumer.cc".into()],
            deps: vec![],
            public_deps: vec![],
            visibility: vec![],
        });
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::ConsumerWithoutCxxBridge)
        ));

        tree.write(
            "cxx/Cargo.toml",
            "[package]\nname='cxx'\nversion='1.0.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
        );
        tree.write("cxx/lib.rs", "pub fn placeholder() {}\n");
        tree.write(
            "Cargo.toml",
            "[package]\nname='bridge'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncxx={path='cxx'}\n",
        );
        tree.write("src/lib.rs", "#[cxx::bridge]\nmod ffi {}\n");
        tree.write(
            "consumer.h",
            "#include \"services/example/rust/src/lib.rs.h\"\n",
        );
        options.consumer.as_mut().unwrap().sources = vec!["consumer.h".into()];
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::MissingConsumerCompilationUnit)
        ));
    }

    #[test]
    fn rejects_consumer_target_and_dependency_partition_conflicts() {
        let tree = TempTree::new();
        tree.write(
            "cxx/Cargo.toml",
            "[package]\nname='cxx'\nversion='1.0.0'\nedition='2021'\n[lib]\npath='lib.rs'\n",
        );
        tree.write("cxx/lib.rs", "pub fn placeholder() {}\n");
        package(
            &tree,
            "[package]\nname='bridge'\nversion='0.1.0'\nedition='2021'\n[dependencies]\ncxx={path='cxx'}\n",
            "#[cxx::bridge]\nmod ffi {}\n",
        );
        tree.write(
            "consumer.cc",
            "#include \"services/example/rust/src/lib.rs.h\"\n",
        );
        let mut options = options(&tree);
        options.gn_package_path = Some("//services/example/rust".into());
        options.consumer = Some(ConsumerOptions {
            target_name: "bridge".into(),
            sources: vec!["consumer.cc".into()],
            deps: vec![],
            public_deps: vec![],
            visibility: vec![],
        });
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::ConsumerTargetCollision(name)) if name == "bridge"
        ));

        let consumer = options.consumer.as_mut().unwrap();
        consumer.target_name = "bridge_cpp".into();
        consumer.deps = vec!["//base".into()];
        consumer.public_deps = vec!["//base".into()];
        assert!(matches!(
            generate_bridge(&options),
            Err(BuildBridgeError::ConflictingGnDependency(label)) if label == "//base"
        ));
    }
}
