#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus};

use chromifer_build::BridgeProvenance;
use chromifer_cabi::CAbiProvenance;
use chromifer_manifest::normalize_repo_relative_path;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTRACT_SCHEMA_VERSION: u32 = 1;
const BUILD_PROVENANCE_SCHEMA_VERSION: u32 = 4;
const C_ABI_PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationOptions {
    pub repo_root: PathBuf,
    pub source_root: PathBuf,
    pub contract: PathBuf,
    pub gn: PathBuf,
    pub ninja: PathBuf,
    pub rustc: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationContract {
    pub schema_version: u32,
    pub package_root: String,
    pub build_provenance: String,
    pub c_abi_provenance: String,
    pub destination: String,
    pub source_inputs: Vec<String>,
    pub endpoint_source: String,
    pub endpoint_target: String,
    #[serde(default = "default_integration_target")]
    pub integration_target: String,
    pub out_dir: String,
    #[serde(default)]
    pub rust_template: RustTemplateMode,
    #[serde(default)]
    pub expected_exit_code: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RustTemplateMode {
    Existing,
    #[default]
    HostAdapter,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntegrationSummary {
    pub package: String,
    pub destination: String,
    pub root_target: String,
    pub endpoint_target: String,
    pub out_dir: String,
    pub target_count: usize,
    pub endpoint_path: String,
    pub endpoint_sha256: String,
    pub endpoint_bytes: usize,
    pub endpoint_exit_code: i32,
    pub tools: ToolchainIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolchainIdentity {
    pub gn: ToolIdentity,
    pub ninja: ToolIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc: Option<ToolIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolIdentity {
    pub requested: String,
    pub invocation_path: String,
    pub resolved_path: String,
    pub sha256: String,
    pub bytes: usize,
    pub version: String,
}

#[derive(Debug, Error)]
pub enum IntegrationError {
    #[error("repository root `{0}` is not an accessible directory")]
    InvalidRepoRoot(String),
    #[error("GN source root `{0}` is not an accessible GN checkout")]
    InvalidSourceRoot(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse integration JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported integration contract schema {found}; supported schema is {supported}")]
    UnsupportedContractSchema { found: u32, supported: u32 },
    #[error("invalid integration contract: {0}")]
    InvalidContract(String),
    #[error("path `{0}` is missing, symlinked, or escapes its declared root")]
    InvalidPath(String),
    #[error("generated build provenance schema {found} is unsupported")]
    UnsupportedBuildProvenance { found: u32 },
    #[error("C ABI provenance schema {found} is unsupported")]
    UnsupportedCAbiProvenance { found: u32 },
    #[error("generated BUILD.gn digest differs from build provenance")]
    BuildDigestMismatch,
    #[error("C ABI artifact `{path}` digest differs from provenance")]
    CAbiDigestMismatch { path: String },
    #[error("generated package destination `{0}` already exists")]
    DestinationExists(String),
    #[error("host Rust adapter path `{0}` already exists")]
    AdapterExists(String),
    #[error("existing Chromium Rust template `{0}` is missing")]
    MissingRustTemplate(String),
    #[error("executable `{0}` could not be resolved")]
    MissingExecutable(String),
    #[error("failed to launch `{program}`: {source}")]
    Launch {
        program: String,
        #[source]
        source: std::io::Error,
    },
    #[error("command `{command}` failed with status {status}: {output}")]
    CommandFailed {
        command: String,
        status: String,
        output: String,
    },
    #[error("integration endpoint exited with {actual}; expected {expected}")]
    EndpointExitMismatch { actual: i32, expected: i32 },
    #[error("GN project export is invalid: {0}")]
    InvalidProject(String),
    #[error("integration target `{0}` is absent from the GN project export")]
    MissingTarget(String),
    #[error("integration endpoint has no executable output")]
    MissingEndpointOutput,
    #[error("tool `{0}` changed during integration execution")]
    ToolChanged(String),
    #[error("failed to create or remove integration overlay `{path}`: {source}")]
    OverlayIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
struct ResolvedTool {
    requested: String,
    invocation_path: PathBuf,
    resolved_path: PathBuf,
    sha256: String,
    bytes: usize,
    version: String,
}

#[derive(Debug)]
struct OverlayGuard {
    paths: Vec<PathBuf>,
    active: bool,
}

impl OverlayGuard {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            active: true,
        }
    }

    fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    fn cleanup(&mut self) -> Result<(), IntegrationError> {
        for path in self.paths.iter().rev() {
            if !path.exists() {
                continue;
            }
            let result = if path.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            };
            result.map_err(|source| IntegrationError::OverlayIo {
                path: display(path),
                source,
            })?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for OverlayGuard {
    fn drop(&mut self) {
        if self.active {
            for path in self.paths.iter().rev() {
                if path.is_dir() {
                    let _ = fs::remove_dir_all(path);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
}

pub fn run_integration(
    options: &IntegrationOptions,
) -> Result<IntegrationSummary, IntegrationError> {
    let repo_root = canonical_directory(&options.repo_root)
        .ok_or_else(|| IntegrationError::InvalidRepoRoot(display(&options.repo_root)))?;
    let source_root = canonical_directory(&options.source_root)
        .filter(|root| root.join(".gn").is_file() && root.join("BUILD.gn").is_file())
        .ok_or_else(|| IntegrationError::InvalidSourceRoot(display(&options.source_root)))?;
    let contract_path = canonical_file(&repo_root, &options.contract)?;
    let contract_bytes = read_file(&contract_path)?;
    let contract: IntegrationContract = serde_json::from_slice(&contract_bytes)?;
    validate_contract(&contract)?;
    for input in &contract.source_inputs {
        resolve_file(&source_root, input)?;
    }

    let package_root = resolve_directory(&repo_root, &contract.package_root)?;
    let build_provenance_path = resolve_file(&repo_root, &contract.build_provenance)?;
    let c_abi_provenance_path = resolve_file(&repo_root, &contract.c_abi_provenance)?;
    if !build_provenance_path.starts_with(&package_root)
        || !c_abi_provenance_path.starts_with(&package_root)
    {
        return Err(IntegrationError::InvalidContract(
            "build and C ABI provenance must be inside package_root".into(),
        ));
    }
    let build_provenance: BridgeProvenance =
        serde_json::from_slice(&read_file(&build_provenance_path)?)?;
    let c_abi_provenance: CAbiProvenance =
        serde_json::from_slice(&read_file(&c_abi_provenance_path)?)?;
    validate_provenance(
        &repo_root,
        &package_root,
        &contract,
        &build_provenance,
        &c_abi_provenance,
    )?;

    let tools = ToolchainRuntime::new(options, &source_root, contract.rust_template)?;
    let consumer = build_provenance.consumer.as_ref().ok_or_else(|| {
        IntegrationError::InvalidContract("build provenance has no C++ consumer".into())
    })?;
    let destination = source_root.join(&contract.destination);
    if destination.exists() {
        return Err(IntegrationError::DestinationExists(display(&destination)));
    }
    let mut guard = OverlayGuard::new();
    validate_overlay_parent(&source_root, &contract.destination)?;
    track_missing_parents(&source_root, &contract.destination, &mut guard)?;
    guard.track(destination.clone());
    materialize_package(
        &package_root,
        &destination,
        &contract,
        &build_provenance,
        &c_abi_provenance,
        consumer,
    )?;

    if contract.rust_template == RustTemplateMode::HostAdapter {
        let rustc = tools.rustc.as_ref().ok_or_else(|| {
            IntegrationError::InvalidContract("host adapter has no resolved Rustc".into())
        })?;
        install_host_adapter(&source_root, &rustc.invocation_path, &mut guard)?;
    } else {
        let template = resolve_file(&source_root, "build/rust/rust_static_library.gni");
        if template.is_err() {
            let template = source_root.join("build/rust/rust_static_library.gni");
            return Err(IntegrationError::MissingRustTemplate(display(&template)));
        }
    }

    let out_dir = source_root.join(&contract.out_dir);
    validate_overlay_parent(&source_root, &contract.out_dir)?;
    fs::create_dir_all(&out_dir).map_err(|source| IntegrationError::OverlayIo {
        path: display(&out_dir),
        source,
    })?;
    let root_target = format!("//{}:{}", contract.destination, contract.integration_target);
    run_checked(
        &tools.gn.invocation_path,
        &source_root,
        &[
            "gen",
            &contract.out_dir,
            &format!("--root-target={root_target}"),
            "--ide=json",
            "--json-file-name=project.json",
            &format!(
                "--ninja-executable={}",
                display(&tools.ninja.invocation_path)
            ),
        ],
    )?;

    let endpoint_label = format!("//{}:{}", contract.destination, contract.endpoint_target);
    let project_path = out_dir.join("project.json");
    let (target_count, endpoint_path) =
        endpoint_from_project(&read_file(&project_path)?, &source_root, &endpoint_label)?;
    run_checked(
        &tools.ninja.invocation_path,
        &source_root,
        &[
            "-C",
            &contract.out_dir,
            &format!("{}:{}", contract.destination, contract.endpoint_target),
        ],
    )?;

    let status = Command::new(&endpoint_path)
        .current_dir(&source_root)
        .status()
        .map_err(|source| IntegrationError::Launch {
            program: display(&endpoint_path),
            source,
        })?;
    let actual_exit = status_code(status);
    if actual_exit != contract.expected_exit_code {
        return Err(IntegrationError::EndpointExitMismatch {
            actual: actual_exit,
            expected: contract.expected_exit_code,
        });
    }
    let endpoint_bytes = read_file(&endpoint_path)?;
    guard.cleanup()?;
    tools.verify_unchanged()?;

    Ok(IntegrationSummary {
        package: build_provenance.package,
        destination: contract.destination,
        root_target,
        endpoint_target: endpoint_label,
        out_dir: contract.out_dir,
        target_count,
        endpoint_path: display(&endpoint_path),
        endpoint_sha256: sha256_hex(&endpoint_bytes),
        endpoint_bytes: endpoint_bytes.len(),
        endpoint_exit_code: actual_exit,
        tools: tools.into_identity(),
    })
}

struct ToolchainRuntime {
    gn: ResolvedTool,
    ninja: ResolvedTool,
    rustc: Option<ResolvedTool>,
}

impl ToolchainRuntime {
    fn new(
        options: &IntegrationOptions,
        cwd: &Path,
        rust_template: RustTemplateMode,
    ) -> Result<Self, IntegrationError> {
        Ok(Self {
            gn: resolve_tool(&options.gn, cwd, &["--version"])?,
            ninja: resolve_tool(&options.ninja, cwd, &["--version"])?,
            rustc: if rust_template == RustTemplateMode::HostAdapter {
                Some(resolve_tool(&options.rustc, cwd, &["--version"])?)
            } else {
                None
            },
        })
    }

    fn verify_unchanged(&self) -> Result<(), IntegrationError> {
        for tool in [&self.gn, &self.ninja] {
            let current = file_identity(&tool.resolved_path)?;
            if current.0 != tool.sha256 || current.1 != tool.bytes {
                return Err(IntegrationError::ToolChanged(tool.requested.clone()));
            }
            let invocation = tool
                .invocation_path
                .canonicalize()
                .map_err(|_| IntegrationError::ToolChanged(tool.requested.clone()))?;
            if invocation != tool.resolved_path {
                return Err(IntegrationError::ToolChanged(tool.requested.clone()));
            }
        }
        if let Some(tool) = &self.rustc {
            let current = file_identity(&tool.resolved_path)?;
            if current.0 != tool.sha256 || current.1 != tool.bytes {
                return Err(IntegrationError::ToolChanged(tool.requested.clone()));
            }
            let invocation = tool
                .invocation_path
                .canonicalize()
                .map_err(|_| IntegrationError::ToolChanged(tool.requested.clone()))?;
            if invocation != tool.resolved_path {
                return Err(IntegrationError::ToolChanged(tool.requested.clone()));
            }
        }
        Ok(())
    }

    fn into_identity(self) -> ToolchainIdentity {
        ToolchainIdentity {
            gn: tool_identity(self.gn),
            ninja: tool_identity(self.ninja),
            rustc: self.rustc.map(tool_identity),
        }
    }
}

fn tool_identity(tool: ResolvedTool) -> ToolIdentity {
    ToolIdentity {
        requested: tool.requested,
        invocation_path: display(&tool.invocation_path),
        resolved_path: display(&tool.resolved_path),
        sha256: tool.sha256,
        bytes: tool.bytes,
        version: tool.version,
    }
}

fn validate_contract(contract: &IntegrationContract) -> Result<(), IntegrationError> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(IntegrationError::UnsupportedContractSchema {
            found: contract.schema_version,
            supported: CONTRACT_SCHEMA_VERSION,
        });
    }
    for (field, value) in [
        ("package_root", &contract.package_root),
        ("build_provenance", &contract.build_provenance),
        ("c_abi_provenance", &contract.c_abi_provenance),
        ("destination", &contract.destination),
        ("endpoint_source", &contract.endpoint_source),
        ("out_dir", &contract.out_dir),
    ] {
        normalized_exact(value).map_err(|_| {
            IntegrationError::InvalidContract(format!(
                "{field} `{value}` is not a normalized relative path"
            ))
        })?;
    }
    if contract.source_inputs.is_empty() {
        return Err(IntegrationError::InvalidContract(
            "source_inputs must declare the GN checkout files required by the integration".into(),
        ));
    }
    let mut source_inputs = BTreeSet::new();
    for input in &contract.source_inputs {
        let normalized = normalized_exact(input).map_err(|_| {
            IntegrationError::InvalidContract(format!(
                "source input `{input}` is not a normalized relative path"
            ))
        })?;
        if !source_inputs.insert(normalized) {
            return Err(IntegrationError::InvalidContract(format!(
                "duplicate source input `{input}`"
            )));
        }
    }
    if contract.rust_template == RustTemplateMode::HostAdapter && env::consts::OS != "linux" {
        return Err(IntegrationError::InvalidContract(
            "host_adapter currently supports Linux only".into(),
        ));
    }
    if contract.rust_template == RustTemplateMode::Existing
        && !source_inputs.contains("build/rust/rust_static_library.gni")
    {
        return Err(IntegrationError::InvalidContract(
            "existing Rust template mode must list `build/rust/rust_static_library.gni` in source_inputs"
                .into(),
        ));
    }
    if !contract.out_dir.starts_with("out/") {
        return Err(IntegrationError::InvalidContract(
            "out_dir must be below `out/`".into(),
        ));
    }
    if !(0..=255).contains(&contract.expected_exit_code) {
        return Err(IntegrationError::InvalidContract(
            "expected_exit_code must be between 0 and 255".into(),
        ));
    }
    for (field, value) in [
        ("endpoint_target", &contract.endpoint_target),
        ("integration_target", &contract.integration_target),
    ] {
        if !is_identifier(value) {
            return Err(IntegrationError::InvalidContract(format!(
                "{field} `{value}` is not a valid GN target identifier"
            )));
        }
    }
    Ok(())
}

fn validate_provenance(
    repo_root: &Path,
    package_root: &Path,
    contract: &IntegrationContract,
    build: &BridgeProvenance,
    c_abi: &CAbiProvenance,
) -> Result<(), IntegrationError> {
    if build.schema_version != BUILD_PROVENANCE_SCHEMA_VERSION {
        return Err(IntegrationError::UnsupportedBuildProvenance {
            found: build.schema_version,
        });
    }
    if c_abi.schema_version != C_ABI_PROVENANCE_SCHEMA_VERSION {
        return Err(IntegrationError::UnsupportedCAbiProvenance {
            found: c_abi.schema_version,
        });
    }
    let expected_package_path = format!("//{}", contract.destination);
    if build.gn_package_path.as_deref() != Some(expected_package_path.as_str()) {
        return Err(IntegrationError::InvalidContract(format!(
            "destination must match generated GN package path `{}`",
            build.gn_package_path.as_deref().unwrap_or("<missing>")
        )));
    }
    let consumer = build.consumer.as_ref().ok_or_else(|| {
        IntegrationError::InvalidContract("build provenance has no C++ consumer".into())
    })?;
    if consumer.sources.is_empty() {
        return Err(IntegrationError::InvalidContract(
            "build provenance consumer has no sources".into(),
        ));
    }
    let build_bytes = read_file(&package_root.join("BUILD.gn"))?;
    if sha256_hex(&build_bytes) != build.build_gn_sha256 {
        return Err(IntegrationError::BuildDigestMismatch);
    }
    let contract_path = resolve_file(package_root, &c_abi.contract_path)?;
    verify_digest(&contract_path, &c_abi.contract_sha256)?;
    let header_path = resolve_file(package_root, &c_abi.header_path)?;
    verify_digest(&header_path, &c_abi.header_sha256)?;
    for source in &c_abi.sources {
        let source_path = resolve_file(package_root, &source.source)?;
        verify_digest(&source_path, &source.sha256)?;
    }
    let endpoint = resolve_file(
        repo_root,
        &format!("{}/{}", contract.package_root, contract.endpoint_source),
    )?;
    if !endpoint.starts_with(package_root) {
        return Err(IntegrationError::InvalidPath(display(&endpoint)));
    }
    Ok(())
}

fn verify_digest(path: &Path, expected: &str) -> Result<(), IntegrationError> {
    let bytes = read_file(path)?;
    if sha256_hex(&bytes) != expected {
        return Err(IntegrationError::CAbiDigestMismatch {
            path: display(path),
        });
    }
    Ok(())
}

fn materialize_package(
    package_root: &Path,
    destination: &Path,
    contract: &IntegrationContract,
    build: &BridgeProvenance,
    c_abi: &CAbiProvenance,
    consumer: &chromifer_build::ConsumerProvenance,
) -> Result<(), IntegrationError> {
    fs::create_dir_all(destination).map_err(|source| IntegrationError::OverlayIo {
        path: display(destination),
        source,
    })?;
    let mut files = BTreeSet::new();
    files.insert("BUILD.gn".to_owned());
    files.insert(build.crate_root.clone());
    files.insert(contract.endpoint_source.clone());
    files.insert(c_abi.contract_path.clone());
    files.insert(c_abi.header_path.clone());
    for source in &build.sources {
        files.insert(source.clone());
    }
    for source in &consumer.sources {
        files.insert(source.clone());
    }
    for header in &consumer.required_headers {
        let prefix = format!("{}/", contract.destination);
        let relative = header.strip_prefix(&prefix).ok_or_else(|| {
            IntegrationError::InvalidContract(format!(
                "consumer header `{header}` is outside destination"
            ))
        })?;
        files.insert(relative.to_owned());
    }
    for source in &c_abi.sources {
        files.insert(source.source.clone());
    }

    for relative in files {
        let relative = normalized_exact(&relative)?;
        let source = resolve_file(package_root, &relative)?;
        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| IntegrationError::OverlayIo {
                path: display(parent),
                source,
            })?;
        }
        fs::copy(&source, &target).map_err(|source| IntegrationError::OverlayIo {
            path: display(&target),
            source,
        })?;
    }
    append_integration_targets(&destination.join("BUILD.gn"), contract, consumer)?;
    Ok(())
}

fn append_integration_targets(
    build_gn: &Path,
    contract: &IntegrationContract,
    consumer: &chromifer_build::ConsumerProvenance,
) -> Result<(), IntegrationError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(build_gn)
        .map_err(|source| IntegrationError::OverlayIo {
            path: display(build_gn),
            source,
        })?;
    let block = format!(
        "\n# Generated by Chromifer's GN endpoint integration harness.\n\
executable(\"{}\") {{\n  sources = [ \"{}\" ]\n  deps = [ \":{}\" ]\n}}\n\n\
group(\"{}\") {{\n  deps = [ \":{}\" ]\n}}\n",
        contract.endpoint_target,
        contract.endpoint_source,
        consumer.target_name,
        contract.integration_target,
        contract.endpoint_target,
    );
    file.write_all(block.as_bytes())
        .map_err(|source| IntegrationError::OverlayIo {
            path: display(build_gn),
            source,
        })
}

fn install_host_adapter(
    source_root: &Path,
    rustc: &Path,
    guard: &mut OverlayGuard,
) -> Result<(), IntegrationError> {
    validate_overlay_parent(source_root, "build/rust")?;
    let directory = source_root.join("build/rust");
    if directory.exists() {
        return Err(IntegrationError::AdapterExists(display(&directory)));
    }
    let template = directory.join("rust_static_library.gni");
    let script = directory.join("compile_staticlib.py");
    fs::create_dir_all(&directory).map_err(|source| IntegrationError::OverlayIo {
        path: display(&directory),
        source,
    })?;
    guard.track(directory.clone());
    fs::write(&script, host_compile_script()).map_err(|source| IntegrationError::OverlayIo {
        path: display(&script),
        source,
    })?;
    fs::write(&template, host_rust_template(rustc)).map_err(|source| {
        IntegrationError::OverlayIo {
            path: display(&template),
            source,
        }
    })?;
    Ok(())
}

fn host_compile_script() -> &'static str {
    "#!/usr/bin/env python3\nimport pathlib\nimport subprocess\nimport sys\n\nrustc, crate_root, output, edition, crate_name, unsafe_policy = sys.argv[1:]\npathlib.Path(output).parent.mkdir(parents=True, exist_ok=True)\ncommand = [rustc, crate_root, '--crate-name', crate_name, '--crate-type', 'staticlib', '--edition', edition, '-C', 'panic=abort', '-o', output]\nif unsafe_policy == 'deny':\n    command.extend(['-F', 'unsafe-code'])\nsubprocess.run(command, check=True)\n"
}

fn host_rust_template(rustc: &Path) -> String {
    let rustc = gn_escape(&display(rustc));
    format!(
        "template(\"rust_static_library\") {{\n  _crate_name = target_name\n  _archive_target = target_name + \"__archive\"\n  _link_config = target_name + \"__link\"\n  _archive_dir = get_label_info(\":$_archive_target\", \"target_out_dir\")\n  _archive = \"$_archive_dir/lib${{_crate_name}}.a\"\n  _unsafe_policy = \"deny\"\n  if (defined(invoker.allow_unsafe) && invoker.allow_unsafe) {{\n    _unsafe_policy = \"allow\"\n  }}\n\n  action(_archive_target) {{\n    script = \"//build/rust/compile_staticlib.py\"\n    sources = invoker.sources\n    inputs = [ invoker.crate_root ]\n    outputs = [ _archive ]\n    args = [\n      \"{rustc}\",\n      rebase_path(invoker.crate_root, root_build_dir),\n      rebase_path(_archive, root_build_dir),\n      invoker.edition,\n      _crate_name,\n      _unsafe_policy,\n    ]\n  }}\n\n  config(_link_config) {{\n    include_dirs = [ \"//\" ]\n    libs = [ _archive ]\n    if (is_linux) {{\n      libs += [ \"dl\", \"pthread\", \"m\" ]\n    }}\n  }}\n\n  group(_crate_name) {{\n    public_deps = [ \":$_archive_target\" ]\n    public_configs = [ \":$_link_config\" ]\n    if (defined(invoker.visibility)) {{\n      visibility = invoker.visibility\n    }}\n  }}\n}}\n"
    )
}

fn endpoint_from_project(
    bytes: &[u8],
    source_root: &Path,
    label: &str,
) -> Result<(usize, PathBuf), IntegrationError> {
    let project: Value = serde_json::from_slice(bytes)?;
    let targets = project
        .get("targets")
        .and_then(Value::as_object)
        .ok_or_else(|| IntegrationError::InvalidProject("missing targets object".into()))?;
    let target = targets
        .get(label)
        .ok_or_else(|| IntegrationError::MissingTarget(label.to_owned()))?;
    let outputs = target
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or(IntegrationError::MissingEndpointOutput)?;
    let output = outputs
        .iter()
        .filter_map(Value::as_str)
        .find(|value| value.starts_with("//"))
        .ok_or(IntegrationError::MissingEndpointOutput)?;
    let relative = normalized_exact(output.trim_start_matches("//"))?;
    Ok((targets.len(), source_root.join(relative)))
}

fn resolve_tool(
    requested: &Path,
    cwd: &Path,
    version_args: &[&str],
) -> Result<ResolvedTool, IntegrationError> {
    let requested_text = display(requested);
    let invocation_path = resolve_executable(requested, cwd)?;
    let resolved_path = invocation_path
        .canonicalize()
        .map_err(|_| IntegrationError::MissingExecutable(requested_text.clone()))?;
    let (sha256, bytes) = file_identity(&resolved_path)?;
    let output = Command::new(&invocation_path)
        .current_dir(cwd)
        .args(version_args)
        .output()
        .map_err(|source| IntegrationError::Launch {
            program: requested_text.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(command_failed(
            &invocation_path,
            version_args,
            output.status,
            &output.stdout,
            &output.stderr,
        ));
    }
    let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if version.is_empty() {
        return Err(IntegrationError::InvalidContract(format!(
            "tool `{requested_text}` returned an empty version"
        )));
    }
    Ok(ResolvedTool {
        requested: requested_text,
        invocation_path,
        resolved_path,
        sha256,
        bytes,
        version,
    })
}

fn resolve_executable(requested: &Path, cwd: &Path) -> Result<PathBuf, IntegrationError> {
    if requested.is_absolute() || requested.components().count() > 1 {
        let path = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            cwd.join(requested)
        };
        if path.is_file() {
            return Ok(path);
        }
        return Err(IntegrationError::MissingExecutable(display(requested)));
    }
    let path = env::var_os("PATH")
        .ok_or_else(|| IntegrationError::MissingExecutable(display(requested)))?;
    for directory in env::split_paths(&path) {
        let directory = if directory.as_os_str().is_empty() {
            cwd.to_path_buf()
        } else if directory.is_absolute() {
            directory
        } else {
            cwd.join(directory)
        };
        let candidate = directory.join(requested);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(IntegrationError::MissingExecutable(display(requested)))
}

fn run_checked(program: &Path, cwd: &Path, args: &[&str]) -> Result<Vec<u8>, IntegrationError> {
    let output = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .map_err(|source| IntegrationError::Launch {
            program: display(program),
            source,
        })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(command_failed(
            program,
            args,
            output.status,
            &output.stdout,
            &output.stderr,
        ))
    }
}

fn command_failed(
    program: &Path,
    args: &[&str],
    status: ExitStatus,
    stdout: &[u8],
    stderr: &[u8],
) -> IntegrationError {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    let output = match (stdout.trim(), stderr.trim()) {
        ("", stderr) => stderr.to_owned(),
        (stdout, "") => stdout.to_owned(),
        (stdout, stderr) => format!("{stdout}\n{stderr}"),
    };
    IntegrationError::CommandFailed {
        command: format!("{} {}", display(program), args.join(" ")),
        status: status.to_string(),
        output,
    }
}

fn status_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

fn canonical_directory(path: &Path) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    path.canonicalize().ok()
}

fn canonical_file(root: &Path, path: &Path) -> Result<PathBuf, IntegrationError> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|_| IntegrationError::InvalidPath(display(path)))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(IntegrationError::InvalidPath(display(path)));
    }
    Ok(canonical)
}

fn resolve_directory(root: &Path, relative: &str) -> Result<PathBuf, IntegrationError> {
    reject_symlink_components(root, relative)?;
    let canonical = root
        .join(relative)
        .canonicalize()
        .map_err(|_| IntegrationError::InvalidPath(relative.to_owned()))?;
    if !canonical.starts_with(root) || !canonical.is_dir() {
        return Err(IntegrationError::InvalidPath(relative.to_owned()));
    }
    Ok(canonical)
}

fn resolve_file(root: &Path, relative: &str) -> Result<PathBuf, IntegrationError> {
    reject_symlink_components(root, relative)?;
    let canonical = root
        .join(relative)
        .canonicalize()
        .map_err(|_| IntegrationError::InvalidPath(relative.to_owned()))?;
    if !canonical.starts_with(root) || !canonical.is_file() {
        return Err(IntegrationError::InvalidPath(relative.to_owned()));
    }
    Ok(canonical)
}

fn reject_symlink_components(root: &Path, relative: &str) -> Result<(), IntegrationError> {
    let relative = normalized_exact(relative)?;
    let mut current = root.to_path_buf();
    for component in Path::new(&relative).components() {
        let Component::Normal(component) = component else {
            return Err(IntegrationError::InvalidPath(relative));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| IntegrationError::InvalidPath(relative.clone()))?;
        if metadata.file_type().is_symlink() {
            return Err(IntegrationError::InvalidPath(relative));
        }
    }
    Ok(())
}

fn validate_overlay_parent(root: &Path, relative: &str) -> Result<(), IntegrationError> {
    let relative = normalized_exact(relative)?;
    let components: Vec<_> = Path::new(&relative).components().collect();
    let mut current = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            return Err(IntegrationError::InvalidPath(relative));
        };
        current.push(component);
        if !current.exists() {
            break;
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| IntegrationError::InvalidPath(relative.clone()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(IntegrationError::InvalidPath(relative));
        }
        let canonical = current
            .canonicalize()
            .map_err(|_| IntegrationError::InvalidPath(relative.clone()))?;
        if !canonical.starts_with(root) {
            return Err(IntegrationError::InvalidPath(relative));
        }
    }
    Ok(())
}

fn track_missing_parents(
    root: &Path,
    relative: &str,
    guard: &mut OverlayGuard,
) -> Result<(), IntegrationError> {
    let relative = normalized_exact(relative)?;
    let components: Vec<_> = Path::new(&relative).components().collect();
    let mut current = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(component) = component else {
            return Err(IntegrationError::InvalidPath(relative));
        };
        current.push(component);
        if !current.exists() {
            guard.track(current.clone());
        }
    }
    Ok(())
}

fn normalized_exact(value: &str) -> Result<String, IntegrationError> {
    let normalized = normalize_repo_relative_path(value)
        .ok_or_else(|| IntegrationError::InvalidPath(value.to_owned()))?;
    if normalized != value.replace('\\', "/") {
        return Err(IntegrationError::InvalidPath(value.to_owned()));
    }
    Ok(normalized)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn file_identity(path: &Path) -> Result<(String, usize), IntegrationError> {
    let bytes = read_file(path)?;
    Ok((sha256_hex(&bytes), bytes.len()))
}

fn read_file(path: &Path) -> Result<Vec<u8>, IntegrationError> {
    fs::read(path).map_err(|source| IntegrationError::ReadFile {
        path: display(path),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn gn_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn default_integration_target() -> String {
    "integration".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_template_uses_public_config_and_exact_rustc() {
        let template = host_rust_template(Path::new("/opt/rust/bin/rustc"));
        assert!(template.contains("public_configs"));
        assert!(template.contains("include_dirs = [ \"//\" ]"));
        assert!(template.contains("/opt/rust/bin/rustc"));
        assert!(template.contains("libs += [ \"dl\", \"pthread\", \"m\" ]"));
    }

    #[test]
    fn validates_contract_paths_and_targets() {
        let valid = IntegrationContract {
            schema_version: 1,
            package_root: "examples/c-abi-bridge".into(),
            build_provenance: "examples/c-abi-bridge/chromifer-build.json".into(),
            c_abi_provenance: "examples/c-abi-bridge/include/api.h.chromifer.json".into(),
            destination: "examples/c-abi-bridge".into(),
            source_inputs: vec![".gn".into(), "BUILD.gn".into()],
            endpoint_source: "consumer/main.cc".into(),
            endpoint_target: "c_abi_endpoint".into(),
            integration_target: "integration".into(),
            out_dir: "out/ChromiferIntegration".into(),
            rust_template: RustTemplateMode::HostAdapter,
            expected_exit_code: 0,
        };
        assert!(validate_contract(&valid).is_ok());
        let mut existing = valid.clone();
        existing.rust_template = RustTemplateMode::Existing;
        assert!(validate_contract(&existing).is_err());
        existing
            .source_inputs
            .push("build/rust/rust_static_library.gni".into());
        assert!(validate_contract(&existing).is_ok());

        let mut invalid = valid.clone();
        invalid.out_dir = "../out".into();
        assert!(validate_contract(&invalid).is_err());
        let mut invalid_exit = valid;
        invalid_exit.expected_exit_code = 256;
        assert!(validate_contract(&invalid_exit).is_err());
    }

    #[test]
    fn parses_endpoint_output_from_gn_project() {
        let project = br#"{
          "targets": {
            "//examples/c-abi-bridge:c_abi_endpoint": {
              "outputs": ["//out/ChromiferIntegration/c_abi_endpoint"]
            }
          }
        }"#;
        let (count, path) = endpoint_from_project(
            project,
            Path::new("/src"),
            "//examples/c-abi-bridge:c_abi_endpoint",
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            path,
            Path::new("/src/out/ChromiferIntegration/c_abi_endpoint")
        );
    }
}
