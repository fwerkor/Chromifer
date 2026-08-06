#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

pub fn normalize_repo_relative_path(value: &str) -> Option<String> {
    let normalized = value.replace('\\', "/");
    let normalized = if let Some(relative) = normalized.strip_prefix("//") {
        relative
    } else if normalized.starts_with('/')
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|character| *character == b':')
    {
        return None;
    } else {
        normalized.as_str()
    };

    let mut segments = Vec::new();
    for component in Path::new(normalized).components() {
        match component {
            Component::Normal(segment) => segments.push(segment.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub project: Project,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory: Option<InventoryMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<Target>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<CompatibilityGate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<Module>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    pub upstream: String,
    pub baseline: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryMetadata {
    pub source_format: String,
    pub build_dir: String,
    pub default_toolchain: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,
    #[serde(default)]
    pub include_all_toolchains: bool,
    #[serde(default)]
    pub include_testonly: bool,
    #[serde(default)]
    pub include_meta_targets: bool,
    #[serde(default)]
    pub infer_state: bool,
    #[serde(default)]
    pub omitted_dependency_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatibilityGate {
    pub id: String,
    #[serde(flatten)]
    pub execution: GateExecution,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<GateInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
}

impl<'de> Deserialize<'de> for CompatibilityGate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireGate {
            id: String,
            #[serde(default)]
            command: Option<String>,
            #[serde(default)]
            program: Option<String>,
            #[serde(default)]
            args: Vec<String>,
            #[serde(default)]
            inputs: Vec<GateInput>,
            #[serde(default)]
            targets: Vec<String>,
        }

        let wire = WireGate::deserialize(deserializer)?;
        let execution = match (wire.command, wire.program) {
            (Some(command), None) if wire.args.is_empty() => GateExecution::Shell { command },
            (None, Some(program)) => GateExecution::Direct {
                program,
                args: wire.args,
            },
            (Some(_), None) => {
                return Err(serde::de::Error::custom(
                    "shell gate must not declare direct-execution args",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "gate must declare exactly one of `command` or `program`",
                ));
            }
            (None, None) => {
                return Err(serde::de::Error::custom(
                    "gate must declare exactly one of `command` or `program`",
                ));
            }
        };
        Ok(Self {
            id: wire.id,
            execution,
            inputs: wire.inputs,
            targets: wire.targets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GateExecution {
    Shell {
        command: String,
    },
    Direct {
        program: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GateInput {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    pub id: String,
    pub path: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<ModuleOwnership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    pub state: MigrationState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviews: Vec<BoundaryReview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleOwnership {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub common_effective_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_sources: Vec<String>,
    #[serde(default)]
    pub split_ownership: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceOwnership>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceOwnership {
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primary_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_owners: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inheritance_stopped_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub module: String,
    pub boundary: Boundary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<BoundaryEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reviews: Vec<BoundaryReview>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoundaryEvidence {
    pub kind: BoundaryEvidenceKind,
    pub file: String,
    pub line: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryEvidenceKind {
    CxxGeneratedHeader,
    CxxBridgeInclude,
    CAbiSymbol,
    MojoGeneratedHeader,
}

impl BoundaryEvidenceKind {
    pub const fn boundary(self) -> Boundary {
        match self {
            Self::CxxGeneratedHeader | Self::CxxBridgeInclude => Boundary::Cxx,
            Self::CAbiSymbol => Boundary::CAbi,
            Self::MojoGeneratedHeader => Boundary::Mojo,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoundaryReview {
    pub kind: BoundaryReviewKind,
    pub file: String,
    pub line: usize,
    pub detail: String,
    #[serde(default)]
    pub resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryReviewKind {
    Callback,
    Observer,
}

impl fmt::Display for BoundaryReviewKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Callback => "callback",
            Self::Observer => "observer",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    LegacyCpp,
    Bridged,
    RustOwned,
}

impl MigrationState {
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::LegacyCpp => Some(Self::Bridged),
            Self::Bridged => Some(Self::RustOwned),
            Self::RustOwned => None,
        }
    }
}

impl fmt::Display for MigrationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LegacyCpp => "legacy_cpp",
            Self::Bridged => "bridged",
            Self::RustOwned => "rust_owned",
        })
    }
}

impl FromStr for MigrationState {
    type Err = ParseMigrationStateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "legacy_cpp" => Ok(Self::LegacyCpp),
            "bridged" => Ok(Self::Bridged),
            "rust_owned" => Ok(Self::RustOwned),
            other => Err(ParseMigrationStateError(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown migration state `{0}`; expected legacy_cpp, bridged, or rust_owned")]
pub struct ParseMigrationStateError(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    Unclassified,
    CppInternal,
    Cxx,
    CAbi,
    Mojo,
    Rust,
}

impl Boundary {
    pub const fn is_audited_cross_language(self) -> bool {
        matches!(self, Self::Cxx | Self::CAbi | Self::Mojo)
    }
}

impl fmt::Display for Boundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unclassified => "unclassified",
            Self::CppInternal => "cpp_internal",
            Self::Cxx => "cxx",
            Self::CAbi => "c_abi",
            Self::Mojo => "mojo",
            Self::Rust => "rust",
        })
    }
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("failed to read manifest `{path}`: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse manifest `{path}`: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(transparent)]
    Validation(#[from] ValidationErrors),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors(pub Vec<ValidationError>);

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "manifest validation failed with {} error(s):",
            self.0.len()
        )?;
        for error in &self.0 {
            writeln!(f, "- {error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidationError {
    #[error("unsupported schema version {found}; supported version is {supported}")]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("project field `{field}` must not be empty")]
    EmptyProjectField { field: &'static str },
    #[error("inventory field `{field}` must not be empty")]
    EmptyInventoryField { field: &'static str },
    #[error("duplicate {kind} id `{id}`")]
    DuplicateId { kind: &'static str, id: String },
    #[error("{kind} `{id}` has an empty {field}")]
    EmptyField {
        kind: &'static str,
        id: String,
        field: &'static str,
    },
    #[error("gate `{gate}` references unknown target `{target}`")]
    UnknownTarget { gate: String, target: String },
    #[error("gate `{gate}` has an invalid execution definition: {detail}")]
    InvalidGateExecution { gate: String, detail: String },
    #[error("gate `{gate}` has invalid input path `{path}`")]
    InvalidGateInputPath { gate: String, path: String },
    #[error("gate `{gate}` has invalid SHA-256 `{sha256}` for input `{path}`")]
    InvalidGateInputDigest {
        gate: String,
        path: String,
        sha256: String,
    },
    #[error("gate `{gate}` contains duplicate input `{path}`")]
    DuplicateGateInput { gate: String, path: String },
    #[error("module `{module}` references unknown gate `{gate}`")]
    UnknownGate { module: String, gate: String },
    #[error("module `{module}` references unknown dependency `{dependency}`")]
    UnknownDependency { module: String, dependency: String },
    #[error("module `{module}` depends on itself")]
    SelfDependency { module: String },
    #[error("module `{module}` has duplicate dependency `{dependency}`")]
    DuplicateDependency { module: String, dependency: String },
    #[error("module `{module}` has an invalid ownership value in `{field}`")]
    InvalidOwnershipValue { module: String, field: &'static str },
    #[error("{kind} `{id}` has an invalid source location in `{file}` at line {line}")]
    InvalidSourceLocation {
        kind: &'static str,
        id: String,
        file: String,
        line: usize,
    },
    #[error("module dependency cycle detected: {cycle}")]
    DependencyCycle { cycle: String },
    #[error("module `{module}` in state `{state}` must declare at least one compatibility gate")]
    MissingCompatibilityGate {
        module: String,
        state: MigrationState,
    },
}

fn default_true() -> bool {
    true
}

impl Manifest {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let source = fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: display.clone(),
            source,
        })?;
        let manifest: Self = toml::from_str(&source).map_err(|source| LoadError::Parse {
            path: display,
            source,
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            errors.push(ValidationError::UnsupportedSchema {
                found: self.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }

        for (field, value) in [
            ("name", self.project.name.as_str()),
            ("upstream", self.project.upstream.as_str()),
            ("baseline", self.project.baseline.as_str()),
        ] {
            if value.trim().is_empty() {
                errors.push(ValidationError::EmptyProjectField { field });
            }
        }

        if let Some(inventory) = &self.inventory {
            for (field, value) in [
                ("source_format", inventory.source_format.as_str()),
                ("build_dir", inventory.build_dir.as_str()),
                ("default_toolchain", inventory.default_toolchain.as_str()),
            ] {
                if value.trim().is_empty() {
                    errors.push(ValidationError::EmptyInventoryField { field });
                }
            }
        }

        let target_ids = collect_ids(
            "target",
            self.targets.iter().map(|item| item.id.as_str()),
            &mut errors,
        );
        let gate_ids = collect_ids(
            "gate",
            self.gates.iter().map(|item| item.id.as_str()),
            &mut errors,
        );
        let module_ids = collect_ids(
            "module",
            self.modules.iter().map(|item| item.id.as_str()),
            &mut errors,
        );

        for target in &self.targets {
            check_nonempty(
                "target",
                &target.id,
                "description",
                &target.description,
                &mut errors,
            );
        }

        for gate in &self.gates {
            validate_gate_execution(gate, &mut errors);
            let mut input_paths = BTreeSet::new();
            for input in &gate.inputs {
                let normalized = normalize_repo_relative_path(&input.path);
                if normalized.as_deref() != Some(input.path.as_str()) {
                    errors.push(ValidationError::InvalidGateInputPath {
                        gate: gate.id.clone(),
                        path: input.path.clone(),
                    });
                }
                if input.sha256.len() != 64
                    || !input
                        .sha256
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    errors.push(ValidationError::InvalidGateInputDigest {
                        gate: gate.id.clone(),
                        path: input.path.clone(),
                        sha256: input.sha256.clone(),
                    });
                }
                if !input_paths.insert(input.path.as_str()) {
                    errors.push(ValidationError::DuplicateGateInput {
                        gate: gate.id.clone(),
                        path: input.path.clone(),
                    });
                }
            }
            for target in &gate.targets {
                if !target_ids.contains(target) {
                    errors.push(ValidationError::UnknownTarget {
                        gate: gate.id.clone(),
                        target: target.clone(),
                    });
                }
            }
        }

        for module in &self.modules {
            check_nonempty("module", &module.id, "path", &module.path, &mut errors);
            check_nonempty("module", &module.id, "owner", &module.owner, &mut errors);
            if let Some(ownership) = &module.ownership {
                check_ownership(module, ownership, &mut errors);
            }
            for source in &module.sources {
                check_nonempty("module", &module.id, "source", source, &mut errors);
            }
            for review in &module.reviews {
                check_source_location(
                    "module review",
                    &module.id,
                    &review.file,
                    review.line,
                    &review.detail,
                    &mut errors,
                );
            }

            if module.state != MigrationState::LegacyCpp && module.gates.is_empty() {
                errors.push(ValidationError::MissingCompatibilityGate {
                    module: module.id.clone(),
                    state: module.state,
                });
            }

            for gate in &module.gates {
                if !gate_ids.contains(gate) {
                    errors.push(ValidationError::UnknownGate {
                        module: module.id.clone(),
                        gate: gate.clone(),
                    });
                }
            }

            let mut dependencies = BTreeSet::new();
            for dependency in &module.dependencies {
                if dependency.module == module.id {
                    errors.push(ValidationError::SelfDependency {
                        module: module.id.clone(),
                    });
                } else if !module_ids.contains(&dependency.module) {
                    errors.push(ValidationError::UnknownDependency {
                        module: module.id.clone(),
                        dependency: dependency.module.clone(),
                    });
                }
                if !dependencies.insert(dependency.module.clone()) {
                    errors.push(ValidationError::DuplicateDependency {
                        module: module.id.clone(),
                        dependency: dependency.module.clone(),
                    });
                }
                for evidence in &dependency.evidence {
                    check_source_location(
                        "boundary evidence",
                        &format!("{} -> {}", module.id, dependency.module),
                        &evidence.file,
                        evidence.line,
                        &evidence.detail,
                        &mut errors,
                    );
                }
                for review in &dependency.reviews {
                    check_source_location(
                        "boundary review",
                        &format!("{} -> {}", module.id, dependency.module),
                        &review.file,
                        review.line,
                        &review.detail,
                        &mut errors,
                    );
                }
            }
        }

        if let Some(cycle) = find_cycle(&self.modules, &module_ids) {
            errors.push(ValidationError::DependencyCycle {
                cycle: cycle.join(" -> "),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors(errors))
        }
    }

    pub fn to_toml_pretty(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    pub fn module(&self, id: &str) -> Option<&Module> {
        self.modules.iter().find(|module| module.id == id)
    }

    pub fn gate(&self, id: &str) -> Option<&CompatibilityGate> {
        self.gates.iter().find(|gate| gate.id == id)
    }
}

fn check_ownership(
    module: &Module,
    ownership: &ModuleOwnership,
    errors: &mut Vec<ValidationError>,
) {
    for (field, values) in [
        ("ownership.primary_owners", &ownership.primary_owners),
        ("ownership.effective_owners", &ownership.effective_owners),
        (
            "ownership.common_effective_owners",
            &ownership.common_effective_owners,
        ),
        ("ownership.owner_files", &ownership.owner_files),
        (
            "ownership.unresolved_sources",
            &ownership.unresolved_sources,
        ),
    ] {
        if values.iter().any(|value| value.trim().is_empty()) {
            errors.push(ValidationError::InvalidOwnershipValue {
                module: module.id.clone(),
                field,
            });
        }
    }

    for source in &ownership.sources {
        if source.source.trim().is_empty() {
            errors.push(ValidationError::InvalidOwnershipValue {
                module: module.id.clone(),
                field: "ownership.sources.source",
            });
        }
        for (field, values) in [
            ("ownership.sources.primary_owners", &source.primary_owners),
            (
                "ownership.sources.effective_owners",
                &source.effective_owners,
            ),
            ("ownership.sources.owner_files", &source.owner_files),
        ] {
            if values.iter().any(|value| value.trim().is_empty()) {
                errors.push(ValidationError::InvalidOwnershipValue {
                    module: module.id.clone(),
                    field,
                });
            }
        }
        if source
            .inheritance_stopped_at
            .as_ref()
            .is_some_and(|path| path.trim().is_empty())
        {
            errors.push(ValidationError::InvalidOwnershipValue {
                module: module.id.clone(),
                field: "ownership.sources.inheritance_stopped_at",
            });
        }
    }
}

fn collect_ids<'a>(
    kind: &'static str,
    ids: impl Iterator<Item = &'a str>,
    errors: &mut Vec<ValidationError>,
) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for id in ids {
        if !found.insert(id.to_owned()) {
            errors.push(ValidationError::DuplicateId {
                kind,
                id: id.to_owned(),
            });
        }
    }
    found
}

fn validate_gate_execution(gate: &CompatibilityGate, errors: &mut Vec<ValidationError>) {
    let invalid = match &gate.execution {
        GateExecution::Shell { command } => {
            if command.trim().is_empty() {
                Some("shell command must not be empty".to_owned())
            } else if command.contains('\0') {
                Some("shell command must not contain NUL".to_owned())
            } else {
                None
            }
        }
        GateExecution::Direct { program, args } => {
            if program.trim().is_empty() {
                Some("program must not be empty".to_owned())
            } else if program.contains('\0') {
                Some("program must not contain NUL".to_owned())
            } else if args.iter().any(|argument| argument.contains('\0')) {
                Some("arguments must not contain NUL".to_owned())
            } else {
                None
            }
        }
    };
    if let Some(detail) = invalid {
        errors.push(ValidationError::InvalidGateExecution {
            gate: gate.id.clone(),
            detail,
        });
    }
}

fn check_nonempty(
    kind: &'static str,
    id: &str,
    field: &'static str,
    value: &str,
    errors: &mut Vec<ValidationError>,
) {
    if value.trim().is_empty() {
        errors.push(ValidationError::EmptyField {
            kind,
            id: id.to_owned(),
            field,
        });
    }
}

fn check_source_location(
    kind: &'static str,
    id: &str,
    file: &str,
    line: usize,
    detail: &str,
    errors: &mut Vec<ValidationError>,
) {
    if file.trim().is_empty() || detail.trim().is_empty() || line == 0 {
        errors.push(ValidationError::InvalidSourceLocation {
            kind,
            id: id.to_owned(),
            file: file.to_owned(),
            line,
        });
    }
}

fn find_cycle(modules: &[Module], known: &BTreeSet<String>) -> Option<Vec<String>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Visit {
        Active,
        Complete,
    }

    fn visit(
        id: &str,
        graph: &BTreeMap<&str, Vec<&str>>,
        states: &mut BTreeMap<String, Visit>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        match states.get(id) {
            Some(Visit::Complete) => return None,
            Some(Visit::Active) => {
                let start = stack.iter().position(|item| item == id).unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.push(id.to_owned());
                return Some(cycle);
            }
            None => {}
        }

        states.insert(id.to_owned(), Visit::Active);
        stack.push(id.to_owned());
        if let Some(dependencies) = graph.get(id) {
            for dependency in dependencies {
                if let Some(cycle) = visit(dependency, graph, states, stack) {
                    return Some(cycle);
                }
            }
        }
        stack.pop();
        states.insert(id.to_owned(), Visit::Complete);
        None
    }

    let graph: BTreeMap<_, _> = modules
        .iter()
        .map(|module| {
            let dependencies = module
                .dependencies
                .iter()
                .filter(|dependency| known.contains(&dependency.module))
                .map(|dependency| dependency.module.as_str())
                .collect();
            (module.id.as_str(), dependencies)
        })
        .collect();

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    for module in modules {
        if let Some(cycle) = visit(&module.id, &graph, &mut states, &mut stack) {
            return Some(cycle);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "Chromifer".into(),
                upstream: "chromium/src".into(),
                baseline: "main".into(),
            },
            inventory: None,
            targets: vec![Target {
                id: "linux".into(),
                description: "Linux desktop".into(),
                required: true,
            }],
            gates: vec![CompatibilityGate {
                id: "unit".into(),
                execution: GateExecution::Shell {
                    command: "autoninja -C out/Default unit_tests".into(),
                },
                inputs: vec![],
                targets: vec!["linux".into()],
            }],
            modules: vec![
                Module {
                    id: "base".into(),
                    path: "base".into(),
                    owner: "foundation".into(),
                    ownership: None,
                    source_label: None,
                    source_type: None,
                    sources: vec![],
                    state: MigrationState::LegacyCpp,
                    gates: vec![],
                    reviews: vec![],
                    dependencies: vec![],
                },
                Module {
                    id: "network".into(),
                    path: "services/network".into(),
                    owner: "services".into(),
                    ownership: None,
                    source_label: None,
                    source_type: None,
                    sources: vec![],
                    state: MigrationState::Bridged,
                    gates: vec!["unit".into()],
                    reviews: vec![],
                    dependencies: vec![Dependency {
                        module: "base".into(),
                        boundary: Boundary::Cxx,
                        evidence: vec![],
                        reviews: vec![],
                    }],
                },
            ],
        }
    }

    #[test]
    fn accepts_valid_manifest() {
        assert_eq!(valid_manifest().validate(), Ok(()));
    }

    #[test]
    fn accepts_direct_gates_and_legacy_shell_toml() {
        let mut manifest = valid_manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: "cargo".into(),
            args: vec!["test".into(), "--locked".into()],
        };
        manifest.gates[0].inputs = vec![GateInput {
            path: "Cargo.lock".into(),
            sha256: "a".repeat(64),
        }];
        assert_eq!(manifest.validate(), Ok(()));

        let legacy: Manifest = toml::from_str(
            r#"
schema_version = 1

[project]
name = "Chromifer"
upstream = "chromium/src"
baseline = "main"

[[gates]]
id = "legacy"
command = "echo compatibility"
"#,
        )
        .unwrap();
        assert_eq!(legacy.validate(), Ok(()));
        assert!(matches!(
            legacy.gates[0].execution,
            GateExecution::Shell { .. }
        ));
    }

    #[test]
    fn rejects_ambiguous_or_unknown_gate_execution_fields() {
        let ambiguous = r#"
schema_version = 1

[project]
name = "Chromifer"
upstream = "chromium/src"
baseline = "main"

[[gates]]
id = "ambiguous"
command = "echo shell"
program = "printf"
args = ["direct"]
"#;
        assert!(toml::from_str::<Manifest>(ambiguous).is_err());

        let shell_with_args = ambiguous.replace("program = \"printf\"\n", "");
        assert!(toml::from_str::<Manifest>(&shell_with_args).is_err());

        let unknown = ambiguous.replace(
            "program = \"printf\"\nargs = [\"direct\"]\n",
            "mystery = true\n",
        );
        assert!(toml::from_str::<Manifest>(&unknown).is_err());
    }

    #[test]
    fn rejects_invalid_direct_gates_and_input_contracts() {
        let mut manifest = valid_manifest();
        manifest.gates[0].execution = GateExecution::Direct {
            program: String::new(),
            args: vec!["bad\0argument".into()],
        };
        manifest.gates[0].inputs = vec![
            GateInput {
                path: "../Cargo.lock".into(),
                sha256: "not-a-digest".into(),
            },
            GateInput {
                path: "../Cargo.lock".into(),
                sha256: "b".repeat(64),
            },
        ];

        let errors = manifest.validate().unwrap_err();
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidGateExecution { .. }))
        );
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidGateInputPath { .. }))
        );
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidGateInputDigest { .. }))
        );
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::DuplicateGateInput { .. }))
        );
    }

    #[test]
    fn normalizes_only_repository_relative_paths() {
        assert_eq!(
            normalize_repo_relative_path("//services\\network/./context.cc"),
            Some("services/network/context.cc".into())
        );
        assert_eq!(normalize_repo_relative_path("services/../base.cc"), None);
        assert_eq!(normalize_repo_relative_path("/etc/passwd"), None);
        assert_eq!(normalize_repo_relative_path("C:\\Windows\\win.ini"), None);
        assert_eq!(normalize_repo_relative_path(""), None);
    }

    #[test]
    fn reports_unknown_references() {
        let mut manifest = valid_manifest();
        manifest.modules[1].gates.push("missing".into());
        manifest.modules[1].dependencies.push(Dependency {
            module: "missing".into(),
            boundary: Boundary::Mojo,
            evidence: vec![],
            reviews: vec![],
        });

        let errors = manifest.validate().unwrap_err();
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::UnknownGate { gate, .. } if gate == "missing"
        )));
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::UnknownDependency { dependency, .. } if dependency == "missing"
        )));
    }

    #[test]
    fn detects_dependency_cycle() {
        let mut manifest = valid_manifest();
        manifest.modules[0].dependencies.push(Dependency {
            module: "network".into(),
            boundary: Boundary::CppInternal,
            evidence: vec![],
            reviews: vec![],
        });

        let errors = manifest.validate().unwrap_err();
        assert!(
            errors
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::DependencyCycle { .. }))
        );
    }

    #[test]
    fn requires_gates_after_legacy_state() {
        let mut manifest = valid_manifest();
        manifest.modules[1].gates.clear();

        let errors = manifest.validate().unwrap_err();
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::MissingCompatibilityGate { module, .. } if module == "network"
        )));
    }

    #[test]
    fn rejects_invalid_boundary_evidence_locations() {
        let mut manifest = valid_manifest();
        manifest.modules[1].dependencies[0]
            .evidence
            .push(BoundaryEvidence {
                kind: BoundaryEvidenceKind::CxxGeneratedHeader,
                file: "services/network/bridge.cc".into(),
                line: 0,
                detail: "generated bridge header".into(),
            });

        let errors = manifest.validate().unwrap_err();
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::InvalidSourceLocation { kind, .. }
                if *kind == "boundary evidence"
        )));
    }

    #[test]
    fn rejects_incomplete_inventory_metadata() {
        let mut manifest = valid_manifest();
        manifest.inventory = Some(InventoryMetadata {
            source_format: "gn-project-json".into(),
            build_dir: String::new(),
            default_toolchain: "//build/toolchain/linux:clang_x64".into(),
            roots: vec![],
            include_all_toolchains: false,
            include_testonly: false,
            include_meta_targets: false,
            infer_state: false,
            omitted_dependency_count: 0,
        });

        let errors = manifest.validate().unwrap_err();
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::EmptyInventoryField { field } if *field == "build_dir"
        )));
    }
}
