#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: u32,
    pub project: Project,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub gates: Vec<CompatibilityGate>,
    #[serde(default)]
    pub modules: Vec<Module>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub name: String,
    pub upstream: String,
    pub baseline: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub description: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityGate {
    pub id: String,
    pub command: String,
    #[serde(default)]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Module {
    pub id: String,
    pub path: String,
    pub owner: String,
    pub state: MigrationState,
    #[serde(default)]
    pub gates: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub module: String,
    pub boundary: Boundary,
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
    #[error("module `{module}` references unknown gate `{gate}`")]
    UnknownGate { module: String, gate: String },
    #[error("module `{module}` references unknown dependency `{dependency}`")]
    UnknownDependency { module: String, dependency: String },
    #[error("module `{module}` depends on itself")]
    SelfDependency { module: String },
    #[error("module `{module}` has duplicate dependency `{dependency}`")]
    DuplicateDependency { module: String, dependency: String },
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
            check_nonempty("gate", &gate.id, "command", &gate.command, &mut errors);
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

    pub fn module(&self, id: &str) -> Option<&Module> {
        self.modules.iter().find(|module| module.id == id)
    }

    pub fn gate(&self, id: &str) -> Option<&CompatibilityGate> {
        self.gates.iter().find(|gate| gate.id == id)
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
            targets: vec![Target {
                id: "linux".into(),
                description: "Linux desktop".into(),
                required: true,
            }],
            gates: vec![CompatibilityGate {
                id: "unit".into(),
                command: "autoninja -C out/Default unit_tests".into(),
                targets: vec!["linux".into()],
            }],
            modules: vec![
                Module {
                    id: "base".into(),
                    path: "base".into(),
                    owner: "foundation".into(),
                    state: MigrationState::LegacyCpp,
                    gates: vec![],
                    dependencies: vec![],
                },
                Module {
                    id: "network".into(),
                    path: "services/network".into(),
                    owner: "services".into(),
                    state: MigrationState::Bridged,
                    gates: vec!["unit".into()],
                    dependencies: vec![Dependency {
                        module: "base".into(),
                        boundary: Boundary::Cxx,
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
    fn reports_unknown_references() {
        let mut manifest = valid_manifest();
        manifest.modules[1].gates.push("missing".into());
        manifest.modules[1].dependencies.push(Dependency {
            module: "missing".into(),
            boundary: Boundary::Mojo,
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
}
