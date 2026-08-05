#![forbid(unsafe_code)]

use chromifer_manifest::{Boundary, Manifest, MigrationState, Module};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransitionAssessment {
    pub module: String,
    pub from: MigrationState,
    pub to: MigrationState,
    pub allowed: bool,
    pub blockers: Vec<Blocker>,
    pub gate_count: usize,
    pub cross_language_edges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Blocker {
    InvalidTransition {
        expected: Option<MigrationState>,
    },
    MissingCompatibilityGates,
    MissingGateDefinition {
        gate: String,
    },
    UncoveredRequiredTarget {
        target: String,
    },
    UnsafeOutgoingBoundary {
        dependency: String,
        boundary: Boundary,
        dependency_state: MigrationState,
    },
    UnsafeIncomingBoundary {
        dependent: String,
        boundary: Boundary,
        dependent_state: MigrationState,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlannerError {
    #[error("unknown module `{0}`")]
    UnknownModule(String),
}

pub fn assess_transition(
    manifest: &Manifest,
    module_id: &str,
    target: MigrationState,
) -> Result<TransitionAssessment, PlannerError> {
    let module = manifest
        .module(module_id)
        .ok_or_else(|| PlannerError::UnknownModule(module_id.to_owned()))?;

    let mut blockers = Vec::new();
    if module.state.next() != Some(target) {
        blockers.push(Blocker::InvalidTransition {
            expected: module.state.next(),
        });
    }

    if module.gates.is_empty() {
        blockers.push(Blocker::MissingCompatibilityGates);
    }
    for gate in &module.gates {
        if manifest.gate(gate).is_none() {
            blockers.push(Blocker::MissingGateDefinition { gate: gate.clone() });
        }
    }
    for target in manifest.targets.iter().filter(|target| target.required) {
        let covered = module.gates.iter().any(|gate_id| {
            manifest
                .gate(gate_id)
                .is_some_and(|gate| gate.targets.contains(&target.id))
        });
        if !covered {
            blockers.push(Blocker::UncoveredRequiredTarget {
                target: target.id.clone(),
            });
        }
    }

    let mut cross_language_edges = 0;
    if target == MigrationState::RustOwned {
        assess_outgoing_boundaries(manifest, module, &mut blockers, &mut cross_language_edges);
        assess_incoming_boundaries(manifest, module, &mut blockers, &mut cross_language_edges);
    }

    Ok(TransitionAssessment {
        module: module.id.clone(),
        from: module.state,
        to: target,
        allowed: blockers.is_empty(),
        blockers,
        gate_count: module.gates.len(),
        cross_language_edges,
    })
}

pub fn migration_frontier(manifest: &Manifest) -> Vec<TransitionAssessment> {
    let mut frontier: Vec<_> = manifest
        .modules
        .iter()
        .filter_map(|module| {
            module
                .state
                .next()
                .and_then(|target| assess_transition(manifest, &module.id, target).ok())
        })
        .filter(|assessment| assessment.allowed)
        .collect();

    frontier.sort_by(|left, right| {
        left.cross_language_edges
            .cmp(&right.cross_language_edges)
            .then(left.gate_count.cmp(&right.gate_count))
            .then(left.module.cmp(&right.module))
    });
    frontier
}

fn assess_outgoing_boundaries(
    manifest: &Manifest,
    module: &Module,
    blockers: &mut Vec<Blocker>,
    cross_language_edges: &mut usize,
) {
    for dependency in &module.dependencies {
        let Some(target) = manifest.module(&dependency.module) else {
            continue;
        };
        if target.state == MigrationState::RustOwned {
            if dependency.boundary != Boundary::Rust {
                *cross_language_edges += 1;
            }
            continue;
        }

        *cross_language_edges += 1;
        if !dependency.boundary.is_audited_cross_language() {
            blockers.push(Blocker::UnsafeOutgoingBoundary {
                dependency: target.id.clone(),
                boundary: dependency.boundary,
                dependency_state: target.state,
            });
        }
    }
}

fn assess_incoming_boundaries(
    manifest: &Manifest,
    module: &Module,
    blockers: &mut Vec<Blocker>,
    cross_language_edges: &mut usize,
) {
    for dependent in &manifest.modules {
        for dependency in dependent
            .dependencies
            .iter()
            .filter(|dependency| dependency.module == module.id)
        {
            if dependent.state == MigrationState::RustOwned {
                if dependency.boundary != Boundary::Rust {
                    *cross_language_edges += 1;
                }
                continue;
            }

            *cross_language_edges += 1;
            if !dependency.boundary.is_audited_cross_language() {
                blockers.push(Blocker::UnsafeIncomingBoundary {
                    dependent: dependent.id.clone(),
                    boundary: dependency.boundary,
                    dependent_state: dependent.state,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use chromifer_manifest::{CompatibilityGate, Dependency, Module, Project, Target};

    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "Chromifer".into(),
                upstream: "chromium/src".into(),
                baseline: "main".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![CompatibilityGate {
                id: "unit".into(),
                command: "unit_tests".into(),
                targets: vec![],
            }],
            modules: vec![
                Module {
                    id: "base".into(),
                    path: "base".into(),
                    owner: "foundation".into(),
                    source_label: None,
                    source_type: None,
                    state: MigrationState::LegacyCpp,
                    gates: vec!["unit".into()],
                    dependencies: vec![],
                },
                Module {
                    id: "network".into(),
                    path: "services/network".into(),
                    owner: "services".into(),
                    source_label: None,
                    source_type: None,
                    state: MigrationState::Bridged,
                    gates: vec!["unit".into()],
                    dependencies: vec![Dependency {
                        module: "base".into(),
                        boundary: Boundary::Cxx,
                    }],
                },
                Module {
                    id: "browser".into(),
                    path: "content/browser".into(),
                    owner: "content".into(),
                    source_label: None,
                    source_type: None,
                    state: MigrationState::LegacyCpp,
                    gates: vec!["unit".into()],
                    dependencies: vec![Dependency {
                        module: "network".into(),
                        boundary: Boundary::Mojo,
                    }],
                },
            ],
        }
    }

    #[test]
    fn allows_bridged_module_with_audited_crossings_to_become_rust_owned() {
        let assessment =
            assess_transition(&manifest(), "network", MigrationState::RustOwned).unwrap();
        assert!(assessment.allowed);
        assert_eq!(assessment.cross_language_edges, 2);
    }

    #[test]
    fn blocks_private_cpp_incoming_boundary() {
        let mut manifest = manifest();
        manifest.modules[2].dependencies[0].boundary = Boundary::CppInternal;

        let assessment =
            assess_transition(&manifest, "network", MigrationState::RustOwned).unwrap();
        assert!(!assessment.allowed);
        assert!(assessment.blockers.iter().any(|blocker| matches!(
            blocker,
            Blocker::UnsafeIncomingBoundary { dependent, .. } if dependent == "browser"
        )));
    }

    #[test]
    fn blocks_unclassified_outgoing_boundary() {
        let mut manifest = manifest();
        manifest.modules[1].dependencies[0].boundary = Boundary::Unclassified;

        let assessment =
            assess_transition(&manifest, "network", MigrationState::RustOwned).unwrap();
        assert!(!assessment.allowed);
        assert!(assessment.blockers.iter().any(|blocker| matches!(
            blocker,
            Blocker::UnsafeOutgoingBoundary { dependency, boundary, .. }
                if dependency == "base" && *boundary == Boundary::Unclassified
        )));
    }

    #[test]
    fn frontier_only_contains_allowed_next_transitions() {
        let frontier = migration_frontier(&manifest());
        let modules: Vec<_> = frontier.iter().map(|item| item.module.as_str()).collect();
        assert_eq!(modules, vec!["base", "browser", "network"]);
    }

    #[test]
    fn rejects_skipped_transition() {
        let assessment = assess_transition(&manifest(), "base", MigrationState::RustOwned).unwrap();
        assert!(!assessment.allowed);
        assert!(
            assessment
                .blockers
                .iter()
                .any(|blocker| matches!(blocker, Blocker::InvalidTransition { .. }))
        );
    }

    #[test]
    fn blocks_transition_without_required_target_coverage() {
        let mut manifest = manifest();
        manifest.targets.push(Target {
            id: "windows".into(),
            description: "Windows desktop".into(),
            required: true,
        });

        let assessment =
            assess_transition(&manifest, "network", MigrationState::RustOwned).unwrap();
        assert!(!assessment.allowed);
        assert!(assessment.blockers.iter().any(|blocker| matches!(
            blocker,
            Blocker::UncoveredRequiredTarget { target } if target == "windows"
        )));
    }
}
