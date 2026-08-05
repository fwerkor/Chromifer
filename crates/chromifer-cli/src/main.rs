#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use chromifer_components::{
    AnalysisOptions, CandidateConcern, ComponentAnalysis, analyze_components,
};
use chromifer_evidence::{RunOptions, run_gates, verify_evidence};
use chromifer_gn::{GateOptions, ImportOptions, import_gn_file};
use chromifer_manifest::{Manifest, MigrationState};
use chromifer_owners::scan_ownership;
use chromifer_planner::{Blocker, assess_transition, migration_frontier};
use chromifer_source::scan_manifest;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "chromifer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Import a Chromium GN project JSON export into a migration manifest.
    ImportGn {
        project_json: PathBuf,
        output: PathBuf,
        /// Exact Chromium revision, tag, or other reproducible baseline identifier.
        #[arg(long)]
        baseline: String,
        /// Import only these roots and their transitive dependencies. Repeatable.
        #[arg(long = "root")]
        roots: Vec<String>,
        /// Include targets outside GN's default toolchain.
        #[arg(long)]
        all_toolchains: bool,
        /// Include GN targets marked test-only.
        #[arg(long)]
        include_testonly: bool,
        /// Preserve groups, actions, and other targets without compilable sources.
        #[arg(long)]
        include_meta_targets: bool,
        /// Infer legacy, bridged, and Rust-owned states from source extensions.
        #[arg(long)]
        infer_state: bool,
        /// Compatibility command assigned to imported modules.
        #[arg(long)]
        gate_command: Option<String>,
        #[arg(long, default_value = "imported-compatibility")]
        gate_id: String,
        #[arg(long, default_value = "import-host")]
        target_id: String,
        #[arg(long, default_value = "Host configuration used for the GN export")]
        target_description: String,
        #[arg(long, default_value = "Chromifer Chromium inventory")]
        project_name: String,
        #[arg(long, default_value = "https://chromium.googlesource.com/chromium/src")]
        upstream: String,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
        /// Print the import summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Scan imported source files and annotate dependency boundaries with evidence.
    ScanBoundaries {
        /// Input manifest containing module source lists.
        manifest: PathBuf,
        /// Chromium checkout root matching the manifest baseline.
        source_root: PathBuf,
        /// Annotated output manifest.
        output: PathBuf,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
        /// Print the scan summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Resolve Chromium OWNERS hierarchy for every module source file.
    ScanOwners {
        /// Input manifest containing module source lists.
        manifest: PathBuf,
        /// Chromium checkout root matching the manifest baseline.
        source_root: PathBuf,
        /// Ownership-annotated output manifest.
        output: PathBuf,
        /// Replace an existing output file.
        #[arg(long)]
        force: bool,
        /// Print the ownership summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Aggregate GN targets into migration components and rank candidates.
    RankComponents {
        /// Source-annotated migration manifest.
        manifest: PathBuf,
        /// Number of directory segments retained in each component anchor.
        #[arg(long, default_value_t = 2)]
        path_depth: usize,
        /// Maximum candidates printed in text mode. JSON always contains all candidates.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Print the full analysis as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Execute compatibility gates and write content-addressed evidence.
    RunGates {
        /// Migration manifest declaring compatibility gates.
        manifest: PathBuf,
        /// Working directory used for all gate commands.
        workdir: PathBuf,
        /// Directory receiving immutable evidence and log artifacts.
        output_dir: PathBuf,
        /// Run only these gate IDs. Repeatable.
        #[arg(long = "gate")]
        gates: Vec<String>,
        /// Run gates declared by these module IDs. Repeatable.
        #[arg(long = "module")]
        modules: Vec<String>,
        /// Stop after the first failed, timed out, or unlaunchable gate.
        #[arg(long)]
        fail_fast: bool,
        /// Per-gate timeout in seconds.
        #[arg(long, default_value_t = 3600)]
        timeout_seconds: u64,
        /// Maximum stdout/stderr tail bytes embedded in the evidence JSON.
        #[arg(long, default_value_t = 8192)]
        max_tail_bytes: usize,
        /// Print the complete evidence run as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify an evidence bundle and every referenced content-addressed log.
    VerifyEvidence {
        /// Manifest whose exact bytes and gate definitions must match the evidence.
        manifest: PathBuf,
        /// Content-addressed evidence JSON file.
        evidence: PathBuf,
        /// Root directory containing the evidence bundle's `logs/` paths.
        artifact_root: PathBuf,
        /// Print the verification summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Parse and structurally validate a migration manifest.
    Validate { manifest: PathBuf },
    /// Show all currently legal next migration transitions.
    Frontier {
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Explain whether a specific state transition is currently legal.
    CheckTransition {
        manifest: PathBuf,
        module: String,
        target: MigrationState,
        /// Verified evidence bundle used to prove declared gates passed.
        #[arg(long, requires = "artifact_root")]
        evidence: Option<PathBuf>,
        /// Root directory containing logs referenced by `--evidence`.
        #[arg(long, requires = "evidence")]
        artifact_root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::ImportGn {
            project_json,
            output,
            baseline,
            roots,
            all_toolchains,
            include_testonly,
            include_meta_targets,
            infer_state,
            gate_command,
            gate_id,
            target_id,
            target_description,
            project_name,
            upstream,
            force,
            json,
        } => {
            if output.exists() && !force {
                return Err(format!(
                    "output `{}` already exists; pass --force to replace it",
                    output.display()
                )
                .into());
            }
            let gate = gate_command.map(|command| GateOptions {
                id: gate_id,
                command,
                target_id,
                target_description,
            });
            let imported = import_gn_file(
                &project_json,
                &ImportOptions {
                    project_name,
                    upstream,
                    baseline,
                    roots,
                    include_all_toolchains: all_toolchains,
                    include_testonly,
                    include_meta_targets,
                    infer_state,
                    gate,
                },
            )?;
            let manifest = imported.manifest.to_toml_pretty()?;
            fs::write(&output, manifest)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&imported.summary)?);
            } else {
                println!(
                    "imported {} modules from {} selected GN targets into {}",
                    imported.summary.imported_modules,
                    imported.summary.selected_targets,
                    output.display()
                );
                println!(
                    "skipped: {} meta, {} test-only, {} other-toolchain; omitted {} dependency edge(s)",
                    imported.summary.skipped_meta_targets,
                    imported.summary.skipped_testonly_targets,
                    imported.summary.skipped_other_toolchain_targets,
                    imported.summary.omitted_dependencies.len()
                );
                for edge in &imported.summary.omitted_dependencies {
                    println!(
                        "  - {} -> {} ({})",
                        edge.target, edge.dependency, edge.reason
                    );
                }
            }
        }
        Command::ScanBoundaries {
            manifest,
            source_root,
            output,
            force,
            json,
        } => {
            if output.exists() && !force {
                return Err(format!(
                    "output `{}` already exists; pass --force to replace it",
                    output.display()
                )
                .into());
            }
            let manifest = Manifest::load(&manifest)?;
            let scanned = scan_manifest(&manifest, &source_root)?;
            fs::write(&output, scanned.manifest.to_toml_pretty()?)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&scanned.summary)?);
            } else {
                println!(
                    "scanned {} file(s) across {} module(s); updated {} boundary edge(s)",
                    scanned.summary.scanned_files,
                    scanned.summary.scanned_modules,
                    scanned.summary.updated_boundaries.len()
                );
                println!(
                    "reviews: {} edge, {} module; conflicts: {}; missing sources: {}",
                    scanned.summary.edge_reviews,
                    scanned.summary.module_reviews,
                    scanned.summary.conflicts.len(),
                    scanned.summary.missing_sources.len()
                );
                for update in &scanned.summary.updated_boundaries {
                    println!(
                        "  - {} -> {}: {} -> {} ({} evidence item(s))",
                        update.module,
                        update.dependency,
                        update.from,
                        update.to,
                        update.evidence_count
                    );
                }
                for conflict in &scanned.summary.conflicts {
                    let detected = conflict
                        .detected
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    println!(
                        "  - conflict {} -> {}: current {}, detected [{}]",
                        conflict.module, conflict.dependency, conflict.current, detected
                    );
                }
                for missing in &scanned.summary.missing_sources {
                    println!("  - missing {}: {}", missing.module, missing.file);
                }
                println!("wrote annotated manifest to {}", output.display());
            }
        }
        Command::ScanOwners {
            manifest,
            source_root,
            output,
            force,
            json,
        } => {
            if output.exists() && !force {
                return Err(format!(
                    "output `{}` already exists; pass --force to replace it",
                    output.display()
                )
                .into());
            }
            let manifest = Manifest::load(&manifest)?;
            let scanned = scan_ownership(&manifest, &source_root)?;
            fs::write(&output, scanned.manifest.to_toml_pretty()?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&scanned.summary)?);
            } else {
                println!(
                    "resolved ownership for {} of {} source file(s) across {} module(s)",
                    scanned.summary.resolved_sources,
                    scanned.summary.scanned_sources,
                    scanned.summary.scanned_modules
                );
                println!(
                    "read {} OWNERS file(s); unresolved sources: {}; split modules: {}; modules without sources: {}",
                    scanned.summary.owner_files_read,
                    scanned.summary.unresolved_sources,
                    scanned.summary.split_ownership_modules,
                    scanned.summary.modules_without_sources
                );
                println!("wrote ownership manifest to {}", output.display());
            }
        }
        Command::RankComponents {
            manifest,
            path_depth,
            limit,
            json,
        } => {
            let manifest = Manifest::load(&manifest)?;
            let analysis = analyze_components(&manifest, &AnalysisOptions { path_depth })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&analysis)?);
            } else {
                print_component_ranking(&analysis, limit);
            }
        }
        Command::RunGates {
            manifest,
            workdir,
            output_dir,
            gates,
            modules,
            fail_fast,
            timeout_seconds,
            max_tail_bytes,
            json,
        } => {
            let manifest_bytes = fs::read(&manifest)?;
            let manifest = Manifest::load(&manifest)?;
            let run = run_gates(
                &manifest,
                &manifest_bytes,
                &RunOptions {
                    workdir,
                    output_dir,
                    gate_ids: gates,
                    module_ids: modules,
                    fail_fast,
                    timeout: Duration::from_secs(timeout_seconds),
                    max_tail_bytes,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&run)?);
            } else {
                println!("evidence {}: {}", run.digest, run.path.display());
                for gate in &run.bundle.gates {
                    println!(
                        "  - {}: {:?} exit={:?} duration={}ms",
                        gate.gate, gate.status, gate.exit_code, gate.duration_ms
                    );
                }
                for gate in &run.bundle.skipped_gates {
                    println!("  - {gate}: skipped by fail-fast");
                }
            }
            if !run.bundle.passed {
                return Err(format!(
                    "one or more compatibility gates failed; evidence was written to {}",
                    run.path.display()
                )
                .into());
            }
        }
        Command::VerifyEvidence {
            manifest,
            evidence,
            artifact_root,
            json,
        } => {
            let manifest_bytes = fs::read(&manifest)?;
            let manifest = Manifest::load(&manifest)?;
            let summary = verify_evidence(&manifest, &manifest_bytes, &evidence, &artifact_root)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "verified evidence {}: {} gate result(s), {} distinct log artifact(s), passed={}",
                    summary.digest, summary.gate_count, summary.log_count, summary.passed
                );
            }
        }
        Command::Validate { manifest } => {
            let manifest = Manifest::load(&manifest)?;
            println!(
                "valid: {} modules, {} gates, baseline {}",
                manifest.modules.len(),
                manifest.gates.len(),
                manifest.project.baseline
            );
        }
        Command::Frontier { manifest, json } => {
            let manifest = Manifest::load(&manifest)?;
            let frontier = migration_frontier(&manifest);
            if json {
                println!("{}", serde_json::to_string_pretty(&frontier)?);
            } else if frontier.is_empty() {
                println!("no legal migration transitions");
            } else {
                for candidate in frontier {
                    println!(
                        "{}: {} -> {} ({} gate(s), {} cross-language edge(s))",
                        candidate.module,
                        candidate.from,
                        candidate.to,
                        candidate.gate_count,
                        candidate.cross_language_edges
                    );
                }
            }
        }
        Command::CheckTransition {
            manifest,
            module,
            target,
            evidence,
            artifact_root,
            json,
        } => {
            let manifest_bytes = fs::read(&manifest)?;
            let manifest = Manifest::load(&manifest)?;
            let assessment = assess_transition(&manifest, &module, target)?;
            let verification = match (evidence, artifact_root) {
                (Some(evidence), Some(artifact_root)) => Some(verify_evidence(
                    &manifest,
                    &manifest_bytes,
                    &evidence,
                    &artifact_root,
                )?),
                (None, None) => None,
                _ => return Err("--evidence and --artifact-root must be supplied together".into()),
            };
            let missing_gate_evidence =
                if target == MigrationState::RustOwned && verification.is_some() {
                    let passed: std::collections::BTreeSet<_> = verification
                        .as_ref()
                        .map(|summary| summary.passed_gates.iter().cloned().collect())
                        .unwrap_or_default();
                    manifest
                        .module(&module)
                        .into_iter()
                        .flat_map(|module| module.gates.iter())
                        .filter(|gate| !passed.contains(*gate))
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
            let allowed = assessment.allowed && missing_gate_evidence.is_empty();

            if json {
                if let Some(verification) = verification {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "transition": assessment,
                            "evidence": verification,
                            "missing_gate_evidence": missing_gate_evidence,
                            "allowed": allowed,
                        }))?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&assessment)?);
                }
            } else {
                println!(
                    "{}: {} -> {}: {}",
                    assessment.module,
                    assessment.from,
                    assessment.to,
                    if allowed { "allowed" } else { "blocked" }
                );
                for blocker in &assessment.blockers {
                    println!("  - {}", display_blocker(blocker));
                }
                for gate in &missing_gate_evidence {
                    println!("  - compatibility gate `{gate}` lacks verified passing evidence");
                }
            }
            if !allowed {
                return Err("transition is blocked".into());
            }
        }
    }
    Ok(())
}

fn print_component_ranking(analysis: &ComponentAnalysis, limit: usize) {
    println!(
        "aggregated {} modules into {} components at path depth {}",
        analysis.module_count, analysis.component_count, analysis.path_depth
    );
    if analysis.ranking.is_empty() {
        println!("no non-Rust-owned migration candidates");
        return;
    }

    for candidate in analysis.ranking.iter().take(limit) {
        println!(
            "{}. {} [{}] score={} risk={} modules={} sources={} scope={} owner={}",
            candidate.rank,
            candidate.component,
            if candidate.eligible { "ready" } else { "audit" },
            candidate.readiness_score,
            candidate.risk_score,
            candidate.module_count,
            candidate.source_files,
            candidate.scope,
            candidate.owner
        );
        for concern in &candidate.concerns {
            println!("   - {}", display_concern(concern));
        }
    }
}

fn display_concern(concern: &CandidateConcern) -> String {
    match concern {
        CandidateConcern::NoSourceFiles => "component has no source files".into(),
        CandidateConcern::MissingCompatibilityGates => {
            "component has no compatibility gates".into()
        }
        CandidateConcern::MissingRequiredTargetCoverage {
            missing_pairs,
            total_pairs,
        } => format!(
            "compatibility gates miss {missing_pairs} of {total_pairs} required module-target pairs"
        ),
        CandidateConcern::MixedMigrationStates => {
            "component mixes legacy_cpp, bridged, or rust_owned modules".into()
        }
        CandidateConcern::DeferredScope { scope } => {
            format!("component belongs to explicitly deferred scope `{scope}`")
        }
        CandidateConcern::UnresolvedReviews { count } => {
            format!("{count} callback/observer review(s) remain unresolved")
        }
        CandidateConcern::UnauditedExternalEdges { count } => {
            format!("{count} external boundary type(s) remain private or unclassified")
        }
    }
}

fn display_blocker(blocker: &Blocker) -> String {
    match blocker {
        Blocker::InvalidTransition { expected } => match expected {
            Some(state) => format!("invalid state jump; next legal state is {state}"),
            None => "module is already rust_owned".into(),
        },
        Blocker::MissingCompatibilityGates => "no compatibility gates declared".into(),
        Blocker::MissingGateDefinition { gate } => {
            format!("compatibility gate `{gate}` is not defined")
        }
        Blocker::UncoveredRequiredTarget { target } => {
            format!("required target `{target}` is not covered by a declared gate")
        }
        Blocker::UnsafeOutgoingBoundary {
            dependency,
            boundary,
            dependency_state,
        } => format!(
            "outgoing edge to `{dependency}` ({dependency_state}) uses unsafe boundary `{boundary}`"
        ),
        Blocker::UnsafeIncomingBoundary {
            dependent,
            boundary,
            dependent_state,
        } => format!(
            "incoming edge from `{dependent}` ({dependent_state}) uses unsafe boundary `{boundary}`"
        ),
        Blocker::UnresolvedModuleReview {
            review_kind,
            file,
            line,
        } => format!("unresolved {review_kind} review at {file}:{line}"),
        Blocker::UnresolvedOutgoingBoundaryReview {
            dependency,
            review_kind,
            file,
            line,
        } => format!(
            "outgoing edge to `{dependency}` has unresolved {review_kind} review at {file}:{line}"
        ),
        Blocker::UnresolvedIncomingBoundaryReview {
            dependent,
            review_kind,
            file,
            line,
        } => format!(
            "incoming edge from `{dependent}` has unresolved {review_kind} review at {file}:{line}"
        ),
    }
}
