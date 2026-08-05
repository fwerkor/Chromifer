#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use chromifer_manifest::{Manifest, MigrationState};
use chromifer_planner::{Blocker, assess_transition, migration_frontier};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "chromifer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
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
            json,
        } => {
            let manifest = Manifest::load(&manifest)?;
            let assessment = assess_transition(&manifest, &module, target)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&assessment)?);
            } else {
                println!(
                    "{}: {} -> {}: {}",
                    assessment.module,
                    assessment.from,
                    assessment.to,
                    if assessment.allowed {
                        "allowed"
                    } else {
                        "blocked"
                    }
                );
                for blocker in &assessment.blockers {
                    println!("  - {}", display_blocker(blocker));
                }
            }
            if !assessment.allowed {
                return Err("transition is blocked".into());
            }
        }
    }
    Ok(())
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
    }
}
