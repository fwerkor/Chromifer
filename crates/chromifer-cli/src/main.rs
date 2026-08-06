#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use chromifer_build::{ConsumerOptions, GenerateOptions, generate_and_write};
use chromifer_cabi::{CAbiGenerateOptions, generate_and_write as generate_c_abi};
use chromifer_checkout::{CheckoutAuditOptions, audit_and_write as audit_checkout};
use chromifer_components::{
    AnalysisOptions, CandidateConcern, ComponentAnalysis, analyze_components,
};
use chromifer_evidence::{RunOptions, run_gates, verify_evidence, verify_evidence_with_workdir};
use chromifer_gates::{DeriveGateOptions, derive_and_write as derive_gates};
use chromifer_gn::{GateOptions, ImportOptions, import_gn_file};
use chromifer_manifest::{Manifest, MigrationState};
use chromifer_mojo::{MojoGenerateOptions, generate_and_write as generate_mojo};
use chromifer_owners::scan_ownership;
use chromifer_planner::{Blocker, assess_transition, migration_frontier};
use chromifer_safety::{AuditOptions, audit_and_write};
use chromifer_source::scan_manifest;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "chromifer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct GenerateGnArgs {
    /// Cargo.toml for a first-party Rust library.
    cargo_manifest: PathBuf,
    /// Must be BUILD.gn in the selected package root.
    output: PathBuf,
    /// Select a package when Cargo.toml is a virtual workspace manifest.
    #[arg(long)]
    package: Option<String>,
    /// Override the generated GN target name.
    #[arg(long)]
    target_name: Option<String>,
    /// Map an active Cargo dependency as `cargo_name=//gn:label`. Repeatable.
    #[arg(long = "dep")]
    dependencies: Vec<String>,
    /// Map a public Cargo dependency as `cargo_name=//gn:label`. Repeatable.
    #[arg(long = "public-dep")]
    public_dependencies: Vec<String>,
    /// Add a non-Cargo private GN dependency. Repeatable.
    #[arg(long = "gn-dep")]
    additional_deps: Vec<String>,
    /// Add a non-Cargo public GN dependency. Repeatable.
    #[arg(long = "gn-public-dep")]
    additional_public_deps: Vec<String>,
    /// Restrict GN visibility. Repeatable.
    #[arg(long)]
    visibility: Vec<String>,
    /// Enable a Cargo feature. Repeatable.
    #[arg(long = "feature")]
    features: Vec<String>,
    /// Do not enable the Cargo package's default feature set.
    #[arg(long)]
    no_default_features: bool,
    /// Include an additional package-relative Rust source. Repeatable.
    #[arg(long = "extra-source")]
    extra_sources: Vec<String>,
    /// Permit unsafe Rust even when no CXX bridge is detected.
    #[arg(long)]
    allow_unsafe: bool,
    /// Chromium repository package path, for example `//services/network/rust`.
    #[arg(long)]
    gn_package_path: Option<String>,
    /// Generate a C++ source_set with this target name.
    #[arg(long)]
    consumer_target: Option<String>,
    /// Package-relative C++ consumer source. Repeatable.
    #[arg(long = "consumer-source")]
    consumer_sources: Vec<String>,
    /// Package-relative generated C ABI or other boundary header. Repeatable.
    #[arg(long = "consumer-header")]
    consumer_headers: Vec<String>,
    /// Additional private GN dependency for the C++ consumer. Repeatable.
    #[arg(long = "consumer-dep")]
    consumer_deps: Vec<String>,
    /// Additional public GN dependency for the C++ consumer. Repeatable.
    #[arg(long = "consumer-public-dep")]
    consumer_public_deps: Vec<String>,
    /// Restrict C++ consumer visibility. Repeatable.
    #[arg(long = "consumer-visibility")]
    consumer_visibility: Vec<String>,
    /// Cargo executable used for metadata extraction.
    #[arg(long, default_value = "cargo")]
    cargo: PathBuf,
    /// Replace existing BUILD.gn and provenance files.
    #[arg(long, conflicts_with = "check")]
    force: bool,
    /// Verify generated files are current without modifying them.
    #[arg(long, conflicts_with = "force")]
    check: bool,
    /// Print generation summary as JSON.
    #[arg(long)]
    json: bool,
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
    /// Generate Chromium rust_static_library BUILD.gn from Cargo metadata.
    GenerateGn(Box<GenerateGnArgs>),
    /// Validate a Rust C ABI contract and generate its C header.
    GenerateCAbi {
        /// Rust package root containing `src/` and the contract.
        package_root: PathBuf,
        /// Explicit C ABI contract JSON inside the package root.
        contract: PathBuf,
        /// Generated .h file inside an existing package directory.
        output: PathBuf,
        /// Additional package-relative Rust source. Repeatable.
        #[arg(long = "extra-source")]
        extra_sources: Vec<String>,
        /// Replace existing header and provenance files.
        #[arg(long, conflicts_with = "check")]
        force: bool,
        /// Verify generated files are current without modifying them.
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Print generation summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Validate a multi-target Mojom contract and generate Chromium GN targets.
    GenerateMojo {
        /// Package root containing Mojom sources and the contract.
        package_root: PathBuf,
        /// Explicit multi-target Mojo contract JSON inside the package root.
        contract: PathBuf,
        /// Must be BUILD.gn in the package root.
        output: PathBuf,
        /// Replace existing BUILD.gn and provenance files.
        #[arg(long, conflicts_with = "check")]
        force: bool,
        /// Verify generated files are current without modifying them.
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Print generation summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Audit a Cargo workspace against an exact unsafe-code policy.
    AuditUnsafe {
        /// Cargo.toml for the workspace or standalone package.
        cargo_manifest: PathBuf,
        /// Unsafe policy JSON inside the Cargo workspace.
        policy: PathBuf,
        /// Deterministic audit report JSON inside the workspace.
        output: PathBuf,
        /// Cargo executable used for workspace metadata.
        #[arg(long, default_value = "cargo")]
        cargo: PathBuf,
        /// Replace an existing audit report.
        #[arg(long, conflicts_with = "check")]
        force: bool,
        /// Verify the committed audit report without modifying it.
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Print the audit summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Lock a Chromium checkout, gclient metadata, and generated GN outputs.
    AuditCheckout {
        /// Workspace root containing the source checkout and gclient metadata.
        workspace_root: PathBuf,
        /// Checkout contract JSON.
        contract: PathBuf,
        /// Deterministic checkout lock report JSON.
        output: PathBuf,
        /// Optional GN executable used to live-validate args and required targets.
        #[arg(long)]
        gn: Option<PathBuf>,
        /// Replace an existing checkout lock report.
        #[arg(long, conflicts_with = "check")]
        force: bool,
        /// Verify the committed checkout lock without modifying it.
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Print the audit summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Derive structured compatibility gates from committed build provenance.
    DeriveGates {
        /// Repository root used for every generated command and hashed input.
        repo_root: PathBuf,
        /// Source migration manifest receiving generated gate definitions.
        manifest: PathBuf,
        /// Gate contract selecting committed Rust, C ABI, Mojo, and unsafe provenance.
        contract: PathBuf,
        /// Generated migration manifest containing attached structured gates.
        output: PathBuf,
        /// Replace an existing generated manifest.
        #[arg(long, conflicts_with = "check")]
        force: bool,
        /// Verify the generated manifest without modifying it.
        #[arg(long, conflicts_with = "force")]
        check: bool,
        /// Print the derivation summary as JSON.
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
        /// Record Git revision, dirty state, submodules, and the Git executable identity.
        #[arg(long)]
        attest_checkout: bool,
        /// Require the attested checkout to be at this exact Git revision.
        #[arg(long, requires = "attest_checkout")]
        expected_revision: Option<String>,
        /// Refuse to run gates when the attested checkout is dirty.
        #[arg(long, requires = "attest_checkout")]
        require_clean_checkout: bool,
        /// Resolve and hash every direct gate executable before and after execution.
        #[arg(long)]
        attest_executables: bool,
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
        /// Re-check recorded checkout and executable identities against this live worktree.
        #[arg(long)]
        workdir: Option<PathBuf>,
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
        Command::GenerateGn(args) => {
            let GenerateGnArgs {
                cargo_manifest,
                output,
                package,
                target_name,
                dependencies,
                public_dependencies,
                additional_deps,
                additional_public_deps,
                visibility,
                features,
                no_default_features,
                extra_sources,
                allow_unsafe,
                gn_package_path,
                consumer_target,
                consumer_sources,
                consumer_headers,
                consumer_deps,
                consumer_public_deps,
                consumer_visibility,
                cargo,
                force,
                check,
                json,
            } = *args;
            let consumer_requested = consumer_target.is_some()
                || !consumer_sources.is_empty()
                || !consumer_headers.is_empty()
                || !consumer_deps.is_empty()
                || !consumer_public_deps.is_empty()
                || !consumer_visibility.is_empty();
            let consumer = if consumer_requested {
                Some(ConsumerOptions {
                    target_name: consumer_target
                        .ok_or("C++ consumer options require --consumer-target")?,
                    sources: consumer_sources,
                    required_headers: consumer_headers,
                    deps: consumer_deps,
                    public_deps: consumer_public_deps,
                    visibility: consumer_visibility,
                })
            } else {
                None
            };
            let generated = generate_and_write(&GenerateOptions {
                cargo,
                cargo_manifest,
                output,
                package,
                target_name,
                dependency_mappings: parse_dependency_mappings(&dependencies)?,
                public_dependency_mappings: parse_dependency_mappings(&public_dependencies)?,
                additional_deps,
                additional_public_deps,
                visibility,
                features,
                no_default_features,
                extra_sources,
                allow_unsafe,
                gn_package_path,
                consumer,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} and {} match Cargo metadata for {} {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.package,
                    generated.summary.version
                );
            } else {
                println!(
                    "generated {} and {} for {} {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.package,
                    generated.summary.version
                );
                println!(
                    "target {}: {} source(s), {} CXX binding(s), {} generated header(s), {} mapped dependency(ies), allow_unsafe={}",
                    generated.summary.target_name,
                    generated.summary.source_count,
                    generated.summary.cxx_binding_count,
                    generated.summary.generated_cxx_header_count,
                    generated.summary.mapped_dependency_count,
                    generated.summary.allow_unsafe
                );
                if let Some(consumer) = &generated.summary.consumer_target {
                    println!(
                        "consumer {consumer}: {} source(s)",
                        generated.summary.consumer_source_count
                    );
                }
            }
        }
        Command::GenerateCAbi {
            package_root,
            contract,
            output,
            extra_sources,
            force,
            check,
            json,
        } => {
            let generated = generate_c_abi(&CAbiGenerateOptions {
                package_root,
                contract,
                output,
                extra_sources,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} and {} match C ABI contract {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.contract
                );
            } else {
                println!(
                    "generated {} and {} from {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.contract
                );
                println!(
                    "validated {} exported symbol(s) across {} Rust source(s); guard={}",
                    generated.summary.symbol_count,
                    generated.summary.source_count,
                    generated.summary.header_guard
                );
            }
        }
        Command::GenerateMojo {
            package_root,
            contract,
            output,
            force,
            check,
            json,
        } => {
            let generated = generate_mojo(&MojoGenerateOptions {
                package_root,
                contract,
                output,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} and {} match Mojo contract {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.contract
                );
            } else {
                println!(
                    "generated {} and {} from {}",
                    generated.summary.output,
                    generated.summary.provenance,
                    generated.summary.contract
                );
                println!(
                    "validated {} Mojom target(s), {} source(s), {} import(s), and {} declaration(s) under {}",
                    generated.summary.target_count,
                    generated.summary.source_count,
                    generated.summary.import_count,
                    generated.summary.declaration_count,
                    generated.summary.gn_package_path
                );
            }
        }
        Command::AuditUnsafe {
            cargo_manifest,
            policy,
            output,
            cargo,
            force,
            check,
            json,
        } => {
            let generated = audit_and_write(&AuditOptions {
                cargo,
                cargo_manifest,
                policy,
                output,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} matches the workspace unsafe policy",
                    generated.summary.output
                );
            } else {
                println!(
                    "audited {} package(s): {} safe, {} bridge; wrote {}",
                    generated.summary.workspace_packages,
                    generated.summary.safe_packages,
                    generated.summary.bridge_packages,
                    generated.summary.output
                );
                println!(
                    "scanned {} Rust source(s), {} crate root(s), {} unsafe occurrence(s), and {} local allowance(s)",
                    generated.summary.source_files,
                    generated.summary.crate_roots,
                    generated.summary.unsafe_occurrences,
                    generated.summary.lint_allowances
                );
            }
        }
        Command::AuditCheckout {
            workspace_root,
            contract,
            output,
            gn,
            force,
            check,
            json,
        } => {
            let generated = audit_checkout(&CheckoutAuditOptions {
                workspace_root,
                contract,
                output,
                gn,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} matches checkout revision {}",
                    generated.summary.output, generated.summary.source_revision
                );
            } else {
                println!(
                    "locked checkout revision {}: clean={}, metadata_files={}, gn_outputs={}, required_targets={}",
                    generated.summary.source_revision,
                    generated.summary.source_clean,
                    generated.summary.metadata_files,
                    generated.summary.gn_outputs,
                    generated.summary.required_targets
                );
                println!("wrote {}", generated.summary.output);
            }
            if let Some(version) = &generated.summary.gn_version {
                println!(
                    "validated {} GN output(s) with GN {}",
                    generated.summary.gn_validated_outputs, version
                );
            }
        }
        Command::DeriveGates {
            repo_root,
            manifest,
            contract,
            output,
            force,
            check,
            json,
        } => {
            let generated = derive_gates(&DeriveGateOptions {
                repo_root,
                manifest,
                contract,
                output,
                force,
                check,
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&generated.summary)?);
            } else if generated.summary.checked {
                println!(
                    "current: {} matches gate contract {} and source manifest {}",
                    generated.summary.output,
                    generated.summary.contract,
                    generated.summary.source_manifest
                );
            } else {
                println!(
                    "generated {} from {} and {}",
                    generated.summary.output,
                    generated.summary.source_manifest,
                    generated.summary.contract
                );
                println!(
                    "derived {} gate(s), attached {} module(s), and declared {} hashed input(s)",
                    generated.summary.generated_gates,
                    generated.summary.attached_modules,
                    generated.summary.declared_inputs
                );
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
            attest_checkout,
            expected_revision,
            require_clean_checkout,
            attest_executables,
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
                    attest_checkout,
                    expected_revision,
                    require_clean_checkout,
                    attest_executables,
                },
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&run)?);
            } else {
                println!("evidence {}: {}", run.digest, run.path.display());
                if let Some(checkout) = &run.bundle.checkout {
                    if let Some(snapshot) = &checkout.before {
                        println!(
                            "  checkout: revision={} dirty={} submodules={}",
                            snapshot.revision,
                            snapshot.dirty,
                            snapshot.submodules.len()
                        );
                    }
                    if let Some(error) = &checkout.error {
                        println!("  checkout error: {error}");
                    }
                }
                for gate in &run.bundle.gates {
                    println!(
                        "  - {}: {:?} exit={:?} duration={}ms",
                        gate.gate, gate.status, gate.exit_code, gate.duration_ms
                    );
                    if let Some(executable) = &gate.executable {
                        println!(
                            "    executable: {} -> {} sha256={}",
                            executable.invocation_path,
                            executable.resolved_path,
                            executable.after.sha256
                        );
                    }
                }
                for gate in &run.bundle.skipped_gates {
                    println!("  - {gate}: skipped by fail-fast");
                }
            }
            if !run.bundle.passed {
                return Err(format!(
                    "compatibility evidence did not pass; evidence was written to {}",
                    run.path.display()
                )
                .into());
            }
        }
        Command::VerifyEvidence {
            manifest,
            evidence,
            artifact_root,
            workdir,
            json,
        } => {
            let manifest_bytes = fs::read(&manifest)?;
            let manifest = Manifest::load(&manifest)?;
            let summary = if let Some(workdir) = workdir.as_deref() {
                verify_evidence_with_workdir(
                    &manifest,
                    &manifest_bytes,
                    &evidence,
                    &artifact_root,
                    Some(workdir),
                )?
            } else {
                verify_evidence(&manifest, &manifest_bytes, &evidence, &artifact_root)?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!(
                    "verified evidence {}: {} gate result(s), {} distinct log artifact(s), passed={}, checkout_attested={}, executables_attested={}, live_attestation_verified={}",
                    summary.digest,
                    summary.gate_count,
                    summary.log_count,
                    summary.passed,
                    summary.checkout_attested,
                    summary.executables_attested,
                    summary.live_attestation_verified
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

fn parse_dependency_mappings(values: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut mappings = BTreeMap::new();
    for value in values {
        let Some((name, label)) = value.split_once('=') else {
            return Err(format!(
                "dependency mapping `{value}` must use cargo_name=//gn:label"
            ));
        };
        let name = name.trim();
        let label = label.trim();
        if name.is_empty() || label.is_empty() {
            return Err(format!(
                "dependency mapping `{value}` must use nonempty cargo_name=//gn:label"
            ));
        }
        if mappings.insert(name.to_owned(), label.to_owned()).is_some() {
            return Err(format!("duplicate dependency mapping for `{name}`"));
        }
    }
    Ok(mappings)
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
