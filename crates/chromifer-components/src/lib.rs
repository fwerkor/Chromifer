#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chromifer_manifest::{Boundary, Manifest, MigrationState, Module};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisOptions {
    pub path_depth: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self { path_depth: 2 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentAnalysis {
    pub baseline: String,
    pub path_depth: usize,
    pub module_count: usize,
    pub component_count: usize,
    pub components: Vec<ComponentSummary>,
    pub edges: Vec<ComponentEdge>,
    pub ranking: Vec<RankedCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentSummary {
    pub id: String,
    pub path: String,
    pub owner: String,
    pub scope: MigrationScope,
    pub modules: Vec<String>,
    pub source_files: usize,
    pub states: StateCounts,
    pub gates: Vec<String>,
    pub test_coverage: TestCoverageProxy,
    pub incoming_components: usize,
    pub outgoing_components: usize,
    pub unaudited_external_edges: usize,
    pub audited_external_edges: usize,
    pub rust_external_edges: usize,
    pub unresolved_reviews: usize,
    pub evidence_items: usize,
    pub external_owner_edges: usize,
    pub risk: RiskBreakdown,
    pub readiness_score: u32,
    pub eligible: bool,
    pub concerns: Vec<CandidateConcern>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RiskBreakdown {
    pub module_size: u32,
    pub source_size: u32,
    pub topology: u32,
    pub boundaries: u32,
    pub unresolved_reviews: u32,
    pub mixed_state: u32,
    pub missing_gates: u32,
    pub scope: u32,
    pub missing_target_coverage: u32,
    pub total: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct StateCounts {
    pub legacy_cpp: usize,
    pub bridged: usize,
    pub rust_owned: usize,
}

impl StateCounts {
    fn add(&mut self, state: MigrationState) {
        match state {
            MigrationState::LegacyCpp => self.legacy_cpp += 1,
            MigrationState::Bridged => self.bridged += 1,
            MigrationState::RustOwned => self.rust_owned += 1,
        }
    }

    pub fn is_mixed(self) -> bool {
        [self.legacy_cpp, self.bridged, self.rust_owned]
            .into_iter()
            .filter(|count| *count > 0)
            .count()
            > 1
    }

    pub fn is_fully_rust_owned(self) -> bool {
        self.rust_owned > 0 && self.legacy_cpp == 0 && self.bridged == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TestCoverageProxy {
    pub covered_module_target_pairs: usize,
    pub total_module_target_pairs: usize,
    pub basis_points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentEdge {
    pub from: String,
    pub to: String,
    pub module_edges: usize,
    pub boundaries: Vec<Boundary>,
    pub evidence_items: usize,
    pub unresolved_reviews: usize,
    pub crosses_owner: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RankedCandidate {
    pub rank: usize,
    pub component: String,
    pub path: String,
    pub owner: String,
    pub scope: MigrationScope,
    pub readiness_score: u32,
    pub risk_score: u32,
    pub eligible: bool,
    pub source_files: usize,
    pub module_count: usize,
    pub concerns: Vec<CandidateConcern>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CandidateConcern {
    NoSourceFiles,
    MissingCompatibilityGates,
    MissingRequiredTargetCoverage {
        missing_pairs: usize,
        total_pairs: usize,
    },
    MixedMigrationStates,
    DeferredScope {
        scope: MigrationScope,
    },
    UnresolvedReviews {
        count: usize,
    },
    UnauditedExternalEdges {
        count: usize,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("path depth must be at least 1")]
    ZeroPathDepth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationScope {
    BrowserService,
    ReusableInfrastructure,
    ProcessSecurityKernel,
    DeferredRuntime,
    Other,
}

impl fmt::Display for MigrationScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::BrowserService => "browser_service",
            Self::ReusableInfrastructure => "reusable_infrastructure",
            Self::ProcessSecurityKernel => "process_security_kernel",
            Self::DeferredRuntime => "deferred_runtime",
            Self::Other => "other",
        })
    }
}

#[derive(Debug)]
struct GroupDraft<'a> {
    path: String,
    owner: String,
    modules: Vec<&'a Module>,
}

#[derive(Debug, Default)]
struct EdgeDraft {
    module_edges: usize,
    boundaries: BTreeSet<Boundary>,
    evidence_items: usize,
    unresolved_reviews: usize,
}

#[derive(Debug, Clone, Default)]
struct IncidentMetrics {
    incoming_components: BTreeSet<String>,
    outgoing_components: BTreeSet<String>,
    unaudited_external_edges: usize,
    audited_external_edges: usize,
    rust_external_edges: usize,
    unresolved_reviews: usize,
    evidence_items: usize,
    external_owner_edges: usize,
}

pub fn analyze_components(
    manifest: &Manifest,
    options: &AnalysisOptions,
) -> Result<ComponentAnalysis, AnalysisError> {
    if options.path_depth == 0 {
        return Err(AnalysisError::ZeroPathDepth);
    }

    let groups = build_groups(manifest, options.path_depth);
    let component_ids = assign_component_ids(&groups);
    let module_to_component = map_modules_to_components(&groups, &component_ids);
    let component_owners: BTreeMap<_, _> = groups
        .iter()
        .zip(&component_ids)
        .map(|(group, id)| (id.clone(), group.owner.clone()))
        .collect();

    let (edges, incident) =
        build_component_edges(manifest, &module_to_component, &component_owners);

    let mut components = Vec::with_capacity(groups.len());
    for (group, id) in groups.iter().zip(&component_ids) {
        components.push(summarize_component(
            manifest,
            group,
            id,
            incident.get(id).cloned().unwrap_or_default(),
        ));
    }
    components.sort_by(|left, right| left.id.cmp(&right.id));

    let mut ranking: Vec<_> = components
        .iter()
        .filter(|component| !component.states.is_fully_rust_owned())
        .map(|component| RankedCandidate {
            rank: 0,
            component: component.id.clone(),
            path: component.path.clone(),
            owner: component.owner.clone(),
            scope: component.scope,
            readiness_score: component.readiness_score,
            risk_score: component.risk.total,
            eligible: component.eligible,
            source_files: component.source_files,
            module_count: component.modules.len(),
            concerns: component.concerns.clone(),
        })
        .collect();
    ranking.sort_by(|left, right| {
        right
            .eligible
            .cmp(&left.eligible)
            .then(right.readiness_score.cmp(&left.readiness_score))
            .then(left.risk_score.cmp(&right.risk_score))
            .then(left.source_files.cmp(&right.source_files))
            .then(left.component.cmp(&right.component))
    });
    for (index, candidate) in ranking.iter_mut().enumerate() {
        candidate.rank = index + 1;
    }

    Ok(ComponentAnalysis {
        baseline: manifest.project.baseline.clone(),
        path_depth: options.path_depth,
        module_count: manifest.modules.len(),
        component_count: components.len(),
        components,
        edges,
        ranking,
    })
}

fn build_groups(manifest: &Manifest, path_depth: usize) -> Vec<GroupDraft<'_>> {
    let mut grouped: BTreeMap<(String, String), Vec<&Module>> = BTreeMap::new();
    for module in &manifest.modules {
        let path = component_path(module, path_depth);
        grouped
            .entry((module_owner_key(module), path))
            .or_default()
            .push(module);
    }

    grouped
        .into_iter()
        .map(|((owner, path), mut modules)| {
            modules.sort_by(|left, right| left.id.cmp(&right.id));
            GroupDraft {
                path,
                owner,
                modules,
            }
        })
        .collect()
}

fn module_owner_key(module: &Module) -> String {
    module
        .ownership
        .as_ref()
        .filter(|ownership| !ownership.primary_owners.is_empty())
        .map(|ownership| ownership.primary_owners.join(","))
        .unwrap_or_else(|| module.owner.clone())
}

fn component_path(module: &Module, path_depth: usize) -> String {
    let path = usable_module_path(module);
    let segments: Vec<_> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    if segments.is_empty() {
        return module.id.clone();
    }
    segments[..segments.len().min(path_depth)].join("/")
}

fn usable_module_path(module: &Module) -> String {
    let path = normalize_path(&module.path);
    if path != "." && !path.is_empty() {
        return path;
    }
    if let Some(label) = &module.source_label {
        let base = label
            .split_once('(')
            .map_or(label.as_str(), |(base, _)| base)
            .trim_start_matches("//");
        let label_path = base.split_once(':').map_or(base, |(path, _)| path);
        if !label_path.is_empty() {
            return normalize_path(label_path);
        }
    }
    module.id.clone()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_matches('/')
        .trim_start_matches("./")
        .to_owned()
}

fn assign_component_ids(groups: &[GroupDraft<'_>]) -> Vec<String> {
    let mut base_counts = BTreeMap::new();
    for group in groups {
        *base_counts
            .entry(sanitize_id(&group.path))
            .or_insert(0_usize) += 1;
    }

    let mut used = BTreeSet::new();
    let mut ids = Vec::with_capacity(groups.len());
    for group in groups {
        let base = sanitize_id(&group.path);
        let mut candidate = if base_counts[&base] == 1 {
            base.clone()
        } else {
            format!("{}_{}", sanitize_id(&group.owner), base)
        };
        if used.contains(&candidate) {
            candidate = format!(
                "{candidate}_{:08x}",
                fnv1a_32(format!("{}:{}", group.owner, group.path).as_bytes())
            );
        }
        used.insert(candidate.clone());
        ids.push(candidate);
    }
    ids
}

fn sanitize_id(value: &str) -> String {
    let mut output = String::new();
    let mut separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            separator = false;
        } else if !output.is_empty() && !separator {
            output.push('_');
            separator = true;
        }
    }
    while output.ends_with('_') {
        output.pop();
    }
    if output.is_empty() {
        "component".into()
    } else if output.as_bytes()[0].is_ascii_digit() {
        format!("component_{output}")
    } else {
        output
    }
}

fn fnv1a_32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5_u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn map_modules_to_components(
    groups: &[GroupDraft<'_>],
    component_ids: &[String],
) -> BTreeMap<String, String> {
    groups
        .iter()
        .zip(component_ids)
        .flat_map(|(group, component)| {
            group
                .modules
                .iter()
                .map(move |module| (module.id.clone(), component.clone()))
        })
        .collect()
}

fn build_component_edges(
    manifest: &Manifest,
    module_to_component: &BTreeMap<String, String>,
    component_owners: &BTreeMap<String, String>,
) -> (Vec<ComponentEdge>, BTreeMap<String, IncidentMetrics>) {
    let mut drafts: BTreeMap<(String, String), EdgeDraft> = BTreeMap::new();
    let mut incident = BTreeMap::<String, IncidentMetrics>::new();

    for module in &manifest.modules {
        let Some(from) = module_to_component.get(&module.id) else {
            continue;
        };
        let local_module_reviews = module
            .reviews
            .iter()
            .filter(|review| !review.resolved)
            .count();
        incident.entry(from.clone()).or_default().unresolved_reviews += local_module_reviews;

        for dependency in &module.dependencies {
            let Some(to) = module_to_component.get(&dependency.module) else {
                continue;
            };
            let unresolved = dependency
                .reviews
                .iter()
                .filter(|review| !review.resolved)
                .count();
            let evidence = dependency.evidence.len();
            if from == to {
                let metrics = incident.entry(from.clone()).or_default();
                metrics.unresolved_reviews += unresolved;
                metrics.evidence_items += evidence;
                continue;
            }

            let draft = drafts.entry((from.clone(), to.clone())).or_default();
            draft.module_edges += 1;
            draft.boundaries.insert(dependency.boundary);
            draft.evidence_items += evidence;
            draft.unresolved_reviews += unresolved;
        }
    }

    let mut edges = Vec::with_capacity(drafts.len());
    for ((from, to), draft) in drafts {
        let crosses_owner = component_owners.get(&from) != component_owners.get(&to);
        let edge = ComponentEdge {
            from: from.clone(),
            to: to.clone(),
            module_edges: draft.module_edges,
            boundaries: draft.boundaries.iter().copied().collect(),
            evidence_items: draft.evidence_items,
            unresolved_reviews: draft.unresolved_reviews,
            crosses_owner,
        };

        apply_incident_edge(incident.entry(from.clone()).or_default(), &edge, true);
        apply_incident_edge(incident.entry(to.clone()).or_default(), &edge, false);
        edges.push(edge);
    }

    edges.sort_by(|left, right| left.from.cmp(&right.from).then(left.to.cmp(&right.to)));
    (edges, incident)
}

fn apply_incident_edge(metrics: &mut IncidentMetrics, edge: &ComponentEdge, outgoing: bool) {
    if outgoing {
        metrics.outgoing_components.insert(edge.to.clone());
    } else {
        metrics.incoming_components.insert(edge.from.clone());
    }
    for boundary in &edge.boundaries {
        match boundary {
            Boundary::Unclassified | Boundary::CppInternal => {
                metrics.unaudited_external_edges += 1;
            }
            Boundary::Cxx | Boundary::CAbi | Boundary::Mojo => {
                metrics.audited_external_edges += 1;
            }
            Boundary::Rust => metrics.rust_external_edges += 1,
        }
    }
    metrics.unresolved_reviews += edge.unresolved_reviews;
    metrics.evidence_items += edge.evidence_items;
    if edge.crosses_owner {
        metrics.external_owner_edges += 1;
    }
}

fn summarize_component(
    manifest: &Manifest,
    group: &GroupDraft<'_>,
    id: &str,
    incident: IncidentMetrics,
) -> ComponentSummary {
    let mut states = StateCounts::default();
    let mut gates = BTreeSet::new();
    let mut source_files = BTreeSet::new();
    for module in &group.modules {
        states.add(module.state);
        gates.extend(module.gates.iter().cloned());
        source_files.extend(module.sources.iter().cloned());
    }

    let test_coverage = test_coverage_proxy(manifest, &group.modules);
    let scope = migration_scope(&group.path);
    let mut concerns = Vec::new();
    if source_files.is_empty() {
        concerns.push(CandidateConcern::NoSourceFiles);
    }
    if gates.is_empty() {
        concerns.push(CandidateConcern::MissingCompatibilityGates);
    }
    if test_coverage.covered_module_target_pairs < test_coverage.total_module_target_pairs {
        concerns.push(CandidateConcern::MissingRequiredTargetCoverage {
            missing_pairs: test_coverage.total_module_target_pairs
                - test_coverage.covered_module_target_pairs,
            total_pairs: test_coverage.total_module_target_pairs,
        });
    }
    if states.is_mixed() {
        concerns.push(CandidateConcern::MixedMigrationStates);
    }
    if scope == MigrationScope::DeferredRuntime {
        concerns.push(CandidateConcern::DeferredScope { scope });
    }
    if incident.unresolved_reviews > 0 {
        concerns.push(CandidateConcern::UnresolvedReviews {
            count: incident.unresolved_reviews,
        });
    }
    if incident.unaudited_external_edges > 0 {
        concerns.push(CandidateConcern::UnauditedExternalEdges {
            count: incident.unaudited_external_edges,
        });
    }
    concerns.sort();

    let risk = calculate_risk(
        group.modules.len(),
        source_files.len(),
        states,
        &test_coverage,
        gates.is_empty(),
        scope,
        &incident,
    );
    let readiness_score = 100_u32.saturating_sub(risk.total);

    ComponentSummary {
        id: id.to_owned(),
        path: group.path.clone(),
        owner: group.owner.clone(),
        scope,
        modules: group
            .modules
            .iter()
            .map(|module| module.id.clone())
            .collect(),
        source_files: source_files.len(),
        states,
        gates: gates.into_iter().collect(),
        test_coverage,
        incoming_components: incident.incoming_components.len(),
        outgoing_components: incident.outgoing_components.len(),
        unaudited_external_edges: incident.unaudited_external_edges,
        audited_external_edges: incident.audited_external_edges,
        rust_external_edges: incident.rust_external_edges,
        unresolved_reviews: incident.unresolved_reviews,
        evidence_items: incident.evidence_items,
        external_owner_edges: incident.external_owner_edges,
        risk,
        readiness_score,
        eligible: concerns.is_empty(),
        concerns,
    }
}

fn test_coverage_proxy(manifest: &Manifest, modules: &[&Module]) -> TestCoverageProxy {
    let required_targets: Vec<_> = manifest
        .targets
        .iter()
        .filter(|target| target.required)
        .collect();
    let total_pairs = modules.len() * required_targets.len();
    if total_pairs == 0 {
        return TestCoverageProxy {
            covered_module_target_pairs: 0,
            total_module_target_pairs: 0,
            basis_points: 10_000,
        };
    }

    let mut covered_pairs = 0;
    for module in modules {
        for target in &required_targets {
            let covered = module.gates.iter().any(|gate_id| {
                manifest
                    .gate(gate_id)
                    .is_some_and(|gate| gate.targets.contains(&target.id))
            });
            covered_pairs += usize::from(covered);
        }
    }

    TestCoverageProxy {
        covered_module_target_pairs: covered_pairs,
        total_module_target_pairs: total_pairs,
        basis_points: ((covered_pairs as u64 * 10_000) / total_pairs as u64) as u32,
    }
}

fn calculate_risk(
    module_count: usize,
    source_files: usize,
    states: StateCounts,
    coverage: &TestCoverageProxy,
    no_gates: bool,
    scope: MigrationScope,
    incident: &IncidentMetrics,
) -> RiskBreakdown {
    let module_size = module_count.saturating_sub(1).saturating_mul(2).min(20) as u32;
    let source_size = source_files.div_ceil(10).min(15) as u32;
    let topology =
        (incident.incoming_components.len() + incident.outgoing_components.len()).min(20) as u32;
    let boundaries = incident
        .unaudited_external_edges
        .saturating_mul(8)
        .saturating_add(incident.audited_external_edges.saturating_mul(2))
        .saturating_add(incident.rust_external_edges)
        .min(40) as u32;
    let reviews = incident.unresolved_reviews.saturating_mul(10).min(40) as u32;
    let mixed_state = u32::from(states.is_mixed()) * 20;
    let missing_gate = u32::from(no_gates) * 15;
    let scope_penalty = match scope {
        MigrationScope::BrowserService => 0,
        MigrationScope::ReusableInfrastructure => 5,
        MigrationScope::ProcessSecurityKernel => 15,
        MigrationScope::DeferredRuntime => 40,
        MigrationScope::Other => 10,
    };
    let uncovered = coverage
        .total_module_target_pairs
        .saturating_sub(coverage.covered_module_target_pairs);
    let coverage_penalty = if coverage.total_module_target_pairs == 0 {
        0
    } else {
        (uncovered as u64 * 25).div_ceil(coverage.total_module_target_pairs as u64) as u32
    };

    let total = module_size
        .saturating_add(source_size)
        .saturating_add(topology)
        .saturating_add(boundaries)
        .saturating_add(reviews)
        .saturating_add(mixed_state)
        .saturating_add(missing_gate)
        .saturating_add(scope_penalty)
        .saturating_add(coverage_penalty)
        .min(100);

    RiskBreakdown {
        module_size,
        source_size,
        topology,
        boundaries,
        unresolved_reviews: reviews,
        mixed_state,
        missing_gates: missing_gate,
        scope: scope_penalty,
        missing_target_coverage: coverage_penalty,
        total,
    }
}

fn migration_scope(path: &str) -> MigrationScope {
    let first = path.split('/').next().unwrap_or(path);
    if path.starts_with("services/") {
        MigrationScope::BrowserService
    } else if matches!(first, "base" | "components" | "net" | "ui") {
        MigrationScope::ReusableInfrastructure
    } else if matches!(first, "chrome" | "content") {
        MigrationScope::ProcessSecurityKernel
    } else if path.starts_with("third_party/blink")
        || matches!(first, "v8" | "skia" | "gpu" | "media")
    {
        MigrationScope::DeferredRuntime
    } else {
        MigrationScope::Other
    }
}

#[cfg(test)]
mod tests {
    use chromifer_manifest::{
        BoundaryReview, BoundaryReviewKind, CompatibilityGate, Dependency, ModuleOwnership,
        Project, Target,
    };

    use super::*;

    fn module(
        id: &str,
        path: &str,
        owner: &str,
        state: MigrationState,
        sources: &[&str],
        gates: &[&str],
        dependencies: Vec<Dependency>,
    ) -> Module {
        Module {
            id: id.into(),
            path: path.into(),
            owner: owner.into(),
            ownership: None,
            source_label: None,
            source_type: None,
            sources: sources.iter().map(|source| (*source).into()).collect(),
            state,
            gates: gates.iter().map(|gate| (*gate).into()).collect(),
            reviews: vec![],
            dependencies,
        }
    }

    fn dependency(module: &str, boundary: Boundary) -> Dependency {
        Dependency {
            module: module.into(),
            boundary,
            evidence: vec![],
            reviews: vec![],
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "components fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture-baseline".into(),
            },
            inventory: None,
            targets: vec![
                Target {
                    id: "linux".into(),
                    description: "Linux".into(),
                    required: true,
                },
                Target {
                    id: "windows".into(),
                    description: "Windows".into(),
                    required: true,
                },
            ],
            gates: vec![
                CompatibilityGate {
                    id: "all".into(),
                    command: "tests".into(),
                    targets: vec!["linux".into(), "windows".into()],
                },
                CompatibilityGate {
                    id: "linux-only".into(),
                    command: "linux_tests".into(),
                    targets: vec!["linux".into()],
                },
            ],
            modules: vec![
                module(
                    "network_core",
                    "services/network/core",
                    "services",
                    MigrationState::Bridged,
                    &["services/network/core.cc"],
                    &["all"],
                    vec![dependency("base", Boundary::Cxx)],
                ),
                module(
                    "network_public",
                    "services/network/public",
                    "services",
                    MigrationState::Bridged,
                    &["services/network/public.h"],
                    &["all"],
                    vec![dependency("base", Boundary::Cxx)],
                ),
                module(
                    "storage",
                    "services/storage",
                    "services",
                    MigrationState::LegacyCpp,
                    &["services/storage/storage.cc"],
                    &["linux-only"],
                    vec![dependency("base", Boundary::CppInternal)],
                ),
                module(
                    "browser",
                    "content/browser",
                    "content",
                    MigrationState::LegacyCpp,
                    &["content/browser/browser.cc"],
                    &["all"],
                    vec![dependency("network_core", Boundary::Mojo)],
                ),
                module(
                    "base",
                    "base",
                    "foundation",
                    MigrationState::LegacyCpp,
                    &["base/base.cc"],
                    &["all"],
                    vec![],
                ),
            ],
        }
    }

    #[test]
    fn groups_targets_by_owner_and_path_prefix() {
        let analysis = analyze_components(&manifest(), &AnalysisOptions::default()).unwrap();
        assert_eq!(analysis.component_count, 4);
        let network = analysis
            .components
            .iter()
            .find(|component| component.id == "services_network")
            .unwrap();
        assert_eq!(network.modules, vec!["network_core", "network_public"]);
        assert_eq!(network.source_files, 2);
        assert_eq!(network.states.bridged, 2);
    }

    #[test]
    fn owner_difference_prevents_accidental_merging() {
        let mut manifest = manifest();
        manifest.modules.push(module(
            "vendor_network",
            "services/network/vendor",
            "vendor",
            MigrationState::LegacyCpp,
            &["services/network/vendor.cc"],
            &["all"],
            vec![],
        ));
        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        let matching: Vec<_> = analysis
            .components
            .iter()
            .filter(|component| component.path == "services/network")
            .collect();
        assert_eq!(matching.len(), 2);
        assert_ne!(matching[0].id, matching[1].id);
    }

    #[test]
    fn inferred_primary_owners_override_coarse_manifest_owner_for_grouping() {
        let mut manifest = manifest();
        manifest.modules[0].ownership = Some(ModuleOwnership {
            primary_owners: vec!["network@chromium.org".into()],
            effective_owners: vec!["network@chromium.org".into()],
            common_effective_owners: vec!["network@chromium.org".into()],
            owner_files: vec!["services/network/OWNERS".into()],
            unresolved_sources: vec![],
            split_ownership: false,
            sources: vec![],
        });
        manifest.modules[1].ownership = Some(ModuleOwnership {
            primary_owners: vec!["api@chromium.org".into()],
            effective_owners: vec!["api@chromium.org".into()],
            common_effective_owners: vec!["api@chromium.org".into()],
            owner_files: vec!["services/network/OWNERS".into()],
            unresolved_sources: vec![],
            split_ownership: false,
            sources: vec![],
        });

        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        let matching: Vec<_> = analysis
            .components
            .iter()
            .filter(|component| component.path == "services/network")
            .collect();
        assert_eq!(matching.len(), 2);
        assert!(
            matching
                .iter()
                .any(|component| component.owner == "network@chromium.org")
        );
        assert!(
            matching
                .iter()
                .any(|component| component.owner == "api@chromium.org")
        );
    }

    #[test]
    fn internal_edges_are_folded_and_external_edges_are_aggregated() {
        let mut manifest = manifest();
        manifest.modules[0]
            .dependencies
            .push(dependency("network_public", Boundary::CppInternal));
        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        assert_eq!(analysis.edges.len(), 3);
        assert!(
            !analysis
                .edges
                .iter()
                .any(|edge| { edge.from == "services_network" && edge.to == "services_network" })
        );
        let network_base = analysis
            .edges
            .iter()
            .find(|edge| edge.from == "services_network" && edge.to == "base")
            .unwrap();
        assert_eq!(network_base.module_edges, 2);
        assert_eq!(network_base.boundaries, vec![Boundary::Cxx]);
    }

    #[test]
    fn strict_test_proxy_counts_every_module_target_pair() {
        let analysis = analyze_components(&manifest(), &AnalysisOptions::default()).unwrap();
        let storage = analysis
            .components
            .iter()
            .find(|component| component.id == "services_storage")
            .unwrap();
        assert_eq!(storage.test_coverage.covered_module_target_pairs, 1);
        assert_eq!(storage.test_coverage.total_module_target_pairs, 2);
        assert_eq!(storage.test_coverage.basis_points, 5_000);
        assert!(storage.concerns.iter().any(|concern| matches!(
            concern,
            CandidateConcern::MissingRequiredTargetCoverage {
                missing_pairs: 1,
                total_pairs: 2
            }
        )));
    }

    #[test]
    fn unresolved_reviews_and_private_edges_reduce_readiness() {
        let mut manifest = manifest();
        manifest.modules[2].reviews.push(BoundaryReview {
            kind: BoundaryReviewKind::Observer,
            file: "services/storage/storage.cc".into(),
            line: 12,
            detail: "ObserverList<StorageObserver>".into(),
            resolved: false,
        });
        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        let storage = analysis
            .components
            .iter()
            .find(|component| component.id == "services_storage")
            .unwrap();
        assert!(!storage.eligible);
        assert_eq!(storage.unresolved_reviews, 1);
        assert_eq!(storage.unaudited_external_edges, 1);
        assert_eq!(storage.risk.unresolved_reviews, 10);
        assert_eq!(storage.risk.boundaries, 8);
        assert_eq!(storage.risk.missing_target_coverage, 13);
        assert!(storage.readiness_score < 70);
    }

    #[test]
    fn ready_audited_component_ranks_first() {
        let analysis = analyze_components(&manifest(), &AnalysisOptions::default()).unwrap();
        assert_eq!(analysis.ranking[0].component, "services_network");
        assert!(analysis.ranking[0].eligible);
        assert!(analysis.ranking[0].readiness_score > analysis.ranking[1].readiness_score);
    }

    #[test]
    fn fully_rust_owned_components_are_not_migration_candidates() {
        let mut manifest = manifest();
        manifest.modules[4].state = MigrationState::RustOwned;
        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        assert!(
            analysis.components.iter().any(|component| {
                component.id == "base" && component.states.is_fully_rust_owned()
            })
        );
        assert!(
            !analysis
                .ranking
                .iter()
                .any(|candidate| candidate.component == "base")
        );
    }

    #[test]
    fn deferred_runtime_is_never_marked_ready() {
        let mut manifest = manifest();
        manifest.modules.push(module(
            "blink_core",
            "third_party/blink/renderer",
            "web-runtime",
            MigrationState::LegacyCpp,
            &["third_party/blink/renderer/core.cc"],
            &["all"],
            vec![dependency("base", Boundary::Cxx)],
        ));
        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        let blink = analysis
            .components
            .iter()
            .find(|component| component.id == "third_party_blink")
            .unwrap();
        assert_eq!(blink.scope, MigrationScope::DeferredRuntime);
        assert!(!blink.eligible);
        assert!(blink.concerns.iter().any(|concern| matches!(
            concern,
            CandidateConcern::DeferredScope {
                scope: MigrationScope::DeferredRuntime
            }
        )));
    }

    #[test]
    fn root_targets_use_labels_or_ids_instead_of_collapsing_together() {
        let mut first = module(
            "hello",
            ".",
            "root",
            MigrationState::LegacyCpp,
            &["hello.cc"],
            &["all"],
            vec![],
        );
        first.source_label = Some("//:hello".into());
        let mut second = module(
            "hello_static",
            ".",
            "root",
            MigrationState::LegacyCpp,
            &["hello_static.cc"],
            &["all"],
            vec![],
        );
        second.source_label = Some("//:hello_static".into());
        let mut manifest = manifest();
        manifest.modules = vec![first, second];

        let analysis = analyze_components(&manifest, &AnalysisOptions::default()).unwrap();
        assert_eq!(analysis.component_count, 2);
        assert_eq!(
            analysis
                .components
                .iter()
                .map(|component| component.id.as_str())
                .collect::<Vec<_>>(),
            vec!["hello", "hello_static"]
        );
    }

    #[test]
    fn path_depth_changes_grouping_deterministically() {
        let manifest = manifest();
        let shallow = analyze_components(&manifest, &AnalysisOptions { path_depth: 1 }).unwrap();
        let deep = analyze_components(&manifest, &AnalysisOptions { path_depth: 3 }).unwrap();
        assert!(shallow.component_count < deep.component_count);
        assert_eq!(
            analyze_components(&manifest, &AnalysisOptions { path_depth: 3 }).unwrap(),
            deep
        );
    }

    #[test]
    fn rejects_zero_path_depth() {
        assert_eq!(
            analyze_components(&manifest(), &AnalysisOptions { path_depth: 0 }),
            Err(AnalysisError::ZeroPathDepth)
        );
    }
}
