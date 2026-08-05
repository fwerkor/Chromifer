#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use chromifer_manifest::{
    Manifest, ModuleOwnership, SourceOwnership, ValidationErrors, normalize_repo_relative_path,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwnershipScanSummary {
    pub scanned_modules: usize,
    pub scanned_sources: usize,
    pub owner_files_read: usize,
    pub resolved_sources: usize,
    pub unresolved_sources: usize,
    pub split_ownership_modules: usize,
    pub modules_without_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipScanOutput {
    pub manifest: Manifest,
    pub summary: OwnershipScanSummary,
}

#[derive(Debug, Error)]
pub enum OwnershipError {
    #[error("source root `{path}` is not an accessible directory: {source}")]
    InvalidSourceRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("source path `{path}` for module `{module}` escapes the source root")]
    InvalidSourcePath { module: String, path: String },
    #[error("failed to read OWNERS file `{path}`: {source}")]
    ReadOwners {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}:{line}: {message}")]
    Syntax {
        path: String,
        line: usize,
        message: String,
    },
    #[error("OWNERS include `{include}` from `{path}` does not exist")]
    MissingInclude { path: String, include: String },
    #[error("OWNERS include cycle detected: {cycle}")]
    IncludeCycle { cycle: String },
    #[error(transparent)]
    ManifestValidation(#[from] ValidationErrors),
}

#[derive(Debug, Clone)]
struct ParsedOwners {
    global: Vec<Directive>,
    per_file: Vec<PerFileRule>,
    global_noparent: bool,
}

#[derive(Debug, Clone)]
struct PerFileRule {
    pattern: String,
    directive: Directive,
}

#[derive(Debug, Clone)]
enum Directive {
    Owner(String),
    Include(String),
    NoParent,
}

#[derive(Debug, Clone, Default)]
struct LayerOwnership {
    owners: BTreeSet<String>,
    owner_files: BTreeSet<String>,
    stop_inheritance: bool,
}

struct Resolver {
    root: PathBuf,
    parsed: BTreeMap<PathBuf, ParsedOwners>,
    files_read: BTreeSet<PathBuf>,
}

pub fn scan_ownership(
    manifest: &Manifest,
    source_root: &Path,
) -> Result<OwnershipScanOutput, OwnershipError> {
    let root = source_root
        .canonicalize()
        .map_err(|source| OwnershipError::InvalidSourceRoot {
            path: source_root.display().to_string(),
            source,
        })?;
    if !root.is_dir() {
        return Err(OwnershipError::InvalidSourceRoot {
            path: source_root.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "path is not a directory",
            ),
        });
    }
    let mut resolver = Resolver {
        root,
        parsed: BTreeMap::new(),
        files_read: BTreeSet::new(),
    };
    let mut annotated = manifest.clone();
    let mut scanned_sources = 0;
    let mut resolved_sources = 0;
    let mut unresolved_sources = 0;
    let mut split_ownership_modules = 0;
    let mut modules_without_sources = 0;

    for module in &mut annotated.modules {
        if module.sources.is_empty() {
            module.ownership = None;
            modules_without_sources += 1;
            continue;
        }

        let mut sources = Vec::with_capacity(module.sources.len());
        for source in &module.sources {
            let relative = normalize_repo_relative_path(source).ok_or_else(|| {
                OwnershipError::InvalidSourcePath {
                    module: module.id.clone(),
                    path: source.clone(),
                }
            })?;
            scanned_sources += 1;
            let ownership = resolver.resolve_source(&relative)?;
            if ownership.effective_owners.is_empty() {
                unresolved_sources += 1;
            } else {
                resolved_sources += 1;
            }
            sources.push(ownership);
        }
        sources.sort_by(|left, right| left.source.cmp(&right.source));

        let ownership = summarize_module_ownership(sources);
        if ownership.split_ownership {
            split_ownership_modules += 1;
        }
        module.ownership = Some(ownership);
    }

    annotated.validate()?;
    Ok(OwnershipScanOutput {
        summary: OwnershipScanSummary {
            scanned_modules: manifest.modules.len(),
            scanned_sources,
            owner_files_read: resolver.files_read.len(),
            resolved_sources,
            unresolved_sources,
            split_ownership_modules,
            modules_without_sources,
        },
        manifest: annotated,
    })
}

impl Resolver {
    fn resolve_source(&mut self, source: &str) -> Result<SourceOwnership, OwnershipError> {
        let relative = PathBuf::from(source);
        let filename = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(source);
        let mut directory = relative
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        let mut primary_owners = BTreeSet::new();
        let mut effective_owners = BTreeSet::new();
        let mut owner_files = BTreeSet::new();
        let mut inheritance_stopped_at = None;
        let mut found_primary = false;

        loop {
            let owner_file = directory.join("OWNERS");
            if self.root.join(&owner_file).is_file() {
                let layer = self.evaluate_owner_file(&owner_file, filename)?;
                if !found_primary && !layer.owners.is_empty() {
                    primary_owners.extend(layer.owners.iter().cloned());
                    found_primary = true;
                }
                effective_owners.extend(layer.owners);
                owner_files.extend(layer.owner_files);
                if layer.stop_inheritance {
                    inheritance_stopped_at = Some(path_string(&owner_file));
                    break;
                }
            }

            if directory.as_os_str().is_empty() {
                break;
            }
            directory.pop();
        }

        Ok(SourceOwnership {
            source: source.to_owned(),
            primary_owners: primary_owners.into_iter().collect(),
            effective_owners: effective_owners.into_iter().collect(),
            owner_files: owner_files.into_iter().collect(),
            inheritance_stopped_at,
        })
    }

    fn evaluate_owner_file(
        &mut self,
        path: &Path,
        filename: &str,
    ) -> Result<LayerOwnership, OwnershipError> {
        let parsed = self.parse_file(path)?;
        let matched: Vec<_> = parsed
            .per_file
            .iter()
            .filter(|rule| glob_matches(&rule.pattern, filename))
            .map(|rule| rule.directive.clone())
            .collect();
        let per_file_noparent = matched
            .iter()
            .any(|directive| matches!(directive, Directive::NoParent));

        let mut directives = Vec::new();
        if !per_file_noparent {
            directives.extend(parsed.global);
        }
        directives.extend(
            matched
                .into_iter()
                .filter(|directive| !matches!(directive, Directive::NoParent)),
        );

        let mut stack = vec![path.to_path_buf()];
        let mut layer = self.resolve_directives(path, &directives, &mut stack)?;
        layer.stop_inheritance = parsed.global_noparent || per_file_noparent;
        layer.owner_files.insert(path_string(path));
        Ok(layer)
    }

    fn resolve_directives(
        &mut self,
        owner_file: &Path,
        directives: &[Directive],
        stack: &mut Vec<PathBuf>,
    ) -> Result<LayerOwnership, OwnershipError> {
        let mut result = LayerOwnership::default();
        for directive in directives {
            match directive {
                Directive::Owner(owner) => {
                    result.owners.insert(owner.clone());
                }
                Directive::Include(include) => {
                    let included = self.resolve_include(owner_file, include)?;
                    if let Some(position) = stack.iter().position(|item| item == &included) {
                        let mut cycle: Vec<_> = stack[position..]
                            .iter()
                            .map(|item| path_string(item))
                            .collect();
                        cycle.push(path_string(&included));
                        return Err(OwnershipError::IncludeCycle {
                            cycle: cycle.join(" -> "),
                        });
                    }
                    stack.push(included.clone());
                    let parsed = self.parse_file(&included)?;
                    let nested = self.resolve_directives(&included, &parsed.global, stack)?;
                    stack.pop();
                    result.owners.extend(nested.owners);
                    result.owner_files.extend(nested.owner_files);
                    result.owner_files.insert(path_string(&included));
                }
                Directive::NoParent => {}
            }
        }
        Ok(result)
    }

    fn resolve_include(&self, owner_file: &Path, include: &str) -> Result<PathBuf, OwnershipError> {
        let normalized = if let Some(root_relative) = include.strip_prefix("//") {
            normalize_join(Path::new(""), Path::new(root_relative))
        } else {
            normalize_join(
                owner_file.parent().unwrap_or_else(|| Path::new("")),
                Path::new(include),
            )
        }
        .ok_or_else(|| OwnershipError::MissingInclude {
            path: path_string(owner_file),
            include: include.to_owned(),
        })?;
        if !self.root.join(&normalized).is_file() {
            return Err(OwnershipError::MissingInclude {
                path: path_string(owner_file),
                include: include.to_owned(),
            });
        }
        Ok(normalized)
    }

    fn parse_file(&mut self, path: &Path) -> Result<ParsedOwners, OwnershipError> {
        if let Some(parsed) = self.parsed.get(path) {
            return Ok(parsed.clone());
        }
        let full = self.root.join(path);
        let content = fs::read_to_string(&full).map_err(|source| OwnershipError::ReadOwners {
            path: full.display().to_string(),
            source,
        })?;
        let parsed = parse_owners(path, &content)?;
        self.files_read.insert(path.to_path_buf());
        self.parsed.insert(path.to_path_buf(), parsed.clone());
        Ok(parsed)
    }
}

fn parse_owners(path: &Path, content: &str) -> Result<ParsedOwners, OwnershipError> {
    let mut global = Vec::new();
    let mut per_file = Vec::new();
    let mut global_noparent = false;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "set noparent" {
            global_noparent = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("per-file ") {
            let Some((pattern, directive)) = rest.split_once('=') else {
                return syntax(path, line_number, "per-file rule must contain `=`");
            };
            let pattern = pattern.trim();
            if pattern.is_empty()
                || pattern.contains('/')
                || pattern.contains('\\')
                || !pattern.chars().all(|character| {
                    character.is_ascii_alphanumeric() || "_-.*?".contains(character)
                })
            {
                return syntax(
                    path,
                    line_number,
                    "per-file glob must be a filename-only `*`/`?` pattern",
                );
            }
            per_file.push(PerFileRule {
                pattern: pattern.to_owned(),
                directive: parse_directive(path, line_number, directive.trim())?,
            });
            continue;
        }
        if line.starts_with("set ") {
            return syntax(path, line_number, "unknown `set` directive");
        }
        global.push(parse_directive(path, line_number, line)?);
    }

    Ok(ParsedOwners {
        global,
        per_file,
        global_noparent,
    })
}

fn parse_directive(path: &Path, line: usize, directive: &str) -> Result<Directive, OwnershipError> {
    if directive == "set noparent" {
        return Ok(Directive::NoParent);
    }
    if let Some(include) = directive.strip_prefix("file:") {
        let include = include.trim();
        if include.is_empty() {
            return syntax(path, line, "file include must name an OWNERS file");
        }
        return Ok(Directive::Include(include.to_owned()));
    }
    if directive == "*" || valid_owner(directive) {
        return Ok(Directive::Owner(directive.to_owned()));
    }
    syntax(
        path,
        line,
        "expected an email, `*`, `file:`, or `set noparent` directive",
    )
}

fn valid_owner(value: &str) -> bool {
    let Some((left, right)) = value.split_once('@') else {
        return false;
    };
    !left.is_empty()
        && !right.is_empty()
        && !right.contains('@')
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '+' | '%' | '.' | '@')
        })
}

fn summarize_module_ownership(sources: Vec<SourceOwnership>) -> ModuleOwnership {
    let mut primary_owners = BTreeSet::new();
    let mut effective_owners = BTreeSet::new();
    let mut owner_files = BTreeSet::new();
    let mut unresolved_sources = Vec::new();
    let mut distinct_primary = BTreeSet::new();
    let mut common: Option<BTreeSet<String>> = None;

    for source in &sources {
        primary_owners.extend(source.primary_owners.iter().cloned());
        effective_owners.extend(source.effective_owners.iter().cloned());
        owner_files.extend(source.owner_files.iter().cloned());
        if source.effective_owners.is_empty() {
            unresolved_sources.push(source.source.clone());
        } else {
            let current: BTreeSet<_> = source.effective_owners.iter().cloned().collect();
            common = Some(match common {
                None => current,
                Some(previous) => previous.intersection(&current).cloned().collect(),
            });
        }
        distinct_primary.insert(source.primary_owners.clone());
    }

    ModuleOwnership {
        primary_owners: primary_owners.into_iter().collect(),
        effective_owners: effective_owners.into_iter().collect(),
        common_effective_owners: common.unwrap_or_default().into_iter().collect(),
        owner_files: owner_files.into_iter().collect(),
        unresolved_sources,
        split_ownership: distinct_primary.len() > 1,
        sources,
    }
}

fn normalize_repo_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn normalize_join(base: &Path, relative: &Path) -> Option<PathBuf> {
    let mut normalized = normalize_repo_path(base)?;
    for component in relative.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(normalized)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut current = vec![false; value.len() + 1];
    current[0] = true;
    for token in pattern {
        let mut next = vec![false; value.len() + 1];
        match token {
            b'*' => {
                next[0] = current[0];
                for index in 1..=value.len() {
                    next[index] = current[index] || next[index - 1];
                }
            }
            b'?' => {
                next[1..].copy_from_slice(&current[..value.len()]);
            }
            literal => {
                for index in 1..=value.len() {
                    next[index] = current[index - 1] && *literal == value[index - 1];
                }
            }
        }
        current = next;
    }
    current[value.len()]
}

fn syntax<T>(path: &Path, line: usize, message: &str) -> Result<T, OwnershipError> {
    Err(OwnershipError::Syntax {
        path: path_string(path),
        line,
        message: message.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use chromifer_manifest::{MigrationState, Module, Project};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-owners-{}-{id}", std::process::id()));
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

    fn manifest(sources: &[&str]) -> Manifest {
        Manifest {
            schema_version: 1,
            project: Project {
                name: "owners fixture".into(),
                upstream: "fixture".into(),
                baseline: "fixture".into(),
            },
            inventory: None,
            targets: vec![],
            gates: vec![],
            modules: vec![Module {
                id: "module".into(),
                path: "services/network".into(),
                owner: "services".into(),
                ownership: None,
                source_label: None,
                source_type: None,
                sources: sources.iter().map(|source| (*source).into()).collect(),
                state: MigrationState::LegacyCpp,
                gates: vec![],
                reviews: vec![],
                dependencies: vec![],
            }],
        }
    }

    #[test]
    fn inherits_parent_owners_and_preserves_nearest_primary_owners() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write("services/OWNERS", "services@chromium.org\n");
        tree.write("services/network/OWNERS", "network@chromium.org\n");

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        assert_eq!(ownership.primary_owners, vec!["network@chromium.org"]);
        assert_eq!(
            ownership.effective_owners,
            vec![
                "network@chromium.org",
                "root@chromium.org",
                "services@chromium.org"
            ]
        );
        assert_eq!(output.summary.owner_files_read, 3);
    }

    #[test]
    fn global_noparent_stops_parent_inheritance() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            "set noparent\nnetwork@chromium.org\n",
        );

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let source = &output.manifest.modules[0]
            .ownership
            .as_ref()
            .unwrap()
            .sources[0];
        assert_eq!(source.effective_owners, vec!["network@chromium.org"]);
        assert_eq!(
            source.inheritance_stopped_at.as_deref(),
            Some("services/network/OWNERS")
        );
    }

    #[test]
    fn per_file_noparent_ignores_global_entries_in_the_same_file() {
        let tree = TempTree::new();
        tree.write("OWNERS", "root@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            "general@chromium.org\nper-file *.mojom=set noparent\nper-file *.mojom=ipc@chromium.org\n",
        );

        let output = scan_ownership(
            &manifest(&[
                "services/network/service.mojom",
                "services/network/context.cc",
            ]),
            &tree.root,
        )
        .unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        let mojom = ownership
            .sources
            .iter()
            .find(|source| source.source.ends_with(".mojom"))
            .unwrap();
        assert_eq!(mojom.effective_owners, vec!["ipc@chromium.org"]);
        let cpp = ownership
            .sources
            .iter()
            .find(|source| source.source.ends_with(".cc"))
            .unwrap();
        assert_eq!(
            cpp.effective_owners,
            vec!["general@chromium.org", "root@chromium.org"]
        );
        assert!(ownership.split_ownership);
    }

    #[test]
    fn resolves_relative_and_repository_root_includes() {
        let tree = TempTree::new();
        tree.write("SECURITY_OWNERS", "security@chromium.org\n");
        tree.write("services/SHARED_OWNERS", "shared@chromium.org\n");
        tree.write(
            "services/network/OWNERS",
            "file:../SHARED_OWNERS\nfile://SECURITY_OWNERS\n",
        );

        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        assert_eq!(
            output.manifest.modules[0]
                .ownership
                .as_ref()
                .unwrap()
                .effective_owners,
            vec!["security@chromium.org", "shared@chromium.org"]
        );
    }

    #[test]
    fn reports_missing_include_and_include_cycles() {
        let tree = TempTree::new();
        tree.write("services/network/OWNERS", "file://MISSING_OWNERS\n");
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::MissingInclude { .. })
        ));

        tree.write("services/network/OWNERS", "file://A_OWNERS\n");
        tree.write("A_OWNERS", "file://B_OWNERS\n");
        tree.write("B_OWNERS", "file://A_OWNERS\n");
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::IncludeCycle { .. })
        ));
    }

    #[test]
    fn unresolved_sources_are_recorded_without_failing() {
        let tree = TempTree::new();
        let output =
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root).unwrap();
        let ownership = output.manifest.modules[0].ownership.as_ref().unwrap();
        assert_eq!(
            ownership.unresolved_sources,
            vec!["services/network/context.cc"]
        );
        assert_eq!(output.summary.unresolved_sources, 1);
    }

    #[test]
    fn wildcard_matching_uses_filename_only_semantics() {
        assert!(glob_matches("*_messages?.h", "network_messages1.h"));
        assert!(!glob_matches("*_messages?.h", "network_messages.h"));
        assert!(glob_matches("*.mojom", "service.mojom"));
    }

    #[test]
    fn rejects_directory_spanning_per_file_globs() {
        let tree = TempTree::new();
        tree.write(
            "services/network/OWNERS",
            "per-file subdir/*.cc=owner@chromium.org\n",
        );
        assert!(matches!(
            scan_ownership(&manifest(&["services/network/context.cc"]), &tree.root),
            Err(OwnershipError::Syntax { .. })
        ));
    }

    #[test]
    fn rejects_missing_or_non_directory_source_roots() {
        let tree = TempTree::new();
        let missing = tree.root.join("missing");
        assert!(matches!(
            scan_ownership(&manifest(&["context.cc"]), &missing),
            Err(OwnershipError::InvalidSourceRoot { .. })
        ));

        let file = tree.root.join("not-a-directory");
        fs::write(&file, "fixture").unwrap();
        assert!(matches!(
            scan_ownership(&manifest(&["context.cc"]), &file),
            Err(OwnershipError::InvalidSourceRoot { .. })
        ));
    }
}
