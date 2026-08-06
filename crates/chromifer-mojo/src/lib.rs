#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chromifer_manifest::normalize_repo_relative_path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const CONTRACT_SCHEMA_VERSION: u32 = 1;
const PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MojoGenerateOptions {
    pub package_root: PathBuf,
    pub contract: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedMojo {
    pub build_gn: String,
    pub provenance_json: String,
    pub summary: MojoGenerateSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MojoGenerateSummary {
    pub contract: String,
    pub output: String,
    pub provenance: String,
    pub gn_package_path: String,
    pub target_count: usize,
    pub source_count: usize,
    pub import_count: usize,
    pub declaration_count: usize,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MojoContract {
    pub schema_version: u32,
    pub gn_package_path: String,
    pub targets: Vec<MojoTargetContract>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MojoTargetContract {
    pub name: String,
    pub sources: Vec<String>,
    #[serde(default)]
    pub external_imports: BTreeMap<String, String>,
    #[serde(default)]
    pub parser_deps: Vec<String>,
    #[serde(default)]
    pub visibility: Vec<String>,
    #[serde(default)]
    pub testonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MojoProvenance {
    pub schema_version: u32,
    pub contract_sha256: String,
    pub contract_path: String,
    pub build_gn_sha256: String,
    pub build_gn_path: String,
    pub gn_package_path: String,
    pub targets: Vec<MojoTargetEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MojoTargetEvidence {
    pub name: String,
    pub cpp_label: String,
    pub rust_label: String,
    pub sources: Vec<MojoSourceEvidence>,
    pub imports: Vec<MojoImportEvidence>,
    pub declarations: Vec<MojoDeclarationEvidence>,
    pub public_deps: Vec<String>,
    pub parser_deps: Vec<String>,
    pub visibility: Vec<String>,
    pub testonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MojoSourceEvidence {
    pub source: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MojoImportEvidence {
    pub source: String,
    pub line: usize,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_label: Option<String>,
    pub local: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MojoDeclarationEvidence {
    pub source: String,
    pub line: usize,
    pub kind: MojoDeclarationKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MojoDeclarationKind {
    Interface,
    Struct,
    Union,
    Enum,
}

#[derive(Debug, Error)]
pub enum MojoError {
    #[error("package root `{path}` is not an accessible directory: {source}")]
    InvalidPackageRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("contract `{0}` must be a JSON file inside the package root")]
    InvalidContractPath(String),
    #[error("output `{0}` must be BUILD.gn in the package root")]
    InvalidOutputPath(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse contract JSON: {0}")]
    ParseContract(#[from] serde_json::Error),
    #[error("unsupported Mojo contract schema version {found}; supported version is {supported}")]
    UnsupportedContractSchema { found: u32, supported: u32 },
    #[error("Mojo contract contains no targets")]
    EmptyContract,
    #[error("invalid Chromium GN package path `{0}`")]
    InvalidGnPackagePath(String),
    #[error("invalid Mojo target name `{0}`")]
    InvalidTargetName(String),
    #[error("duplicate Mojo target `{0}`")]
    DuplicateTarget(String),
    #[error("Mojo targets `{first}` and `{second}` collide on generated GN target `{generated}`")]
    GeneratedTargetCollision {
        first: String,
        second: String,
        generated: String,
    },
    #[error("target `{0}` contains no .mojom sources")]
    EmptyTarget(String),
    #[error("invalid Mojom source path `{0}`")]
    InvalidSourcePath(String),
    #[error("Mojom source `{0}` does not exist")]
    MissingSource(String),
    #[error("Mojom source `{source_path}` is assigned to both `{first}` and `{second}`")]
    DuplicateSourceOwner {
        source_path: String,
        first: String,
        second: String,
    },
    #[error("invalid Mojom import path `{0}`")]
    InvalidImportPath(String),
    #[error("target `{target}` maps external import `{import}` to invalid GN label `{label}`")]
    InvalidImportMapping {
        target: String,
        import: String,
        label: String,
    },
    #[error("target `{target}` has duplicate normalized external import mapping `{import}`")]
    DuplicateImportMapping { target: String, import: String },
    #[error(
        "target `{target}` imports `{import}` at {source_path}:{line} without an external GN mapping"
    )]
    MissingImportMapping {
        target: String,
        import: String,
        source_path: String,
        line: usize,
    },
    #[error(
        "target `{target}` imports package-local Mojom source `{import}` at {source_path}:{line}, but that source is not assigned to any contract target"
    )]
    UnassignedLocalImport {
        target: String,
        import: String,
        source_path: String,
        line: usize,
    },
    #[error("target `{target}` declares unused external import mapping `{import}`")]
    UnusedImportMapping { target: String, import: String },
    #[error("Mojom source `{source_path}` imports itself at line {line}")]
    SelfImport { source_path: String, line: usize },
    #[error("invalid GN label `{0}`")]
    InvalidGnLabel(String),
    #[error("Mojom target dependency cycle detected: {0}")]
    DependencyCycle(String),
    #[error("duplicate declaration `{name}` in module `{module}` for target `{target}`")]
    DuplicateDeclaration {
        target: String,
        module: String,
        name: String,
    },
    #[error("{path}:{line}: {message}")]
    MojomSyntax {
        path: String,
        line: usize,
        message: String,
    },
    #[error("generated file `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("generated file `{0}` is missing or differs from the Mojo contract")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedMojom {
    module: Option<String>,
    imports: Vec<ParsedImport>,
    declarations: Vec<ParsedDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedImport {
    path: String,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDeclaration {
    kind: MojoDeclarationKind,
    name: String,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    kind: TokenKind,
    line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TokenKind {
    Ident(String),
    String(String),
    Punct(char),
}

pub fn generate_and_write(options: &MojoGenerateOptions) -> Result<GeneratedMojo, MojoError> {
    let generated = generate_mojo(options)?;
    let provenance = provenance_path(&options.output);
    if options.check {
        check_file(&options.output, generated.build_gn.as_bytes())?;
        check_file(&provenance, generated.provenance_json.as_bytes())?;
        return Ok(generated);
    }
    for path in [&options.output, &provenance] {
        if path.exists() && !options.force {
            return Err(MojoError::OutputExists(path.display().to_string()));
        }
    }
    write_file(&options.output, generated.build_gn.as_bytes())?;
    write_file(&provenance, generated.provenance_json.as_bytes())?;
    Ok(generated)
}

pub fn generate_mojo(options: &MojoGenerateOptions) -> Result<GeneratedMojo, MojoError> {
    let root = canonical_package_root(&options.package_root)?;
    let (contract_path, contract_relative) = package_file(&root, &options.contract)?;
    if contract_path.extension().and_then(|value| value.to_str()) != Some("json") {
        return Err(MojoError::InvalidContractPath(
            options.contract.display().to_string(),
        ));
    }
    let (output_path, output_relative) = package_output(&root, &options.output)?;

    let contract_bytes = read_file(&contract_path)?;
    let mut contract: MojoContract = serde_json::from_slice(&contract_bytes)?;
    validate_contract(&root, &mut contract)?;

    let mut source_owner = BTreeMap::new();
    for target in &contract.targets {
        for source in &target.sources {
            let canonical = package_import_path(&contract.gn_package_path, source);
            source_owner.insert(canonical, target.name.clone());
        }
    }

    let all_sources: BTreeSet<_> = contract
        .targets
        .iter()
        .flat_map(|target| target.sources.iter().cloned())
        .collect();
    let mut parsed_sources = BTreeMap::new();
    let mut source_hashes = BTreeMap::new();
    for source in all_sources {
        let bytes = read_file(&root.join(&source))?;
        source_hashes.insert(source.clone(), sha256_hex(&bytes));
        parsed_sources.insert(source.clone(), parse_mojom(&source, &bytes)?);
    }

    let mut target_evidence = Vec::new();
    let mut local_graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for target in &contract.targets {
        let mut sources = Vec::new();
        let mut imports = Vec::new();
        let mut declarations = Vec::new();
        let mut public_deps = BTreeSet::new();
        let mut used_external = BTreeSet::new();
        let mut declaration_names = BTreeSet::new();

        for source in &target.sources {
            let parsed = &parsed_sources[source];
            sources.push(MojoSourceEvidence {
                source: source.clone(),
                sha256: source_hashes[source].clone(),
                module: parsed.module.clone(),
            });
            for declaration in &parsed.declarations {
                let module = parsed.module.clone().unwrap_or_default();
                if !declaration_names.insert((module.clone(), declaration.name.clone())) {
                    return Err(MojoError::DuplicateDeclaration {
                        target: target.name.clone(),
                        module,
                        name: declaration.name.clone(),
                    });
                }
                declarations.push(MojoDeclarationEvidence {
                    source: source.clone(),
                    line: declaration.line,
                    kind: declaration.kind,
                    name: declaration.name.clone(),
                    module: parsed.module.clone(),
                });
            }
            for import in &parsed.imports {
                let import_path = normalize_import_path(&import.path)?;
                let current = package_import_path(&contract.gn_package_path, source);
                if import_path == current {
                    return Err(MojoError::SelfImport {
                        source_path: source.clone(),
                        line: import.line,
                    });
                }
                let (dependency_label, local) = if let Some(owner) = source_owner.get(&import_path)
                {
                    if owner == &target.name {
                        (None, true)
                    } else {
                        local_graph
                            .entry(target.name.clone())
                            .or_default()
                            .insert(owner.clone());
                        let label = format!(":{owner}");
                        public_deps.insert(label.clone());
                        (Some(label), true)
                    }
                } else {
                    if let Some(relative) =
                        package_relative_import(&contract.gn_package_path, &import_path)
                        && root.join(relative).is_file()
                    {
                        return Err(MojoError::UnassignedLocalImport {
                            target: target.name.clone(),
                            import: import_path,
                            source_path: source.clone(),
                            line: import.line,
                        });
                    }
                    let Some(label) = target.external_imports.get(&import_path) else {
                        return Err(MojoError::MissingImportMapping {
                            target: target.name.clone(),
                            import: import_path,
                            source_path: source.clone(),
                            line: import.line,
                        });
                    };
                    used_external.insert(import_path.clone());
                    public_deps.insert(label.clone());
                    (Some(label.clone()), false)
                };
                imports.push(MojoImportEvidence {
                    source: source.clone(),
                    line: import.line,
                    path: import_path,
                    dependency_label,
                    local,
                });
            }
        }

        for import in target.external_imports.keys() {
            if !used_external.contains(import) {
                return Err(MojoError::UnusedImportMapping {
                    target: target.name.clone(),
                    import: import.clone(),
                });
            }
        }

        sources.sort();
        imports.sort();
        declarations.sort();
        let mut public_deps: Vec<_> = public_deps.into_iter().collect();
        public_deps.sort_by(|left, right| gn_label_cmp(left, right));
        local_graph.entry(target.name.clone()).or_default();
        target_evidence.push(MojoTargetEvidence {
            name: target.name.clone(),
            cpp_label: absolute_label(&contract.gn_package_path, &target.name),
            rust_label: absolute_label(&contract.gn_package_path, &format!("{}_rust", target.name)),
            sources,
            imports,
            declarations,
            public_deps,
            parser_deps: target.parser_deps.clone(),
            visibility: target.visibility.clone(),
            testonly: target.testonly,
        });
    }
    reject_dependency_cycle(&local_graph)?;
    target_evidence.sort_by(|left, right| left.name.cmp(&right.name));

    let build_gn = render_build_gn(&target_evidence);
    let provenance = MojoProvenance {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        contract_sha256: sha256_hex(&contract_bytes),
        contract_path: contract_relative,
        build_gn_sha256: sha256_hex(build_gn.as_bytes()),
        build_gn_path: output_relative,
        gn_package_path: contract.gn_package_path.clone(),
        targets: target_evidence.clone(),
    };
    let provenance_json = format!("{}\n", serde_json::to_string_pretty(&provenance)?);
    let summary = MojoGenerateSummary {
        contract: contract_path.display().to_string(),
        output: output_path.display().to_string(),
        provenance: provenance_path(&output_path).display().to_string(),
        gn_package_path: contract.gn_package_path,
        target_count: target_evidence.len(),
        source_count: target_evidence
            .iter()
            .map(|target| target.sources.len())
            .sum(),
        import_count: target_evidence
            .iter()
            .map(|target| target.imports.len())
            .sum(),
        declaration_count: target_evidence
            .iter()
            .map(|target| target.declarations.len())
            .sum(),
        checked: options.check,
    };
    Ok(GeneratedMojo {
        build_gn,
        provenance_json,
        summary,
    })
}

fn validate_contract(root: &Path, contract: &mut MojoContract) -> Result<(), MojoError> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(MojoError::UnsupportedContractSchema {
            found: contract.schema_version,
            supported: CONTRACT_SCHEMA_VERSION,
        });
    }
    if contract.targets.is_empty() {
        return Err(MojoError::EmptyContract);
    }
    contract.gn_package_path = normalize_gn_package_path(&contract.gn_package_path)?;

    let mut target_names = BTreeSet::new();
    let mut generated_names = BTreeMap::new();
    let mut source_owner = BTreeMap::new();
    for target in &mut contract.targets {
        if !valid_target_name(&target.name) {
            return Err(MojoError::InvalidTargetName(target.name.clone()));
        }
        if !target_names.insert(target.name.clone()) {
            return Err(MojoError::DuplicateTarget(target.name.clone()));
        }
        for generated in generated_target_names(&target.name) {
            if let Some(previous) = generated_names.insert(generated.clone(), target.name.clone()) {
                return Err(MojoError::GeneratedTargetCollision {
                    first: previous,
                    second: target.name.clone(),
                    generated,
                });
            }
        }
        if target.sources.is_empty() {
            return Err(MojoError::EmptyTarget(target.name.clone()));
        }
        let mut normalized_sources = BTreeSet::new();
        for source in &target.sources {
            let normalized = normalize_mojom_source(source)?;
            if !root.join(&normalized).is_file() {
                return Err(MojoError::MissingSource(normalized));
            }
            if let Some(previous) = source_owner.insert(normalized.clone(), target.name.clone()) {
                return Err(MojoError::DuplicateSourceOwner {
                    source_path: normalized,
                    first: previous,
                    second: target.name.clone(),
                });
            }
            normalized_sources.insert(normalized);
        }
        target.sources = normalized_sources.into_iter().collect();

        let mut normalized_imports = BTreeMap::new();
        for (import, label) in &target.external_imports {
            let import = normalize_import_path(import)?;
            if !label.starts_with("//") || validate_label(label).is_err() {
                return Err(MojoError::InvalidImportMapping {
                    target: target.name.clone(),
                    import,
                    label: label.clone(),
                });
            }
            let label = canonical_gn_label(label);
            if normalized_imports.insert(import.clone(), label).is_some() {
                return Err(MojoError::DuplicateImportMapping {
                    target: target.name.clone(),
                    import,
                });
            }
        }
        target.external_imports = normalized_imports;
        target.parser_deps = normalize_labels(&target.parser_deps)?;
        target.visibility = normalize_labels(&target.visibility)?;
    }
    contract
        .targets
        .sort_by(|left, right| left.name.cmp(&right.name));
    Ok(())
}

fn parse_mojom(path: &str, bytes: &[u8]) -> Result<ParsedMojom, MojoError> {
    let text = String::from_utf8_lossy(bytes);
    let tokens = lex_mojom(path, &text)?;
    let mut module = None;
    let mut imports = Vec::new();
    let mut declarations = Vec::new();
    let mut index = 0;
    let mut brace_depth = 0usize;
    while index < tokens.len() {
        match &tokens[index].kind {
            TokenKind::Punct('{') => {
                brace_depth += 1;
                index += 1;
                continue;
            }
            TokenKind::Punct('}') => {
                if brace_depth == 0 {
                    return syntax(path, tokens[index].line, "unmatched closing brace");
                }
                brace_depth -= 1;
                index += 1;
                continue;
            }
            _ if brace_depth > 0 => {
                index += 1;
                continue;
            }
            _ => {}
        }

        let TokenKind::Ident(keyword) = &tokens[index].kind else {
            index += 1;
            continue;
        };
        match keyword.as_str() {
            "import" => {
                let Some(Token {
                    kind: TokenKind::String(import),
                    ..
                }) = tokens.get(index + 1)
                else {
                    return syntax(
                        path,
                        tokens[index].line,
                        "import must be followed by a quoted path",
                    );
                };
                if !matches!(
                    tokens.get(index + 2).map(|token| &token.kind),
                    Some(TokenKind::Punct(';'))
                ) {
                    return syntax(path, tokens[index].line, "import must end with `;`");
                }
                imports.push(ParsedImport {
                    path: import.clone(),
                    line: tokens[index].line,
                });
                index += 3;
            }
            "module" => {
                if module.is_some() {
                    return syntax(path, tokens[index].line, "multiple module declarations");
                }
                let mut parts = Vec::new();
                let mut cursor = index + 1;
                loop {
                    match tokens.get(cursor).map(|token| &token.kind) {
                        Some(TokenKind::Ident(part)) => {
                            parts.push(part.clone());
                            cursor += 1;
                        }
                        _ => {
                            return syntax(path, tokens[index].line, "invalid module declaration");
                        }
                    }
                    match tokens.get(cursor).map(|token| &token.kind) {
                        Some(TokenKind::Punct('.')) => cursor += 1,
                        Some(TokenKind::Punct(';')) => break,
                        _ => {
                            return syntax(path, tokens[index].line, "invalid module declaration");
                        }
                    }
                }
                module = Some(parts.join("."));
                index = cursor + 1;
            }
            "interface" | "struct" | "union" | "enum" => {
                let Some(Token {
                    kind: TokenKind::Ident(name),
                    ..
                }) = tokens.get(index + 1)
                else {
                    return syntax(
                        path,
                        tokens[index].line,
                        "declaration keyword must be followed by a name",
                    );
                };
                let kind = match keyword.as_str() {
                    "interface" => MojoDeclarationKind::Interface,
                    "struct" => MojoDeclarationKind::Struct,
                    "union" => MojoDeclarationKind::Union,
                    "enum" => MojoDeclarationKind::Enum,
                    _ => return syntax(path, tokens[index].line, "unsupported declaration"),
                };
                declarations.push(ParsedDeclaration {
                    kind,
                    name: name.clone(),
                    line: tokens[index].line,
                });
                index += 2;
            }
            _ => index += 1,
        }
    }
    if brace_depth != 0 {
        return syntax(
            path,
            text.lines().count().max(1),
            "unclosed declaration body",
        );
    }
    imports.sort_by(|left, right| {
        (left.path.as_str(), left.line).cmp(&(right.path.as_str(), right.line))
    });
    declarations.sort_by(|left, right| {
        (left.name.as_str(), left.kind, left.line).cmp(&(
            right.name.as_str(),
            right.kind,
            right.line,
        ))
    });
    Ok(ParsedMojom {
        module,
        imports,
        declarations,
    })
}

fn lex_mojom(path: &str, text: &str) -> Result<Vec<Token>, MojoError> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut line = 1;
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\r' => index += 1,
            b'\n' => {
                line += 1;
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start_line = line;
                index += 2;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes[index] == b'\n' {
                        line += 1;
                    }
                    if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                        index += 2;
                        closed = true;
                        break;
                    }
                    index += 1;
                }
                if !closed {
                    return syntax(path, start_line, "unterminated block comment");
                }
            }
            b'"' => {
                let start_line = line;
                index += 1;
                let mut value = String::new();
                let mut closed = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'"' => {
                            index += 1;
                            closed = true;
                            break;
                        }
                        b'\\' => {
                            let Some(escaped) = bytes.get(index + 1).copied() else {
                                return syntax(path, start_line, "unterminated string escape");
                            };
                            let character = match escaped {
                                b'"' => '"',
                                b'\\' => '\\',
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                _ => {
                                    return syntax(path, line, "unsupported string escape");
                                }
                            };
                            value.push(character);
                            index += 2;
                        }
                        b'\n' => {
                            return syntax(path, line, "newline in quoted string");
                        }
                        byte if byte.is_ascii() => {
                            value.push(byte as char);
                            index += 1;
                        }
                        _ => {
                            let Some(character) = text[index..].chars().next() else {
                                break;
                            };
                            value.push(character);
                            index += character.len_utf8();
                        }
                    }
                }
                if !closed {
                    return syntax(path, start_line, "unterminated quoted string");
                }
                tokens.push(Token {
                    kind: TokenKind::String(value),
                    line: start_line,
                });
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
                {
                    index += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Ident(text[start..index].to_owned()),
                    line,
                });
            }
            byte => {
                tokens.push(Token {
                    kind: TokenKind::Punct(byte as char),
                    line,
                });
                index += 1;
            }
        }
    }
    Ok(tokens)
}

fn render_build_gn(targets: &[MojoTargetEvidence]) -> String {
    let mut output = String::from(
        "# Generated by Chromifer from an explicit Mojo contract.\n# Re-run `chromifer generate-mojo` instead of editing this file.\n\nimport(\"//mojo/public/tools/bindings/mojom.gni\")\n",
    );
    for target in targets {
        output.push('\n');
        output.push_str(&format!("mojom(\"{}\") {{\n", escape_gn(&target.name)));
        render_list(
            &mut output,
            "sources",
            target.sources.iter().map(|source| source.source.as_str()),
        );
        if !target.public_deps.is_empty() {
            render_list(
                &mut output,
                "public_deps",
                target.public_deps.iter().map(String::as_str),
            );
        }
        if !target.parser_deps.is_empty() {
            render_list(
                &mut output,
                "parser_deps",
                target.parser_deps.iter().map(String::as_str),
            );
        }
        output.push_str("  generate_rust = true\n");
        if target.testonly {
            output.push_str("  testonly = true\n");
        }
        if !target.visibility.is_empty() {
            render_list(
                &mut output,
                "visibility",
                target.visibility.iter().map(String::as_str),
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

fn reject_dependency_cycle(graph: &BTreeMap<String, BTreeSet<String>>) -> Result<(), MojoError> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Visit {
        Visiting,
        Complete,
    }

    fn visit(
        node: &str,
        graph: &BTreeMap<String, BTreeSet<String>>,
        states: &mut BTreeMap<String, Visit>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        match states.get(node) {
            Some(Visit::Complete) => return None,
            Some(Visit::Visiting) => {
                let start = stack.iter().position(|entry| entry == node).unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.push(node.to_owned());
                return Some(cycle);
            }
            None => {}
        }
        states.insert(node.to_owned(), Visit::Visiting);
        stack.push(node.to_owned());
        if let Some(dependencies) = graph.get(node) {
            for dependency in dependencies {
                if let Some(cycle) = visit(dependency, graph, states, stack) {
                    return Some(cycle);
                }
            }
        }
        stack.pop();
        states.insert(node.to_owned(), Visit::Complete);
        None
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    for node in graph.keys() {
        if let Some(cycle) = visit(node, graph, &mut states, &mut stack) {
            return Err(MojoError::DependencyCycle(cycle.join(" -> ")));
        }
    }
    Ok(())
}

fn canonical_package_root(path: &Path) -> Result<PathBuf, MojoError> {
    path.canonicalize()
        .map_err(|source| MojoError::InvalidPackageRoot {
            path: path.display().to_string(),
            source,
        })
}

fn package_file(root: &Path, path: &Path) -> Result<(PathBuf, String), MojoError> {
    let canonical = path
        .canonicalize()
        .map_err(|_| MojoError::InvalidContractPath(path.display().to_string()))?;
    let relative = canonical
        .strip_prefix(root)
        .map_err(|_| MojoError::InvalidContractPath(path.display().to_string()))?;
    let relative = normalize_repo_relative_path(&relative.to_string_lossy())
        .ok_or_else(|| MojoError::InvalidContractPath(path.display().to_string()))?;
    Ok((canonical, relative))
}

fn package_output(root: &Path, path: &Path) -> Result<(PathBuf, String), MojoError> {
    if path.file_name().and_then(|value| value.to_str()) != Some("BUILD.gn") {
        return Err(MojoError::InvalidOutputPath(path.display().to_string()));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| MojoError::InvalidOutputPath(path.display().to_string()))?;
    if parent != root {
        return Err(MojoError::InvalidOutputPath(path.display().to_string()));
    }
    Ok((parent.join("BUILD.gn"), "BUILD.gn".to_owned()))
}

fn normalize_gn_package_path(value: &str) -> Result<String, MojoError> {
    let Some(relative) = value.strip_prefix("//") else {
        return Err(MojoError::InvalidGnPackagePath(value.to_owned()));
    };
    if relative.contains(':')
        || relative.contains('*')
        || !relative.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '/' | '_' | '-' | '.' | '+')
        })
    {
        return Err(MojoError::InvalidGnPackagePath(value.to_owned()));
    }
    if relative.is_empty() {
        return Ok("//".to_owned());
    }
    let normalized = normalize_repo_relative_path(relative)
        .ok_or_else(|| MojoError::InvalidGnPackagePath(value.to_owned()))?;
    Ok(format!("//{normalized}"))
}

fn normalize_mojom_source(value: &str) -> Result<String, MojoError> {
    let normalized = normalize_repo_relative_path(value)
        .ok_or_else(|| MojoError::InvalidSourcePath(value.to_owned()))?;
    if Path::new(&normalized)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("mojom")
    {
        return Err(MojoError::InvalidSourcePath(value.to_owned()));
    }
    Ok(normalized)
}

fn normalize_import_path(value: &str) -> Result<String, MojoError> {
    if value.contains('\\') {
        return Err(MojoError::InvalidImportPath(value.to_owned()));
    }
    let value = value.trim_start_matches("//");
    let normalized = normalize_repo_relative_path(value)
        .ok_or_else(|| MojoError::InvalidImportPath(value.to_owned()))?;
    if Path::new(&normalized)
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("mojom")
    {
        return Err(MojoError::InvalidImportPath(value.to_owned()));
    }
    Ok(normalized)
}

fn package_import_path(package: &str, source: &str) -> String {
    let package = package.trim_start_matches("//");
    if package.is_empty() {
        source.to_owned()
    } else {
        format!("{package}/{source}")
    }
}

fn package_relative_import<'a>(package: &str, import: &'a str) -> Option<&'a str> {
    let package = package.trim_start_matches("//");
    if package.is_empty() {
        return Some(import);
    }
    import.strip_prefix(package)?.strip_prefix('/')
}

fn absolute_label(package: &str, target: &str) -> String {
    format!("{package}:{target}")
}

fn normalize_labels(values: &[String]) -> Result<Vec<String>, MojoError> {
    let mut normalized = BTreeSet::new();
    for value in values {
        validate_label(value)?;
        normalized.insert(canonical_gn_label(value));
    }
    let mut values: Vec<_> = normalized.into_iter().collect();
    values.sort_by(|left, right| gn_label_cmp(left, right));
    Ok(values)
}

fn canonical_gn_label(value: &str) -> String {
    let Some((path, target)) = value.rsplit_once(':') else {
        return value.to_owned();
    };
    let basename = path.rsplit('/').next().unwrap_or("");
    if path.starts_with("//") && target == basename {
        path.to_owned()
    } else {
        value.to_owned()
    }
}

fn validate_label(value: &str) -> Result<(), MojoError> {
    if !(value.starts_with("//") || value.starts_with(':'))
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '/' | ':' | '_' | '-' | '.' | '*' | '+' | '(' | ')'
                )
        })
    {
        return Err(MojoError::InvalidGnLabel(value.to_owned()));
    }
    Ok(())
}

fn valid_target_name(value: &str) -> bool {
    !value.is_empty()
        && !value.as_bytes()[0].is_ascii_digit()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn generated_target_names(target: &str) -> Vec<String> {
    const SUFFIXES: &[&str] = &[
        "",
        "__is_mojom",
        "__check_deps_are_all_mojom",
        "__build_metadata",
        "__parser",
        "__parser_deps",
        "__parser_action",
        "__generate_message_ids",
        "_shared__generator",
        "_shared_cpp_sources",
        "_shared",
        "_mojolpm_proto",
        "__type_mappings",
        "__generator",
        "_headers",
        "_cpp_sources",
        "_mojolpm",
        "_java__generator",
        "_java_sources",
        "_java",
        "_js__generator",
        "_js",
        "_js_data_deps",
        "_js_library_for_compile",
        "_ts__generator",
        "_rust",
        "_rust_deps_meta",
        "_rust_meta",
        "_rust_dep_info",
        "_rust__generator",
        "_rust__crate_root",
    ];
    SUFFIXES
        .iter()
        .map(|suffix| format!("{target}{suffix}"))
        .collect()
}

fn gn_label_cmp(left: &str, right: &str) -> Ordering {
    let left_kind = usize::from(!left.starts_with(':'));
    let right_kind = usize::from(!right.starts_with(':'));
    left_kind.cmp(&right_kind).then(left.cmp(right))
}

fn escape_gn(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('$', "\\$")
        .replace('"', "\\\"")
}

fn syntax<T>(path: &str, line: usize, message: &str) -> Result<T, MojoError> {
    Err(MojoError::MojomSyntax {
        path: path.to_owned(),
        line,
        message: message.to_owned(),
    })
}

fn provenance_path(output: &Path) -> PathBuf {
    output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("chromifer-mojo.json")
}

fn read_file(path: &Path) -> Result<Vec<u8>, MojoError> {
    fs::read(path).map_err(|source| MojoError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), MojoError> {
    fs::write(path, bytes).map_err(|source| MojoError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), MojoError> {
    let actual = fs::read(path).map_err(|_| MojoError::Drift(path.display().to_string()))?;
    if actual != expected {
        return Err(MojoError::Drift(path.display().to_string()));
    }
    Ok(())
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
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, AtomicOrdering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-mojo-{}-{id}", std::process::id()));
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

    fn options(tree: &TempTree) -> MojoGenerateOptions {
        MojoGenerateOptions {
            package_root: tree.root.clone(),
            contract: tree.root.join("mojo.json"),
            output: tree.root.join("BUILD.gn"),
            force: false,
            check: false,
        }
    }

    fn write_two_target_fixture(tree: &TempTree) {
        tree.write(
            "common.mojom",
            "module chromifer.example;\nstruct Pair { int32 left; int32 right; };\n",
        );
        tree.write(
            "service.mojom",
            "// import in a comment must not count: import \"ignored.mojom\";\nmodule chromifer.example;\nimport \"examples/mojo/common.mojom\";\nimport \"mojo/public/mojom/base/time.mojom\";\ninterface Calculator { Add(Pair value) => (int32 result); };\n",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//examples/mojo",
                "targets": [
                    {
                        "name": "common",
                        "sources": ["common.mojom"]
                    },
                    {
                        "name": "service",
                        "sources": ["service.mojom"],
                        "external_imports": {
                            "mojo/public/mojom/base/time.mojom": "//mojo/public/mojom/base:base"
                        },
                        "visibility": ["//examples/mojo:*"]
                    }
                ]
            }))
            .unwrap(),
        );
    }

    #[test]
    fn generates_multiple_mojom_targets_and_resolves_imports() {
        let tree = TempTree::new();
        write_two_target_fixture(&tree);
        let generated = generate_and_write(&options(&tree)).unwrap();
        assert!(generated.build_gn.contains("mojom(\"common\")"));
        assert!(generated.build_gn.contains("mojom(\"service\")"));
        assert!(generated.build_gn.contains("generate_rust = true"));
        assert!(generated.build_gn.contains("\":common\""));
        assert!(generated.build_gn.contains("\"//mojo/public/mojom/base\""));
        assert_eq!(generated.summary.target_count, 2);
        assert_eq!(generated.summary.import_count, 2);
        assert_eq!(generated.summary.declaration_count, 2);

        let provenance: MojoProvenance = serde_json::from_str(&generated.provenance_json).unwrap();
        let service = provenance
            .targets
            .iter()
            .find(|target| target.name == "service")
            .unwrap();
        assert_eq!(service.cpp_label, "//examples/mojo:service");
        assert_eq!(service.rust_label, "//examples/mojo:service_rust");
        assert_eq!(
            service.public_deps,
            vec![":common", "//mojo/public/mojom/base"]
        );
        assert_eq!(service.imports[0].source, "service.mojom");
        assert!(tree.root.join("chromifer-mojo.json").is_file());
    }

    #[test]
    fn requires_exact_external_import_mappings() {
        let tree = TempTree::new();
        write_two_target_fixture(&tree);
        let mut contract: serde_json::Value =
            serde_json::from_slice(&fs::read(tree.root.join("mojo.json")).unwrap()).unwrap();
        contract["targets"][1]["external_imports"] = serde_json::json!({});
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::MissingImportMapping { import, .. })
                if import == "mojo/public/mojom/base/time.mojom"
        ));

        contract["targets"][1]["external_imports"] = serde_json::json!({
            "mojo/public/mojom/base/time.mojom": "//mojo/public/mojom/base:base",
            "unused/path.mojom": "//unused:target"
        });
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::UnusedImportMapping { import, .. }) if import == "unused/path.mojom"
        ));
    }

    #[test]
    fn rejects_existing_package_sources_that_are_not_assigned_to_a_target() {
        let tree = TempTree::new();
        tree.write("orphan.mojom", "struct Orphan {};\n");
        tree.write(
            "service.mojom",
            "import \"examples/mojo/orphan.mojom\";\ninterface Service {};\n",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//examples/mojo",
                "targets": [{"name": "service", "sources": ["service.mojom"]}]
            }))
            .unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::UnassignedLocalImport { import, .. })
                if import == "examples/mojo/orphan.mojom"
        ));
    }

    #[test]
    fn supports_targets_in_the_repository_root_package() {
        let tree = TempTree::new();
        tree.write("common.mojom", "struct Common {};\n");
        tree.write(
            "service.mojom",
            "import \"common.mojom\";\ninterface Service {};\n",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//",
                "targets": [
                    {"name": "common", "sources": ["common.mojom"]},
                    {"name": "service", "sources": ["service.mojom"]}
                ]
            }))
            .unwrap(),
        );
        let generated = generate_mojo(&options(&tree)).unwrap();
        let provenance: MojoProvenance = serde_json::from_str(&generated.provenance_json).unwrap();
        let service = provenance
            .targets
            .iter()
            .find(|target| target.name == "service")
            .unwrap();
        assert_eq!(service.cpp_label, "//:service");
        assert_eq!(service.public_deps, vec![":common"]);
    }

    #[test]
    fn rejects_local_dependency_cycles_and_duplicate_source_owners() {
        let tree = TempTree::new();
        tree.write(
            "a.mojom",
            "import \"examples/mojo/b.mojom\";\nstruct A {};\n",
        );
        tree.write(
            "b.mojom",
            "import \"examples/mojo/a.mojom\";\nstruct B {};\n",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//examples/mojo",
                "targets": [
                    {"name": "a", "sources": ["a.mojom"]},
                    {"name": "b", "sources": ["b.mojom"]}
                ]
            }))
            .unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::DependencyCycle(_))
        ));

        let contract = serde_json::json!({
            "schema_version": 1,
            "gn_package_path": "//examples/mojo",
            "targets": [
                {"name": "a", "sources": ["a.mojom"]},
                {"name": "b", "sources": ["a.mojom"]}
            ]
        });
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::DuplicateSourceOwner { source_path, .. }) if source_path == "a.mojom"
        ));
    }

    #[test]
    fn records_declarations_and_rejects_duplicates() {
        let tree = TempTree::new();
        tree.write(
            "types.mojom",
            "module example;\n[Stable] struct Value {};\nenum State { kReady };\nunion Choice { int32 number; };\ninterface Service {};\n",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//example",
                "targets": [{"name": "types", "sources": ["types.mojom"]}]
            }))
            .unwrap(),
        );
        let generated = generate_mojo(&options(&tree)).unwrap();
        let provenance: MojoProvenance = serde_json::from_str(&generated.provenance_json).unwrap();
        assert_eq!(provenance.targets[0].declarations.len(), 4);

        tree.write(
            "types.mojom",
            "module example;\nstruct Value {};\nenum Value { kReady };\n",
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::DuplicateDeclaration { name, .. }) if name == "Value"
        ));

        tree.write(
            "types.mojom",
            "module example;\ninterface First { enum State { kReady }; };\ninterface Second { enum State { kReady }; };\n",
        );
        let generated = generate_mojo(&options(&tree)).unwrap();
        let provenance: MojoProvenance = serde_json::from_str(&generated.provenance_json).unwrap();
        assert_eq!(provenance.targets[0].declarations.len(), 2);
        assert_eq!(provenance.targets[0].declarations[0].name, "First");
        assert_eq!(provenance.targets[0].declarations[1].name, "Second");
    }

    #[test]
    fn rejects_malformed_mojom_surface_syntax() {
        let tree = TempTree::new();
        tree.write(
            "bad.mojom",
            "module example\nimport missing;\n/* unterminated",
        );
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "//example",
                "targets": [{"name": "bad", "sources": ["bad.mojom"]}]
            }))
            .unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::MojomSyntax { .. })
        ));

        tree.write("bad.mojom", "import \"missing.mojom\"\ninterface Bad {};\n");
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::MojomSyntax { message, .. }) if message.contains("end with")
        ));

        tree.write("bad.mojom", "interface Bad {\n");
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::MojomSyntax { message, .. }) if message.contains("unclosed")
        ));
    }

    #[test]
    fn check_mode_detects_build_and_provenance_drift() {
        let tree = TempTree::new();
        write_two_target_fixture(&tree);
        generate_and_write(&options(&tree)).unwrap();
        let mut check = options(&tree);
        check.check = true;
        assert!(generate_and_write(&check).is_ok());
        fs::write(tree.root.join("BUILD.gn"), "changed").unwrap();
        assert!(matches!(
            generate_and_write(&check),
            Err(MojoError::Drift(_))
        ));
    }

    #[test]
    fn validates_paths_labels_and_target_names() {
        let tree = TempTree::new();
        tree.write("one.mojom", "struct One {};\n");
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "gn_package_path": "example",
                "targets": [{"name": "bad-name", "sources": ["one.mojom"]}]
            }))
            .unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::InvalidGnPackagePath(_))
        ));

        let contract = serde_json::json!({
            "schema_version": 1,
            "gn_package_path": "//example",
            "targets": [{"name": "bad-name", "sources": ["one.mojom"]}]
        });
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::InvalidTargetName(_))
        ));

        let contract = serde_json::json!({
            "schema_version": 1,
            "gn_package_path": "//example",
            "targets": [
                {"name": "api", "sources": ["one.mojom"]},
                {"name": "api_rust", "sources": ["two.mojom"]}
            ]
        });
        tree.write("two.mojom", "struct Two {};\n");
        tree.write(
            "mojo.json",
            &serde_json::to_string_pretty(&contract).unwrap(),
        );
        assert!(matches!(
            generate_mojo(&options(&tree)),
            Err(MojoError::GeneratedTargetCollision { generated, .. })
                if generated == "api_rust"
        ));
    }
}
