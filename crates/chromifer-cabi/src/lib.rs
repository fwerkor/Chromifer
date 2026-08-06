#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use chromifer_manifest::normalize_repo_relative_path;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::{Attribute, FnArg, Item, ItemFn, Pat, ReturnType, Type, TypePath, Visibility};
use thiserror::Error;

const CONTRACT_SCHEMA_VERSION: u32 = 1;
const PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CAbiGenerateOptions {
    pub package_root: PathBuf,
    pub contract: PathBuf,
    pub output: PathBuf,
    pub extra_sources: Vec<String>,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedCAbi {
    pub header: String,
    pub provenance_json: String,
    pub summary: CAbiGenerateSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CAbiGenerateSummary {
    pub contract: String,
    pub output: String,
    pub provenance: String,
    pub source_count: usize,
    pub symbol_count: usize,
    pub header_guard: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CAbiContract {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_guard: Option<String>,
    pub symbols: Vec<CAbiSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CAbiSymbol {
    pub name: String,
    pub return_type: AbiType,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parameters: Vec<CAbiParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CAbiParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub abi_type: AbiType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiType {
    Void,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    Isize,
    Usize,
    F32,
    F64,
    ConstI8Ptr,
    MutI8Ptr,
    ConstU8Ptr,
    MutU8Ptr,
    ConstVoidPtr,
    MutVoidPtr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CAbiProvenance {
    pub schema_version: u32,
    pub contract_sha256: String,
    pub contract_path: String,
    pub header_sha256: String,
    pub header_path: String,
    pub header_guard: String,
    pub sources: Vec<SourceDigest>,
    pub symbols: Vec<ExportEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct SourceDigest {
    pub source: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ExportEvidence {
    pub name: String,
    pub source: String,
    pub line: usize,
    pub unsafe_function: bool,
    pub return_type: AbiType,
    pub parameters: Vec<CAbiParameter>,
}

#[derive(Debug, Error)]
pub enum CAbiError {
    #[error("package root `{path}` is not an accessible directory: {source}")]
    InvalidPackageRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("contract `{0}` must be a JSON file inside the package root")]
    InvalidContractPath(String),
    #[error("output `{0}` must be a .h file inside an existing package directory")]
    InvalidOutputPath(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to inspect source directory `{path}`: {source}")]
    ReadDirectory {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse contract JSON: {0}")]
    ParseContract(#[from] serde_json::Error),
    #[error("unsupported contract schema version {found}; supported version is {supported}")]
    UnsupportedContractSchema { found: u32, supported: u32 },
    #[error("contract contains no symbols")]
    EmptyContract,
    #[error("invalid C identifier `{value}` in {field}")]
    InvalidIdentifier { field: &'static str, value: String },
    #[error("invalid header guard `{0}`")]
    InvalidHeaderGuard(String),
    #[error("duplicate contract symbol `{0}`")]
    DuplicateContractSymbol(String),
    #[error("symbol `{symbol}` has duplicate parameter `{parameter}`")]
    DuplicateParameter { symbol: String, parameter: String },
    #[error("void is only valid as a return type; found in `{symbol}` parameter `{parameter}`")]
    VoidParameter { symbol: String, parameter: String },
    #[error("default Rust source directory `{0}` does not exist; pass --extra-source")]
    MissingSourceDirectory(String),
    #[error("Rust source `{0}` is not a safe package-relative .rs path")]
    InvalidSourcePath(String),
    #[error("Rust source `{0}` does not exist")]
    MissingSource(String),
    #[error("failed to parse Rust source `{path}`: {source}")]
    ParseRust {
        path: String,
        #[source]
        source: syn::Error,
    },
    #[error("duplicate exported C symbol `{symbol}` at {first} and {second}")]
    DuplicateExport {
        symbol: String,
        first: String,
        second: String,
    },
    #[error("contract symbol `{0}` has no public no_mangle extern C definition")]
    MissingExport(String),
    #[error("exported C symbol `{0}` is absent from the contract")]
    UncontractedExport(String),
    #[error("exported symbol `{symbol}` at {file}:{line} is not public")]
    NonPublicExport {
        symbol: String,
        file: String,
        line: usize,
    },
    #[error("exported symbol `{symbol}` at {file}:{line} must use extern \"C\"")]
    UnsupportedExportAbi {
        symbol: String,
        file: String,
        line: usize,
    },
    #[error(
        "exported symbol `{symbol}` at {file}:{line} uses export_name; contracts require the Rust function name to equal the C symbol"
    )]
    UnsupportedExportName {
        symbol: String,
        file: String,
        line: usize,
    },
    #[error(
        "exported symbol `{symbol}` at {file}:{line} is conditionally compiled; one contract must describe one invariant ABI"
    )]
    ConditionalExport {
        symbol: String,
        file: String,
        line: usize,
    },
    #[error(
        "conditionally compiled external module `{module}` at {file}:{line} uses #[path], which cannot be resolved safely"
    )]
    ConditionalModulePath {
        module: String,
        file: String,
        line: usize,
    },
    #[error("exported symbol `{symbol}` uses unsupported Rust signature syntax at {file}:{line}")]
    UnsupportedRustSignature {
        symbol: String,
        file: String,
        line: usize,
    },
    #[error("ABI signature mismatch for `{symbol}`: contract {expected}; Rust {actual}")]
    SignatureMismatch {
        symbol: String,
        expected: String,
        actual: String,
    },
    #[error("generated file `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("generated file `{0}` is missing or differs from the contract")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiscoveredExport {
    evidence: ExportEvidence,
}

pub fn generate_and_write(options: &CAbiGenerateOptions) -> Result<GeneratedCAbi, CAbiError> {
    let generated = generate_c_abi(options)?;
    let provenance = provenance_path(&options.output);
    if options.check {
        check_file(&options.output, generated.header.as_bytes())?;
        check_file(&provenance, generated.provenance_json.as_bytes())?;
        return Ok(generated);
    }
    for path in [&options.output, &provenance] {
        if path.exists() && !options.force {
            return Err(CAbiError::OutputExists(path.display().to_string()));
        }
    }
    write_file(&options.output, generated.header.as_bytes())?;
    write_file(&provenance, generated.provenance_json.as_bytes())?;
    Ok(generated)
}

pub fn generate_c_abi(options: &CAbiGenerateOptions) -> Result<GeneratedCAbi, CAbiError> {
    let root = canonical_package_root(&options.package_root)?;
    let (contract_path, contract_relative) = package_file(&root, &options.contract, true)?;
    if contract_path
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("json")
    {
        return Err(CAbiError::InvalidContractPath(
            options.contract.display().to_string(),
        ));
    }
    let (output_path, output_relative) = package_output(&root, &options.output)?;
    if output_path
        .extension()
        .and_then(|extension| extension.to_str())
        != Some("h")
    {
        return Err(CAbiError::InvalidOutputPath(
            options.output.display().to_string(),
        ));
    }

    let contract_bytes = read_file(&contract_path)?;
    let mut contract: CAbiContract = serde_json::from_slice(&contract_bytes)?;
    validate_contract(&mut contract)?;
    let guard = contract
        .header_guard
        .clone()
        .unwrap_or_else(|| automatic_header_guard(&output_relative));
    if !valid_header_guard(&guard) {
        return Err(CAbiError::InvalidHeaderGuard(guard));
    }

    let sources = source_inventory(&root, &options.extra_sources)?;
    let mut syntax_by_source = BTreeMap::new();
    let mut source_digests = Vec::new();
    for source in &sources {
        let bytes = read_file(&root.join(source))?;
        source_digests.push(SourceDigest {
            source: source.clone(),
            sha256: sha256_hex(&bytes),
        });
        let syntax = syn::parse_file(&String::from_utf8_lossy(&bytes)).map_err(|source_error| {
            CAbiError::ParseRust {
                path: source.clone(),
                source: source_error,
            }
        })?;
        syntax_by_source.insert(source.clone(), syntax);
    }
    source_digests.sort();

    let conditional_sources = conditional_module_sources(&syntax_by_source)?;
    let mut exports = BTreeMap::new();
    for (source, syntax) in &syntax_by_source {
        collect_exports(
            &syntax.items,
            source,
            conditional_sources.contains(source),
            &mut exports,
        )?;
    }

    let contract_symbols: BTreeMap<_, _> = contract
        .symbols
        .iter()
        .map(|symbol| (symbol.name.clone(), symbol))
        .collect();
    for symbol in contract_symbols.keys() {
        if !exports.contains_key(symbol) {
            return Err(CAbiError::MissingExport(symbol.clone()));
        }
    }
    for symbol in exports.keys() {
        if !contract_symbols.contains_key(symbol) {
            return Err(CAbiError::UncontractedExport(symbol.clone()));
        }
    }

    let mut evidence = Vec::new();
    for symbol in &contract.symbols {
        let export = &exports[&symbol.name].evidence;
        if export.return_type != symbol.return_type || export.parameters != symbol.parameters {
            return Err(CAbiError::SignatureMismatch {
                symbol: symbol.name.clone(),
                expected: signature_string(symbol.return_type, &symbol.parameters),
                actual: signature_string(export.return_type, &export.parameters),
            });
        }
        evidence.push(export.clone());
    }
    evidence.sort();

    let header = render_header(&guard, &contract.symbols);
    let provenance = CAbiProvenance {
        schema_version: PROVENANCE_SCHEMA_VERSION,
        contract_sha256: sha256_hex(&contract_bytes),
        contract_path: contract_relative,
        header_sha256: sha256_hex(header.as_bytes()),
        header_path: output_relative.clone(),
        header_guard: guard.clone(),
        sources: source_digests,
        symbols: evidence,
    };
    let provenance_json = format!("{}\n", serde_json::to_string_pretty(&provenance)?);
    Ok(GeneratedCAbi {
        summary: CAbiGenerateSummary {
            contract: contract_path.display().to_string(),
            output: output_path.display().to_string(),
            provenance: provenance_path(&output_path).display().to_string(),
            source_count: sources.len(),
            symbol_count: contract.symbols.len(),
            header_guard: guard,
            checked: options.check,
        },
        header,
        provenance_json,
    })
}

fn canonical_package_root(path: &Path) -> Result<PathBuf, CAbiError> {
    let root = path
        .canonicalize()
        .map_err(|source| CAbiError::InvalidPackageRoot {
            path: path.display().to_string(),
            source,
        })?;
    if !root.is_dir() {
        return Err(CAbiError::InvalidPackageRoot {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "path is not a directory",
            ),
        });
    }
    Ok(root)
}

fn package_file(root: &Path, path: &Path, contract: bool) -> Result<(PathBuf, String), CAbiError> {
    let canonical = path.canonicalize().map_err(|_| {
        if contract {
            CAbiError::InvalidContractPath(path.display().to_string())
        } else {
            CAbiError::InvalidSourcePath(path.display().to_string())
        }
    })?;
    let relative = canonical.strip_prefix(root).map_err(|_| {
        if contract {
            CAbiError::InvalidContractPath(path.display().to_string())
        } else {
            CAbiError::InvalidSourcePath(path.display().to_string())
        }
    })?;
    let relative = normalize_repo_relative_path(&relative.to_string_lossy()).ok_or_else(|| {
        if contract {
            CAbiError::InvalidContractPath(path.display().to_string())
        } else {
            CAbiError::InvalidSourcePath(path.display().to_string())
        }
    })?;
    Ok((canonical, relative))
}

fn package_output(root: &Path, output: &Path) -> Result<(PathBuf, String), CAbiError> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| CAbiError::InvalidOutputPath(output.display().to_string()))?;
    let relative_parent = parent
        .strip_prefix(root)
        .map_err(|_| CAbiError::InvalidOutputPath(output.display().to_string()))?;
    let filename = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| CAbiError::InvalidOutputPath(output.display().to_string()))?;
    let relative = relative_parent.join(filename);
    let relative = normalize_repo_relative_path(&relative.to_string_lossy())
        .ok_or_else(|| CAbiError::InvalidOutputPath(output.display().to_string()))?;
    Ok((parent.join(filename), relative))
}

fn validate_contract(contract: &mut CAbiContract) -> Result<(), CAbiError> {
    if contract.schema_version != CONTRACT_SCHEMA_VERSION {
        return Err(CAbiError::UnsupportedContractSchema {
            found: contract.schema_version,
            supported: CONTRACT_SCHEMA_VERSION,
        });
    }
    if contract.symbols.is_empty() {
        return Err(CAbiError::EmptyContract);
    }
    contract.symbols.sort();
    let mut symbols = BTreeSet::new();
    for symbol in &contract.symbols {
        validate_identifier("symbol", &symbol.name)?;
        if !symbols.insert(symbol.name.clone()) {
            return Err(CAbiError::DuplicateContractSymbol(symbol.name.clone()));
        }
        let mut parameters = BTreeSet::new();
        for parameter in &symbol.parameters {
            validate_identifier("parameter", &parameter.name)?;
            if parameter.abi_type == AbiType::Void {
                return Err(CAbiError::VoidParameter {
                    symbol: symbol.name.clone(),
                    parameter: parameter.name.clone(),
                });
            }
            if !parameters.insert(parameter.name.clone()) {
                return Err(CAbiError::DuplicateParameter {
                    symbol: symbol.name.clone(),
                    parameter: parameter.name.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), CAbiError> {
    let mut characters = value.chars();
    let valid = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(CAbiError::InvalidIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn source_inventory(root: &Path, extra_sources: &[String]) -> Result<Vec<String>, CAbiError> {
    let src = root.join("src");
    if !src.is_dir() && extra_sources.is_empty() {
        return Err(CAbiError::MissingSourceDirectory(src.display().to_string()));
    }
    let mut sources = BTreeSet::new();
    if src.is_dir() {
        collect_sources(root, &src, &mut sources)?;
    }
    for source in extra_sources {
        let relative = normalize_repo_relative_path(source)
            .filter(|path| path.ends_with(".rs"))
            .ok_or_else(|| CAbiError::InvalidSourcePath(source.clone()))?;
        if !root.join(&relative).is_file() {
            return Err(CAbiError::MissingSource(relative));
        }
        sources.insert(relative);
    }
    Ok(sources.into_iter().collect())
}

fn collect_sources(
    root: &Path,
    directory: &Path,
    sources: &mut BTreeSet<String>,
) -> Result<(), CAbiError> {
    let entries = fs::read_dir(directory).map_err(|source| CAbiError::ReadDirectory {
        path: directory.display().to_string(),
        source,
    })?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(
            entry
                .map_err(|source| CAbiError::ReadDirectory {
                    path: directory.display().to_string(),
                    source,
                })?
                .path(),
        );
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.join("Cargo.toml").is_file() {
                continue;
            }
            collect_sources(root, &path, sources)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| CAbiError::InvalidSourcePath(path.display().to_string()))?;
            let relative = normalize_repo_relative_path(&relative.to_string_lossy())
                .ok_or_else(|| CAbiError::InvalidSourcePath(path.display().to_string()))?;
            sources.insert(relative);
        }
    }
    Ok(())
}

fn conditional_module_sources(
    files: &BTreeMap<String, syn::File>,
) -> Result<BTreeSet<String>, CAbiError> {
    let available: BTreeSet<_> = files.keys().map(String::as_str).collect();
    let mut conditional = BTreeSet::new();

    loop {
        let previous_len = conditional.len();
        for (source, syntax) in files {
            let file_conditional =
                conditional.contains(source) || has_conditional_attribute(&syntax.attrs);
            if file_conditional {
                conditional.insert(source.clone());
            }
            propagate_conditional_modules(
                &syntax.items,
                source,
                &module_base_directory(source),
                file_conditional,
                &available,
                &mut conditional,
            )?;
        }
        if conditional.len() == previous_len {
            break;
        }
    }

    Ok(conditional)
}

fn propagate_conditional_modules(
    items: &[Item],
    source: &str,
    module_base: &Path,
    conditional_parent: bool,
    available: &BTreeSet<&str>,
    conditional: &mut BTreeSet<String>,
) -> Result<(), CAbiError> {
    for item in items {
        let Item::Mod(module) = item else {
            continue;
        };
        let module_conditional = conditional_parent || has_conditional_attribute(&module.attrs);
        if let Some((_, nested)) = &module.content {
            propagate_conditional_modules(
                nested,
                source,
                &module_base.join(module.ident.to_string()),
                module_conditional,
                available,
                conditional,
            )?;
            continue;
        }
        if !module_conditional {
            continue;
        }
        if module
            .attrs
            .iter()
            .any(|attribute| attribute.path().is_ident("path"))
        {
            return Err(CAbiError::ConditionalModulePath {
                module: module.ident.to_string(),
                file: source.to_owned(),
                line: module.ident.span().start().line,
            });
        }

        let module_name = module.ident.to_string();
        let candidates = [
            module_base.join(format!("{module_name}.rs")),
            module_base.join(&module_name).join("mod.rs"),
        ];
        for candidate in candidates {
            let candidate = candidate.to_string_lossy().replace('\\', "/");
            if available.contains(candidate.as_str()) {
                conditional.insert(candidate);
            }
        }
    }
    Ok(())
}

fn module_base_directory(source: &str) -> PathBuf {
    let path = Path::new(source);
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("");
    if matches!(stem, "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

fn collect_exports(
    items: &[Item],
    source: &str,
    conditional_parent: bool,
    exports: &mut BTreeMap<String, DiscoveredExport>,
) -> Result<(), CAbiError> {
    for item in items {
        match item {
            Item::Fn(function) if has_export_name(&function.attrs) => {
                return Err(CAbiError::UnsupportedExportName {
                    symbol: function.sig.ident.to_string(),
                    file: source.to_owned(),
                    line: function.sig.ident.span().start().line,
                });
            }
            Item::Fn(function) if has_no_mangle(&function.attrs) => {
                let symbol = function.sig.ident.to_string();
                let line = function.sig.ident.span().start().line;
                if conditional_parent || has_conditional_attribute(&function.attrs) {
                    return Err(CAbiError::ConditionalExport {
                        symbol,
                        file: source.to_owned(),
                        line,
                    });
                }
                if !matches!(function.vis, Visibility::Public(_)) {
                    return Err(CAbiError::NonPublicExport {
                        symbol,
                        file: source.to_owned(),
                        line,
                    });
                }
                if function
                    .sig
                    .abi
                    .as_ref()
                    .and_then(|abi| abi.name.as_ref())
                    .is_none_or(|name| name.value() != "C")
                {
                    return Err(CAbiError::UnsupportedExportAbi {
                        symbol,
                        file: source.to_owned(),
                        line,
                    });
                }
                let evidence = export_evidence(function, source)?;
                if let Some(previous) = exports.insert(
                    evidence.name.clone(),
                    DiscoveredExport {
                        evidence: evidence.clone(),
                    },
                ) {
                    return Err(CAbiError::DuplicateExport {
                        symbol: evidence.name,
                        first: format!("{}:{}", previous.evidence.source, previous.evidence.line),
                        second: format!("{}:{}", evidence.source, evidence.line),
                    });
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_exports(
                        nested,
                        source,
                        conditional_parent || has_conditional_attribute(&module.attrs),
                        exports,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn has_no_mangle(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("no_mangle") {
            return true;
        }
        match &attribute.meta {
            syn::Meta::List(list) if list.path.is_ident("unsafe") => {
                list.tokens.to_string() == "no_mangle"
            }
            _ => false,
        }
    })
}

fn has_export_name(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if attribute.path().is_ident("export_name") {
            return true;
        }
        matches!(
            &attribute.meta,
            syn::Meta::List(list)
                if list.path.is_ident("unsafe")
                    && list.tokens.to_string().starts_with("export_name")
        )
    })
}

fn has_conditional_attribute(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn export_evidence(function: &ItemFn, source: &str) -> Result<ExportEvidence, CAbiError> {
    let line = function.sig.ident.span().start().line;
    if !function.sig.generics.params.is_empty() || function.sig.variadic.is_some() {
        return Err(CAbiError::UnsupportedRustSignature {
            symbol: function.sig.ident.to_string(),
            file: source.to_owned(),
            line,
        });
    }
    let mut parameters = Vec::new();
    for argument in &function.sig.inputs {
        let FnArg::Typed(argument) = argument else {
            return Err(CAbiError::UnsupportedRustSignature {
                symbol: function.sig.ident.to_string(),
                file: source.to_owned(),
                line,
            });
        };
        let Pat::Ident(name) = argument.pat.as_ref() else {
            return Err(CAbiError::UnsupportedRustSignature {
                symbol: function.sig.ident.to_string(),
                file: source.to_owned(),
                line,
            });
        };
        let abi_type =
            rust_abi_type(&argument.ty).ok_or_else(|| CAbiError::UnsupportedRustSignature {
                symbol: function.sig.ident.to_string(),
                file: source.to_owned(),
                line,
            })?;
        if abi_type == AbiType::Void {
            return Err(CAbiError::UnsupportedRustSignature {
                symbol: function.sig.ident.to_string(),
                file: source.to_owned(),
                line,
            });
        }
        parameters.push(CAbiParameter {
            name: name.ident.to_string(),
            abi_type,
        });
    }
    let return_type = match &function.sig.output {
        ReturnType::Default => AbiType::Void,
        ReturnType::Type(_, value) => {
            rust_abi_type(value).ok_or_else(|| CAbiError::UnsupportedRustSignature {
                symbol: function.sig.ident.to_string(),
                file: source.to_owned(),
                line,
            })?
        }
    };
    Ok(ExportEvidence {
        name: function.sig.ident.to_string(),
        source: source.to_owned(),
        line,
        unsafe_function: function.sig.unsafety.is_some(),
        return_type,
        parameters,
    })
}

fn rust_abi_type(value: &Type) -> Option<AbiType> {
    match value {
        Type::Path(path) => scalar_type(path),
        Type::Ptr(pointer) => {
            let pointee = pointer.elem.as_ref();
            let mutable = pointer.mutability.is_some();
            match pointee {
                Type::Path(path) if path_ends_with(path, "i8") => Some(if mutable {
                    AbiType::MutI8Ptr
                } else {
                    AbiType::ConstI8Ptr
                }),
                Type::Path(path) if path_ends_with(path, "u8") => Some(if mutable {
                    AbiType::MutU8Ptr
                } else {
                    AbiType::ConstU8Ptr
                }),
                Type::Path(path) if path_ends_with(path, "c_void") => Some(if mutable {
                    AbiType::MutVoidPtr
                } else {
                    AbiType::ConstVoidPtr
                }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn scalar_type(path: &TypePath) -> Option<AbiType> {
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = path.path.segments.first()?;
    if !matches!(segment.arguments, syn::PathArguments::None) {
        return None;
    }
    match segment.ident.to_string().as_str() {
        "bool" => Some(AbiType::Bool),
        "i8" => Some(AbiType::I8),
        "u8" => Some(AbiType::U8),
        "i16" => Some(AbiType::I16),
        "u16" => Some(AbiType::U16),
        "i32" => Some(AbiType::I32),
        "u32" => Some(AbiType::U32),
        "i64" => Some(AbiType::I64),
        "u64" => Some(AbiType::U64),
        "isize" => Some(AbiType::Isize),
        "usize" => Some(AbiType::Usize),
        "f32" => Some(AbiType::F32),
        "f64" => Some(AbiType::F64),
        _ => None,
    }
}

fn path_ends_with(path: &TypePath, name: &str) -> bool {
    path.qself.is_none()
        && path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
}

fn render_header(guard: &str, symbols: &[CAbiSymbol]) -> String {
    let mut output = format!(
        "// Generated by Chromifer from an explicit C ABI contract.\n// Do not edit manually.\n\n#ifndef {guard}\n#define {guard}\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n#ifdef __cplusplus\nextern \"C\" {{\n#endif\n\n"
    );
    for symbol in symbols {
        output.push_str(&format!(
            "{} {}({});\n",
            symbol.return_type.c_type(),
            symbol.name,
            if symbol.parameters.is_empty() {
                "void".into()
            } else {
                symbol
                    .parameters
                    .iter()
                    .map(|parameter| format!("{} {}", parameter.abi_type.c_type(), parameter.name))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ));
    }
    output.push_str(&format!(
        "\n#ifdef __cplusplus\n}}  // extern \"C\"\n#endif\n\n#endif  // {guard}\n"
    ));
    output
}

impl AbiType {
    pub const fn c_type(self) -> &'static str {
        match self {
            Self::Void => "void",
            Self::Bool => "bool",
            Self::I8 => "int8_t",
            Self::U8 => "uint8_t",
            Self::I16 => "int16_t",
            Self::U16 => "uint16_t",
            Self::I32 => "int32_t",
            Self::U32 => "uint32_t",
            Self::I64 => "int64_t",
            Self::U64 => "uint64_t",
            Self::Isize => "intptr_t",
            Self::Usize => "uintptr_t",
            Self::F32 => "float",
            Self::F64 => "double",
            Self::ConstI8Ptr => "const int8_t*",
            Self::MutI8Ptr => "int8_t*",
            Self::ConstU8Ptr => "const uint8_t*",
            Self::MutU8Ptr => "uint8_t*",
            Self::ConstVoidPtr => "const void*",
            Self::MutVoidPtr => "void*",
        }
    }
}

fn signature_string(return_type: AbiType, parameters: &[CAbiParameter]) -> String {
    format!(
        "{}({})",
        return_type.c_type(),
        parameters
            .iter()
            .map(|parameter| format!("{} {}", parameter.abi_type.c_type(), parameter.name))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn automatic_header_guard(path: &str) -> String {
    let mut guard = String::from("CHROMIFER_");
    for character in path.chars() {
        if character.is_ascii_alphanumeric() {
            guard.push(character.to_ascii_uppercase());
        } else if !guard.ends_with('_') {
            guard.push('_');
        }
    }
    if !guard.ends_with('_') {
        guard.push('_');
    }
    guard
}

fn valid_header_guard(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_uppercase() || character == '_')
        && characters.all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

fn provenance_path(output: &Path) -> PathBuf {
    let filename = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("c-abi.h");
    output.with_file_name(format!("{filename}.chromifer.json"))
}

fn read_file(path: &Path) -> Result<Vec<u8>, CAbiError> {
    fs::read(path).map_err(|source| CAbiError::ReadFile {
        path: path.display().to_string(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CAbiError> {
    fs::write(path, bytes).map_err(|source| CAbiError::WriteFile {
        path: path.display().to_string(),
        source,
    })
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), CAbiError> {
    let actual = fs::read(path).map_err(|_| CAbiError::Drift(path.display().to_string()))?;
    if actual != expected {
        return Err(CAbiError::Drift(path.display().to_string()));
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TREE: AtomicU64 = AtomicU64::new(1);

    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new() -> Self {
            let id = NEXT_TREE.fetch_add(1, Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("chromifer-cabi-{}-{id}", std::process::id()));
            fs::create_dir_all(root.join("src")).unwrap();
            fs::create_dir_all(root.join("include")).unwrap();
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

    fn contract(symbols: serde_json::Value) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "symbols": symbols,
        }))
        .unwrap()
    }

    fn options(tree: &TempTree) -> CAbiGenerateOptions {
        CAbiGenerateOptions {
            package_root: tree.root.clone(),
            contract: tree.root.join("c-abi.json"),
            output: tree.root.join("include/api.h"),
            extra_sources: vec![],
            force: false,
            check: false,
        }
    }

    fn standard_contract() -> String {
        contract(serde_json::json!([
            {
                "name": "chromifer_add",
                "return_type": "i32",
                "parameters": [
                    {"name": "left", "type": "i32"},
                    {"name": "right", "type": "i32"}
                ]
            },
            {
                "name": "chromifer_copy",
                "return_type": "bool",
                "parameters": [
                    {"name": "input", "type": "const_u8_ptr"},
                    {"name": "length", "type": "usize"},
                    {"name": "output", "type": "mut_u8_ptr"}
                ]
            }
        ]))
    }

    fn standard_rust() -> &'static str {
        "#[unsafe(no_mangle)]\npub extern \"C\" fn chromifer_add(left: i32, right: i32) -> i32 { left + right }\n\n#[no_mangle]\npub unsafe extern \"C\" fn chromifer_copy(input: *const u8, length: usize, output: *mut u8) -> bool { !input.is_null() && length > 0 && !output.is_null() }\n"
    }

    #[test]
    fn validates_exports_and_generates_deterministic_c_header() {
        let tree = TempTree::new();
        tree.write("c-abi.json", &standard_contract());
        tree.write("src/lib.rs", standard_rust());

        let generated = generate_and_write(&options(&tree)).unwrap();
        assert!(
            generated
                .header
                .contains("int32_t chromifer_add(int32_t left, int32_t right);")
        );
        assert!(generated.header.contains(
            "bool chromifer_copy(const uint8_t* input, uintptr_t length, uint8_t* output);"
        ));
        assert!(generated.header.contains("extern \"C\""));
        assert_eq!(generated.summary.symbol_count, 2);
        assert!(tree.root.join("include/api.h").is_file());
        assert!(tree.root.join("include/api.h.chromifer.json").is_file());

        let second = generate_c_abi(&options(&tree)).unwrap();
        assert_eq!(generated.header, second.header);
        assert_eq!(generated.provenance_json, second.provenance_json);
        let provenance: serde_json::Value =
            serde_json::from_str(&generated.provenance_json).unwrap();
        assert_eq!(provenance["symbols"][0]["name"], "chromifer_add");
        assert_eq!(provenance["symbols"][1]["unsafe_function"], true);
    }

    #[test]
    fn rejects_missing_and_uncontracted_exports() {
        let tree = TempTree::new();
        tree.write("c-abi.json", &standard_contract());
        tree.write(
            "src/lib.rs",
            "#[no_mangle]\npub extern \"C\" fn chromifer_add(left: i32, right: i32) -> i32 { left + right }\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::MissingExport(name)) if name == "chromifer_copy"
        ));

        tree.write(
            "src/lib.rs",
            &format!(
                "{}\n#[no_mangle]\npub extern \"C\" fn unexpected() {{}}\n",
                standard_rust()
            ),
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::UncontractedExport(name)) if name == "unexpected"
        ));
    }

    #[test]
    fn requires_no_mangle_and_exact_signature() {
        let tree = TempTree::new();
        tree.write("c-abi.json", &standard_contract());
        tree.write(
            "src/lib.rs",
            "pub extern \"C\" fn chromifer_add(left: i32, right: i32) -> i32 { left + right }\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::MissingExport(_))
        ));

        tree.write(
            "src/lib.rs",
            &standard_rust().replace("left: i32", "left: u32"),
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::SignatureMismatch { symbol, .. }) if symbol == "chromifer_add"
        ));
    }

    #[test]
    fn rejects_exports_that_bypass_or_vary_the_contract() {
        let tree = TempTree::new();
        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([{
                "name": "boundary",
                "return_type": "void"
            }])),
        );

        tree.write(
            "src/lib.rs",
            "#[no_mangle]\npub(crate) extern \"C\" fn boundary() {}\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::NonPublicExport { symbol, .. }) if symbol == "boundary"
        ));

        tree.write(
            "src/lib.rs",
            "#[no_mangle]\npub extern \"system\" fn boundary() {}\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::UnsupportedExportAbi { symbol, .. }) if symbol == "boundary"
        ));

        tree.write(
            "src/lib.rs",
            "#[unsafe(export_name = \"boundary\")]\npub extern \"C\" fn local_name() {}\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::UnsupportedExportName { symbol, .. }) if symbol == "local_name"
        ));

        tree.write(
            "src/lib.rs",
            "#[cfg(unix)]\nmod platform {\n    #[no_mangle]\n    pub extern \"C\" fn boundary() {}\n}\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::ConditionalExport { symbol, .. }) if symbol == "boundary"
        ));

        tree.write("src/lib.rs", "#[cfg(unix)]\nmod platform;\n");
        tree.write(
            "src/platform.rs",
            "#[no_mangle]\npub extern \"C\" fn boundary() {}\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::ConditionalExport { symbol, .. }) if symbol == "boundary"
        ));

        tree.write(
            "src/lib.rs",
            "#[cfg(unix)]\n#[path = \"platform.rs\"]\nmod platform;\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::ConditionalModulePath { module, .. }) if module == "platform"
        ));
    }

    #[test]
    fn rejects_unsupported_rust_abi_types() {
        let tree = TempTree::new();
        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([{
                "name": "bad",
                "return_type": "usize",
                "parameters": [{"name": "input", "type": "const_u8_ptr"}]
            }])),
        );
        tree.write(
            "src/lib.rs",
            "#[no_mangle]\npub extern \"C\" fn bad(input: &str) -> usize { input.len() }\n",
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::UnsupportedRustSignature { symbol, .. }) if symbol == "bad"
        ));
    }

    #[test]
    fn detects_duplicate_exports_across_sources() {
        let tree = TempTree::new();
        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([{
                "name": "duplicate",
                "return_type": "void"
            }])),
        );
        let export = "#[no_mangle]\npub extern \"C\" fn duplicate() {}\n";
        tree.write("src/lib.rs", export);
        tree.write("src/other.rs", export);
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::DuplicateExport { symbol, .. }) if symbol == "duplicate"
        ));
    }

    #[test]
    fn validates_contract_identifiers_duplicates_and_void_parameters() {
        let tree = TempTree::new();
        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([
                {"name": "same", "return_type": "void"},
                {"name": "same", "return_type": "void"}
            ])),
        );
        tree.write("src/lib.rs", "");
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::DuplicateContractSymbol(name)) if name == "same"
        ));

        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([{
                "name": "invalid-name",
                "return_type": "void"
            }])),
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::InvalidIdentifier { .. })
        ));

        tree.write(
            "c-abi.json",
            &contract(serde_json::json!([{
                "name": "bad_void",
                "return_type": "void",
                "parameters": [{"name": "value", "type": "void"}]
            }])),
        );
        assert!(matches!(
            generate_c_abi(&options(&tree)),
            Err(CAbiError::VoidParameter { .. })
        ));
    }

    #[test]
    fn check_mode_detects_header_and_provenance_drift() {
        let tree = TempTree::new();
        tree.write("c-abi.json", &standard_contract());
        tree.write("src/lib.rs", standard_rust());
        generate_and_write(&options(&tree)).unwrap();

        let mut check = options(&tree);
        check.check = true;
        assert!(generate_and_write(&check).is_ok());
        fs::write(tree.root.join("include/api.h"), "changed").unwrap();
        assert!(matches!(
            generate_and_write(&check),
            Err(CAbiError::Drift(_))
        ));
    }

    #[test]
    fn supports_c_void_pointers_and_custom_header_guards() {
        let tree = TempTree::new();
        tree.write(
            "c-abi.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": 1,
                "header_guard": "CUSTOM_C_ABI_H_",
                "symbols": [{
                    "name": "opaque",
                    "return_type": "mut_void_ptr",
                    "parameters": [{"name": "input", "type": "const_void_ptr"}]
                }]
            }))
            .unwrap(),
        );
        tree.write(
            "src/lib.rs",
            "#[unsafe(no_mangle)]\npub extern \"C\" fn opaque(input: *const core::ffi::c_void) -> *mut core::ffi::c_void { input.cast_mut() }\n",
        );
        let generated = generate_c_abi(&options(&tree)).unwrap();
        assert!(generated.header.contains("#ifndef CUSTOM_C_ABI_H_"));
        assert!(
            generated
                .header
                .contains("void* opaque(const void* input);")
        );
    }
}
