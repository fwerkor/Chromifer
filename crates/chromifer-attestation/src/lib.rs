#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const ATTESTATION_SCHEMA_VERSION: u32 = 1;
const ALGORITHM: &str = "ed25519";
const DOMAIN: &[u8] = b"chromifer:evidence-attestation:v1\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOptions {
    pub evidence: PathBuf,
    pub private_key: PathBuf,
    pub output: PathBuf,
    pub runner_id: String,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyOptions {
    pub private_key: PathBuf,
    pub output: PathBuf,
    pub force: bool,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAttestation {
    pub schema_version: u32,
    pub algorithm: String,
    pub runner_id: String,
    pub evidence_sha256: String,
    pub public_key_sha256: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignSummary {
    pub evidence_sha256: String,
    pub runner_id: String,
    pub public_key_sha256: String,
    pub output: String,
    pub checked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifySummary {
    pub evidence_sha256: String,
    pub runner_id: String,
    pub public_key_sha256: String,
    pub signature_valid: bool,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("runner id must be 1..=128 characters from [A-Za-z0-9._:@/-]")]
    InvalidRunnerId,
    #[error("path `{0}` is missing, symlinked, or not a regular file")]
    InvalidFile(String),
    #[error("private key `{0}` is readable by group or other users; require mode 0600 or stricter")]
    InsecurePrivateKeyPermissions(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("key file `{0}` is not valid 32-byte hexadecimal data")]
    InvalidKey(String),
    #[error("failed to parse evidence attestation JSON: {0}")]
    ParseAttestation(#[from] serde_json::Error),
    #[error(
        "unsupported evidence attestation schema version {found}; supported version is {supported}"
    )]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("unsupported signature algorithm `{0}`")]
    UnsupportedAlgorithm(String),
    #[error("attestation public key does not match the trusted public key")]
    UntrustedPublicKey,
    #[error("attestation public-key digest is invalid")]
    PublicKeyDigestMismatch,
    #[error("attestation evidence digest does not match `{0}`")]
    EvidenceDigestMismatch(String),
    #[error("attestation signature is not valid")]
    InvalidSignature,
    #[error("output `{0}` already exists; pass --force to replace it")]
    OutputExists(String),
    #[error("output `{output}` aliases protected input `{input}`")]
    OutputAliasesInput { output: String, input: String },
    #[error("generated output `{0}` is missing or differs")]
    Drift(String),
    #[error("failed to write `{path}`: {source}")]
    WriteFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn sign_and_write(options: &SignOptions) -> Result<SignSummary, AttestationError> {
    validate_runner_id(&options.runner_id)?;
    reject_output_alias(&options.output, &options.evidence)?;
    reject_output_alias(&options.output, &options.private_key)?;
    let evidence = read_regular_file(&options.evidence)?;
    let signing_key = load_private_key(&options.private_key)?;
    let verifying_key = signing_key.verifying_key();
    let evidence_sha256 = sha256_hex(&evidence);
    let public_key = encode_hex(verifying_key.as_bytes());
    let public_key_sha256 = sha256_hex(verifying_key.as_bytes());
    let message = signing_payload(
        &options.runner_id,
        &evidence_sha256,
        &public_key,
        &public_key_sha256,
    );
    let signature = signing_key.sign(&message);
    let attestation = EvidenceAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION,
        algorithm: ALGORITHM.into(),
        runner_id: options.runner_id.clone(),
        evidence_sha256: evidence_sha256.clone(),
        public_key_sha256: public_key_sha256.clone(),
        public_key,
        signature: encode_hex(&signature.to_bytes()),
    };
    let json = format!("{}\n", serde_json::to_string_pretty(&attestation)?);
    write_or_check(
        &options.output,
        json.as_bytes(),
        options.force,
        options.check,
    )?;
    Ok(SignSummary {
        evidence_sha256,
        runner_id: options.runner_id.clone(),
        public_key_sha256,
        output: display(&options.output),
        checked: options.check,
    })
}

pub fn derive_public_key(options: &PublicKeyOptions) -> Result<String, AttestationError> {
    reject_output_alias(&options.output, &options.private_key)?;
    let signing_key = load_private_key(&options.private_key)?;
    let output = format!("{}\n", encode_hex(signing_key.verifying_key().as_bytes()));
    write_or_check(
        &options.output,
        output.as_bytes(),
        options.force,
        options.check,
    )?;
    Ok(output.trim_end().to_owned())
}

pub fn verify(
    evidence_path: &Path,
    attestation_path: &Path,
    trusted_public_key_path: &Path,
) -> Result<VerifySummary, AttestationError> {
    let evidence = read_regular_file(evidence_path)?;
    let attestation_bytes = read_regular_file(attestation_path)?;
    let attestation: EvidenceAttestation = serde_json::from_slice(&attestation_bytes)?;
    validate_attestation(&attestation)?;
    let trusted_public_key = load_public_key(trusted_public_key_path)?;
    let attested_public_key = decode_array::<32>(&attestation.public_key)
        .map_err(|_| AttestationError::InvalidKey(display(attestation_path)))?;
    if trusted_public_key.to_bytes() != attested_public_key {
        return Err(AttestationError::UntrustedPublicKey);
    }
    if sha256_hex(&attested_public_key) != attestation.public_key_sha256 {
        return Err(AttestationError::PublicKeyDigestMismatch);
    }
    let evidence_sha256 = sha256_hex(&evidence);
    if evidence_sha256 != attestation.evidence_sha256 {
        return Err(AttestationError::EvidenceDigestMismatch(display(
            evidence_path,
        )));
    }
    let signature_bytes = decode_array::<64>(&attestation.signature)
        .map_err(|_| AttestationError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let message = signing_payload(
        &attestation.runner_id,
        &attestation.evidence_sha256,
        &attestation.public_key,
        &attestation.public_key_sha256,
    );
    trusted_public_key
        .verify_strict(&message, &signature)
        .map_err(|_| AttestationError::InvalidSignature)?;
    Ok(VerifySummary {
        evidence_sha256,
        runner_id: attestation.runner_id,
        public_key_sha256: attestation.public_key_sha256,
        signature_valid: true,
    })
}

fn validate_attestation(attestation: &EvidenceAttestation) -> Result<(), AttestationError> {
    if attestation.schema_version != ATTESTATION_SCHEMA_VERSION {
        return Err(AttestationError::UnsupportedSchema {
            found: attestation.schema_version,
            supported: ATTESTATION_SCHEMA_VERSION,
        });
    }
    if attestation.algorithm != ALGORITHM {
        return Err(AttestationError::UnsupportedAlgorithm(
            attestation.algorithm.clone(),
        ));
    }
    validate_runner_id(&attestation.runner_id)?;
    if !is_lower_hex(&attestation.evidence_sha256, 64)
        || !is_lower_hex(&attestation.public_key_sha256, 64)
        || !is_lower_hex(&attestation.public_key, 64)
        || !is_lower_hex(&attestation.signature, 128)
    {
        return Err(AttestationError::InvalidSignature);
    }
    Ok(())
}

fn validate_runner_id(value: &str) -> Result<(), AttestationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        })
    {
        return Err(AttestationError::InvalidRunnerId);
    }
    Ok(())
}

fn load_private_key(path: &Path) -> Result<SigningKey, AttestationError> {
    let mut bytes = read_key_file(path, true)?;
    let decoded = decode_array::<32>(&bytes);
    bytes.zeroize();
    let mut secret = decoded.map_err(|_| AttestationError::InvalidKey(display(path)))?;
    let signing_key = SigningKey::from_bytes(&secret);
    secret.zeroize();
    Ok(signing_key)
}

fn load_public_key(path: &Path) -> Result<VerifyingKey, AttestationError> {
    let bytes = read_key_file(path, false)?;
    let public =
        decode_array::<32>(&bytes).map_err(|_| AttestationError::InvalidKey(display(path)))?;
    VerifyingKey::from_bytes(&public).map_err(|_| AttestationError::InvalidKey(display(path)))
}

fn read_key_file(path: &Path, private: bool) -> Result<String, AttestationError> {
    let metadata = regular_file_metadata(path)?;
    if private {
        validate_private_permissions(path, &metadata)?;
    }
    let bytes = fs::read(path).map_err(|source| AttestationError::ReadFile {
        path: display(path),
        source,
    })?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| AttestationError::InvalidKey(display(path)))?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if text.len() != 64 || text.trim() != text || !is_lower_hex(text, 64) {
        return Err(AttestationError::InvalidKey(display(path)));
    }
    Ok(text.to_owned())
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, AttestationError> {
    regular_file_metadata(path)?;
    fs::read(path).map_err(|source| AttestationError::ReadFile {
        path: display(path),
        source,
    })
}

fn regular_file_metadata(path: &Path) -> Result<fs::Metadata, AttestationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AttestationError::InvalidFile(display(path)))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AttestationError::InvalidFile(display(path)));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn validate_private_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AttestationError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(AttestationError::InsecurePrivateKeyPermissions(display(
            path,
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_permissions(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), AttestationError> {
    Ok(())
}

fn write_or_check(
    path: &Path,
    bytes: &[u8],
    force: bool,
    check: bool,
) -> Result<(), AttestationError> {
    if check {
        let actual = read_regular_file(path).map_err(|_| AttestationError::Drift(display(path)))?;
        if actual != bytes {
            return Err(AttestationError::Drift(display(path)));
        }
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AttestationError::InvalidFile(display(path)));
            }
            if !force {
                return Err(AttestationError::OutputExists(display(path)));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(AttestationError::InvalidFile(display(path))),
    }
    fs::write(path, bytes).map_err(|source| AttestationError::WriteFile {
        path: display(path),
        source,
    })
}

fn reject_output_alias(output: &Path, input: &Path) -> Result<(), AttestationError> {
    if output == input {
        return Err(AttestationError::OutputAliasesInput {
            output: display(output),
            input: display(input),
        });
    }
    let Ok(output_metadata) = fs::symlink_metadata(output) else {
        return Ok(());
    };
    if output_metadata.file_type().is_symlink() {
        return Err(AttestationError::InvalidFile(display(output)));
    }
    let input_metadata = regular_file_metadata(input)?;
    if same_file(&output_metadata, &input_metadata, output, input) {
        return Err(AttestationError::OutputAliasesInput {
            output: display(output),
            input: display(input),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(
    left: &fs::Metadata,
    right: &fs::Metadata,
    _left_path: &Path,
    _right_path: &Path,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(
    _left: &fs::Metadata,
    _right: &fs::Metadata,
    left_path: &Path,
    right_path: &Path,
) -> bool {
    left_path.canonicalize().ok() == right_path.canonicalize().ok()
}

fn signing_payload(
    runner_id: &str,
    evidence_sha256: &str,
    public_key: &str,
    public_key_sha256: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        DOMAIN.len()
            + runner_id.len()
            + evidence_sha256.len()
            + public_key.len()
            + public_key_sha256.len()
            + 4,
    );
    message.extend_from_slice(DOMAIN);
    for value in [runner_id, evidence_sha256, public_key, public_key_sha256] {
        message.extend_from_slice(value.as_bytes());
        message.push(b'\n');
    }
    message
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 {
        return Err(());
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for (index, slot) in output.iter_mut().enumerate() {
        let high = decode_nibble(bytes[index * 2]).ok_or(())?;
        let low = decode_nibble(bytes[index * 2 + 1]).ok_or(())?;
        *slot = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        evidence: PathBuf,
        private_key: PathBuf,
        public_key: PathBuf,
        attestation: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "chromifer-attestation-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            let evidence = root.join("evidence.json");
            let private_key = root.join("runner.key");
            let public_key = root.join("runner.pub");
            let attestation = root.join("evidence.sig.json");
            fs::write(&evidence, b"{\"passed\":true}\n").unwrap();
            fs::write(
                &private_key,
                b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
            )
            .unwrap();
            set_private_permissions(&private_key);
            Self {
                root,
                evidence,
                private_key,
                public_key,
                attestation,
            }
        }

        fn sign_options(&self) -> SignOptions {
            SignOptions {
                evidence: self.evidence.clone(),
                private_key: self.private_key.clone(),
                output: self.attestation.clone(),
                runner_id: "ci/linux-x64".into(),
                force: false,
                check: false,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(unix)]
    fn set_private_permissions(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn set_private_permissions(_path: &Path) {}

    #[test]
    fn signs_verifies_and_checks_deterministic_attestation() {
        let fixture = Fixture::new();
        derive_public_key(&PublicKeyOptions {
            private_key: fixture.private_key.clone(),
            output: fixture.public_key.clone(),
            force: false,
            check: false,
        })
        .unwrap();
        let summary = sign_and_write(&fixture.sign_options()).unwrap();
        assert_eq!(summary.runner_id, "ci/linux-x64");
        let verified =
            verify(&fixture.evidence, &fixture.attestation, &fixture.public_key).unwrap();
        assert!(verified.signature_valid);
        let mut check = fixture.sign_options();
        check.check = true;
        assert!(sign_and_write(&check).is_ok());
    }

    #[test]
    fn rejects_evidence_attestation_and_trusted_key_tampering() {
        let fixture = Fixture::new();
        derive_public_key(&PublicKeyOptions {
            private_key: fixture.private_key.clone(),
            output: fixture.public_key.clone(),
            force: false,
            check: false,
        })
        .unwrap();
        sign_and_write(&fixture.sign_options()).unwrap();

        fs::write(&fixture.evidence, b"{\"passed\":false}\n").unwrap();
        assert!(matches!(
            verify(&fixture.evidence, &fixture.attestation, &fixture.public_key),
            Err(AttestationError::EvidenceDigestMismatch(_))
        ));
        fs::write(&fixture.evidence, b"{\"passed\":true}\n").unwrap();

        let mut attestation: EvidenceAttestation =
            serde_json::from_slice(&fs::read(&fixture.attestation).unwrap()).unwrap();
        attestation.runner_id = "ci/other".into();
        fs::write(
            &fixture.attestation,
            format!("{}\n", serde_json::to_string_pretty(&attestation).unwrap()),
        )
        .unwrap();
        assert!(matches!(
            verify(&fixture.evidence, &fixture.attestation, &fixture.public_key),
            Err(AttestationError::InvalidSignature)
        ));

        let other_key = fixture.root.join("other.key");
        let other_public = fixture.root.join("other.pub");
        fs::write(
            &other_key,
            b"1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100\n",
        )
        .unwrap();
        set_private_permissions(&other_key);
        derive_public_key(&PublicKeyOptions {
            private_key: other_key,
            output: other_public.clone(),
            force: false,
            check: false,
        })
        .unwrap();
        assert!(matches!(
            verify(&fixture.evidence, &fixture.attestation, &other_public),
            Err(AttestationError::UntrustedPublicKey)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_insecure_private_key_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = Fixture::new();
        fs::set_permissions(&fixture.private_key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            sign_and_write(&fixture.sign_options()),
            Err(AttestationError::InsecurePrivateKeyPermissions(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_output_aliases_and_dangling_symlinks() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let mut options = fixture.sign_options();
        options.output = fixture.evidence.clone();
        options.force = true;
        assert!(matches!(
            sign_and_write(&options),
            Err(AttestationError::OutputAliasesInput { .. })
        ));

        let hardlink = fixture.root.join("runner-hardlink.key");
        fs::hard_link(&fixture.private_key, &hardlink).unwrap();
        options.output = hardlink;
        assert!(matches!(
            sign_and_write(&options),
            Err(AttestationError::OutputAliasesInput { .. })
        ));

        let dangling = fixture.root.join("dangling.sig.json");
        symlink(fixture.root.join("missing-target"), &dangling).unwrap();
        options.output = dangling;
        assert!(matches!(
            sign_and_write(&options),
            Err(AttestationError::InvalidFile(_))
        ));
    }

    #[test]
    fn rejects_invalid_runner_ids_and_output_drift() {
        let fixture = Fixture::new();
        let mut options = fixture.sign_options();
        options.runner_id = "bad runner".into();
        assert!(matches!(
            sign_and_write(&options),
            Err(AttestationError::InvalidRunnerId)
        ));

        options.runner_id = "ci/linux-x64".into();
        sign_and_write(&options).unwrap();
        fs::write(&fixture.attestation, b"{}\n").unwrap();
        options.check = true;
        assert!(matches!(
            sign_and_write(&options),
            Err(AttestationError::Drift(_))
        ));
    }
}
