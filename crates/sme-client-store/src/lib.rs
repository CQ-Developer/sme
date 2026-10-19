//! Local keystore: encrypt identity keys, Olm sessions, contacts and TOFU pins to disk (D13', D14).
//!
//! The only client crate allowed to write to disk. The file **must contain no message bytes** (I11):
//! The payload is sealed as a whole by [`sme_crypto::seal`] before hitting disk and only the password-derived KEK can open it.
//! This crate defines no "message" field; callers only put named bytes in.

mod config;
mod olm;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sme_crypto::{CryptoError, KEY_LEN, KdfParams, NONCE_LEN, SALT_LEN};
use zeroize::Zeroizing;

pub use config::LocalConfig;

/// File magic: "SME Keystore".
const MAGIC: &[u8; 4] = b"SMEK";
const VERSION: u8 = 1;

/// magic(4) + version(1) + Argon2id params (3x4) + salt(16).
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN;

/// ChaCha20-Poly1305 authentication tag length.
const TAG_LEN: usize = 16;

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Crypto(CryptoError),
    Pickle(vodozemac::PickleError),
    Encode(postcard::Error),
    Decode(postcard::Error),
    NotAKeystore,
    UnsupportedVersion(u8),
    Corrupt(&'static str),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "keystore I/O failed: {error}"),
            Self::Crypto(error) => write!(f, "keystore crypto failed: {error}"),
            Self::Pickle(error) => write!(f, "olm pickle failed: {error}"),
            Self::Encode(error) => write!(f, "keystore encode failed: {error}"),
            Self::Decode(error) => write!(f, "keystore decode failed: {error}"),
            Self::NotAKeystore => write!(f, "not a sme keystore file"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported keystore version {version}")
            }
            Self::Corrupt(reason) => write!(f, "corrupt keystore: {reason}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::Pickle(error) => Some(error),
            Self::Encode(error) | Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<CryptoError> for StoreError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<vodozemac::PickleError> for StoreError {
    fn from(error: vodozemac::PickleError) -> Self {
        Self::Pickle(error)
    }
}

/// In-memory keystore. On-disk layout:
/// `magic | version | kdf params | salt | nonce | ciphertext` (the first 33 bytes are the AEAD AAD).
pub struct Keystore {
    path: PathBuf,
    kek: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    entries: BTreeMap<String, Vec<u8>>,
}

impl Keystore {
    /// Create an empty keystore (nothing is written until an explicit [`Keystore::save`]).
    pub fn create(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self, StoreError> {
        let salt = sme_crypto::random_salt()?;
        let kdf = KdfParams::default();
        let kek = sme_crypto::derive_kek(password, &salt, &kdf)?;
        Ok(Self {
            path: path.into(),
            kek,
            salt,
            kdf,
            entries: BTreeMap::new(),
        })
    }

    /// Read from disk and open with the password; a wrong password or tampered file fails AEAD authentication.
    pub fn open(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self, StoreError> {
        let path = path.into();
        let bytes = fs::read(&path)?;
        if bytes.len() < HEADER_LEN + NONCE_LEN + TAG_LEN {
            return Err(StoreError::Corrupt(
                "file shorter than the smallest valid keystore",
            ));
        }
        if &bytes[..4] != MAGIC {
            return Err(StoreError::NotAKeystore);
        }
        let version = bytes[4];
        if version != VERSION {
            return Err(StoreError::UnsupportedVersion(version));
        }

        let kdf = KdfParams {
            m_cost: read_u32(&bytes, 5),
            t_cost: read_u32(&bytes, 9),
            p_cost: read_u32(&bytes, 13),
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[HEADER_LEN - SALT_LEN..HEADER_LEN]);

        let kek = sme_crypto::derive_kek(password, &salt, &kdf)?;
        let plaintext = sme_crypto::open(&kek, &bytes[..HEADER_LEN], &bytes[HEADER_LEN..])?;
        let entries: BTreeMap<String, Vec<u8>> =
            postcard::from_bytes(&plaintext).map_err(StoreError::Decode)?;

        Ok(Self {
            path,
            kek,
            salt,
            kdf,
            entries,
        })
    }

    pub fn put(&mut self, key: impl Into<String>, value: impl Into<Vec<u8>>) {
        self.entries.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    /// Iterate entries whose names start with `prefix` (used for `peer.pin.<id>` records).
    pub fn entries_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a str, &'a [u8])> + 'a {
        self.entries
            .iter()
            .filter(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.as_str(), value.as_slice()))
    }

    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Atomic write: write `*.tmp` then rename, Unix mode `0600` (docs/INFRA.md §6).
    pub fn save(&self) -> Result<(), StoreError> {
        let payload = postcard::to_allocvec(&self.entries).map_err(StoreError::Encode)?;
        let header = self.header();
        let sealed = sme_crypto::seal(&self.kek, &header, &payload)?;

        let mut file_bytes = header;
        file_bytes.extend_from_slice(&sealed);

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = self.path.with_extension("tmp");
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp_path)?;
            file.write_all(&file_bytes)?;
            file.sync_all()?;
        }

        #[cfg(windows)]
        {
            // Windows rename does not overwrite an existing file.
            if self.path.exists() {
                fs::remove_file(&self.path)?;
            }
        }
        fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    fn header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&self.kdf.m_cost.to_le_bytes());
        header.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        header.extend_from_slice(&self.kdf.p_cost.to_le_bytes());
        header.extend_from_slice(&self.salt);
        header
    }
}

/// Read one u32 from a header whose length was already checked.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}
