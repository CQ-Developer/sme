//! 本地 keystore：加密落盘身份密钥、Olm 会话、通讯录与 TOFU pin（D13′、D14）。
//!
//! 这是唯一允许写盘的客户端 crate。文件里**不得出现任何消息字节**（I11）：
//! 负载在写盘前由 [`sme_crypto::seal`] 整体加密，只有口令派生的 KEK 能解开。
//! 本 crate 不定义「消息」这种字段，调用方放进去的只是带名字的字节。

mod config;
mod olm;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sme_crypto::{CryptoError, KEY_LEN, KdfParams, NONCE_LEN, SALT_LEN};
use zeroize::Zeroizing;

pub use config::LocalConfig;

/// 文件头 magic：「SME Keystore」。
const MAGIC: &[u8; 4] = b"SMEK";
const VERSION: u8 = 1;

/// magic(4) + version(1) + Argon2id 参数(3×4) + salt(16)。
const HEADER_LEN: usize = 4 + 1 + 12 + SALT_LEN;

/// ChaCha20-Poly1305 的 tag 长度。
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

/// 内存中的 keystore。磁盘布局：
/// `magic | version | kdf 参数 | salt | nonce | ciphertext`（前 33 字节是 AEAD 的 AAD）。
pub struct Keystore {
    path: PathBuf,
    kek: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    entries: BTreeMap<String, Vec<u8>>,
}

impl Keystore {
    /// 新建一个空 keystore（不落盘，需显式 [`Keystore::save`]）。
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

    /// 读盘并用口令打开；口令错误或文件被改都会失败（AEAD 认证）。
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

    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.entries.remove(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 原子写盘：先写 `*.tmp` 再 rename，Unix 权限 `0600`（docs/INFRA.md §6）。
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
            // Windows 的 rename 不覆盖已存在文件。
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

/// 读取已确认长度的头部里的一个 u32。
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(buf)
}
