//! KEK 派生（Argon2id）与 AEAD 封包（plan.md §6.1）。
//!
//! 这一层只把口令变成 KEK、把字节变成密文，不接触文件与网络（I2 门禁）。
//! keystore 的磁盘格式由 `sme-client-store` 定义。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

/// 口令盐长度（docs/INFRA.md §3：由客户端生成）。
pub const SALT_LEN: usize = 16;

/// KEK 长度。
pub const KEY_LEN: usize = 32;

/// AEAD nonce 长度；[`seal`] 会把它附加在密文前面。
pub const NONCE_LEN: usize = 12;

/// Argon2id 参数。默认取 OWASP 推荐的第一档（19 MiB / t=2 / p=1），
/// 单次派生几十毫秒，兼顾移动端。参数随 keystore 一起保存，未来可升级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// 内存开销，单位 KiB。
    pub m_cost: u32,
    /// 迭代次数。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidKdfParams,
    KdfFailure(argon2::Error),
    RandomSource,
    SealFailure,
    OpenFailure,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKdfParams => write!(f, "invalid Argon2id parameters"),
            Self::KdfFailure(error) => write!(f, "Argon2id key derivation failed: {error}"),
            Self::RandomSource => write!(f, "OS random source unavailable"),
            Self::SealFailure => write!(f, "AEAD sealing failed"),
            Self::OpenFailure => {
                write!(
                    f,
                    "AEAD authentication failed (wrong password or tampered data)"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KdfFailure(error) => Some(error),
            _ => None,
        }
    }
}

/// 生成一个随机盐。
pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|_| CryptoError::RandomSource)?;
    Ok(salt)
}

/// `Argon2id(口令, 盐, 参数)` → KEK。KEK 只在内存中存在，用后随 [`Zeroizing`] 擦除。
pub fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut kek[..])
        .map_err(CryptoError::KdfFailure)?;
    Ok(kek)
}

/// 加密，返回 `nonce || ciphertext+tag`。`aad` 参与认证但不加密。
pub fn seal(kek: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(kek.into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomSource)?;

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::SealFailure)?;

    let mut sealed = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// 解开 [`seal`] 的输出；认证失败（口令不对或数据被改）返回 [`CryptoError::OpenFailure`]。
pub fn open(
    kek: &[u8; KEY_LEN],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::OpenFailure);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(kek.into());

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::OpenFailure)?;
    Ok(Zeroizing::new(plaintext))
}
