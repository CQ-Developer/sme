//! Secret-free local config (docs/INFRA.md §6): account ID, password salt and Argon2id parameters.
//!
//! Stored next to the keystore (`<keystore>.config.json`). It holds no secrets:
//! even if read by someone else it only reveals who the user is, not any message, and cannot open the keystore.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sme_proto::{AccountId, KdfParams};

use crate::StoreError;

/// Local config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConfig {
    pub account_id: AccountId,
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
}

impl LocalConfig {
    /// First run: random account ID (D16) and random password salt.
    pub fn new_random() -> Result<Self, StoreError> {
        let account_id = AccountId::random();
        let kdf_salt = sme_crypto::random_salt().map_err(StoreError::Crypto)?;
        Ok(Self {
            account_id,
            kdf_salt,
            kdf_params: KdfParams {
                m_cost: 19_456,
                t_cost: 2,
                p_cost: 1,
            },
        })
    }

    /// Derive the config file name from the keystore path.
    pub fn path_for(keystore_path: &Path) -> PathBuf {
        keystore_path.with_extension("config.json")
    }

    /// Read the config; returns `None` when the file is missing (first run).
    pub fn load(keystore_path: &Path) -> Result<Option<Self>, StoreError> {
        let path = Self::path_for(keystore_path);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError::Corrupt("config.json is not valid JSON"))
    }

    /// Atomic write with Unix mode `0600`.
    pub fn save(&self, keystore_path: &Path) -> Result<(), StoreError> {
        let path = Self::path_for(keystore_path);
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| StoreError::Corrupt("cannot encode config"))?;

        let tmp_path = path.with_extension("tmp");
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        #[cfg(windows)]
        {
            if path.exists() {
                fs::remove_file(&path)?;
            }
        }
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }
}
