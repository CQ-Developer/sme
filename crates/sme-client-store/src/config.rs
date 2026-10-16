//! 不含秘密的本地配置（docs/INFRA.md §6）：账号 ID、口令盐与 Argon2id 参数。
//!
//! 放在 keystore 旁边（`<keystore>.config.json`）。里面没有任何秘密：
//! 即使被读走，也只能看到「这个人是谁」，看不到消息，也打不开 keystore。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sme_proto::{AccountId, KdfParams};

use crate::StoreError;

/// 本地配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalConfig {
    pub account_id: AccountId,
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
}

impl LocalConfig {
    /// 首次启动：随机账号 ID（D16）与随机口令盐。
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

    /// 配置文件名由 keystore 路径派生。
    pub fn path_for(keystore_path: &Path) -> PathBuf {
        keystore_path.with_extension("config.json")
    }

    /// 读取配置；文件不存在时返回 `None`（首次运行）。
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

    /// 原子写入，Unix 权限 `0600`。
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
