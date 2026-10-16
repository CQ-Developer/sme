//! Olm 账号与会话的持久化（M1）。
//!
//! 格式完全走 vodozemac 的公开 API：`AccountPickle::encrypt(kek)` /
//! `SessionPickle::encrypt(kek)`，条目本身再由 keystore 的 AEAD 整体保护（D23）。
//! 不依赖任何内部序列化格式。

use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

use crate::{Keystore, StoreError};

/// keystore 里账号 pickle 的条目名。
pub const ACCOUNT_ENTRY: &str = "olm.account";

/// keystore 里会话 pickle 的条目名前缀，后面接 `Session::session_id()`。
pub const SESSION_ENTRY_PREFIX: &str = "olm.session.";

impl Keystore {
    /// 用 KEK 加密并保存 Olm 账号（身份密钥 + 一次性预密钥）。
    pub fn save_account(&mut self, account: &Account) -> Result<(), StoreError> {
        let encrypted = account.pickle().encrypt(&self.kek);
        self.put(ACCOUNT_ENTRY, encrypted.into_bytes());
        Ok(())
    }

    /// 恢复账号；从未保存过时返回 `None`。
    pub fn load_account(&self) -> Result<Option<Account>, StoreError> {
        let Some(ciphertext) = self.get(ACCOUNT_ENTRY) else {
            return Ok(None);
        };
        let ciphertext = std::str::from_utf8(ciphertext)
            .map_err(|_| StoreError::Corrupt("olm account entry is not UTF-8"))?;
        let pickle = AccountPickle::from_encrypted(ciphertext, &self.kek)?;
        Ok(Some(Account::from(pickle)))
    }

    /// 用 KEK 加密并保存一个 Olm 会话，条目名由 `session_id` 决定。
    pub fn save_session(&mut self, session: &Session) -> Result<(), StoreError> {
        let encrypted = session.pickle().encrypt(&self.kek);
        self.put(session_entry(&session.session_id()), encrypted.into_bytes());
        Ok(())
    }

    /// 恢复指定会话；不存在时返回 `None`。
    pub fn load_session(&self, session_id: &str) -> Result<Option<Session>, StoreError> {
        let Some(ciphertext) = self.get(&session_entry(session_id)) else {
            return Ok(None);
        };
        let ciphertext = std::str::from_utf8(ciphertext)
            .map_err(|_| StoreError::Corrupt("olm session entry is not UTF-8"))?;
        let pickle = SessionPickle::from_encrypted(ciphertext, &self.kek)?;
        Ok(Some(Session::from(pickle)))
    }

    /// 已保存的全部会话 ID；重启后据此逐个恢复。
    pub fn session_ids(&self) -> Vec<String> {
        self.entries
            .keys()
            .filter_map(|key| key.strip_prefix(SESSION_ENTRY_PREFIX))
            .map(str::to_owned)
            .collect()
    }
}

fn session_entry(session_id: &str) -> String {
    format!("{SESSION_ENTRY_PREFIX}{session_id}")
}
