//! Olm 账号与会话的持久化（M1 / M2）。
//!
//! 格式完全走 vodozemac 的公开 API：`AccountPickle::encrypt(kek)` /
//! `SessionPickle::encrypt(kek)`，条目本身再由 keystore 的 AEAD 整体保护（D23）。
//! 不依赖任何内部序列化格式。
//!
//! 会话条目名带对端账号（`olm.session.<peer>.<session_id>`）：vodozemac 的
//! `Session` 不暴露对端，恢复时必须靠条目名归档。

use sme_proto::AccountId;
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

use crate::{Keystore, StoreError};

/// keystore 里账号 pickle 的条目名。
pub const ACCOUNT_ENTRY: &str = "olm.account";

/// keystore 里会话 pickle 的条目名前缀。
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

    /// 用 KEK 加密并保存一个 Olm 会话；同一个对端会覆盖旧会话。
    pub fn save_session(&mut self, peer: AccountId, session: &Session) -> Result<(), StoreError> {
        let encrypted = session.pickle().encrypt(&self.kek);
        self.put(
            session_entry(peer, &session.session_id()),
            encrypted.into_bytes(),
        );
        Ok(())
    }

    /// 恢复全部会话，带上各自的对端账号。
    pub fn load_sessions(&self) -> Result<Vec<(AccountId, Session)>, StoreError> {
        let mut sessions = Vec::new();
        for (key, ciphertext) in &self.entries {
            let Some(rest) = key.strip_prefix(SESSION_ENTRY_PREFIX) else {
                continue;
            };
            let Some((peer, _session_id)) = rest.split_once('.') else {
                return Err(StoreError::Corrupt("malformed olm session entry name"));
            };
            let peer = AccountId::parse_base32(peer)
                .map_err(|_| StoreError::Corrupt("malformed olm session entry name"))?;
            let ciphertext = std::str::from_utf8(ciphertext)
                .map_err(|_| StoreError::Corrupt("olm session entry is not UTF-8"))?;
            let pickle = SessionPickle::from_encrypted(ciphertext, &self.kek)?;
            sessions.push((peer, Session::from(pickle)));
        }
        Ok(sessions)
    }
}

fn session_entry(peer: AccountId, session_id: &str) -> String {
    format!("{SESSION_ENTRY_PREFIX}{peer}.{session_id}")
}
