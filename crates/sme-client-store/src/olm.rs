//! Persistence for Olm accounts and sessions (M1 / M2).
//!
//! The format uses only vodozemac public APIs: `AccountPickle::encrypt(kek)` /
//! `SessionPickle::encrypt(kek)`, with the entry as a whole additionally protected by the keystore AEAD (D23).
//! No internal serialization formats are relied upon.
//!
//! Session entry names carry the peer account (`olm.session.<peer>.<session_id>`): vodozemac's
//! `Session` does not expose the peer, so restore relies on the entry name to file it.

use sme_proto::AccountId;
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

use crate::{Keystore, StoreError};

/// Entry name for the account pickle in the keystore.
pub const ACCOUNT_ENTRY: &str = "olm.account";

/// Entry-name prefix for session pickles in the keystore.
pub const SESSION_ENTRY_PREFIX: &str = "olm.session.";

impl Keystore {
    /// Encrypt and save the Olm account (identity keys + one-time prekeys) with the KEK.
    pub fn save_account(&mut self, account: &Account) -> Result<(), StoreError> {
        let encrypted = account.pickle().encrypt(&self.kek);
        self.put(ACCOUNT_ENTRY, encrypted.into_bytes());
        Ok(())
    }

    /// Restore the account; returns `None` when nothing was ever saved.
    pub fn load_account(&self) -> Result<Option<Account>, StoreError> {
        let Some(ciphertext) = self.get(ACCOUNT_ENTRY) else {
            return Ok(None);
        };
        let ciphertext = std::str::from_utf8(ciphertext)
            .map_err(|_| StoreError::Corrupt("olm account entry is not UTF-8"))?;
        let pickle = AccountPickle::from_encrypted(ciphertext, &self.kek)?;
        Ok(Some(Account::from(pickle)))
    }

    /// Encrypt and save one Olm session with the KEK; the same peer overwrites the old session.
    pub fn save_session(&mut self, peer: AccountId, session: &Session) -> Result<(), StoreError> {
        let encrypted = session.pickle().encrypt(&self.kek);
        self.put(
            session_entry(peer, &session.session_id()),
            encrypted.into_bytes(),
        );
        Ok(())
    }

    /// Restore all sessions together with their peer accounts.
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
