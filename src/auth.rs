//! Passwords and API tokens (PORTA.md §11).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hbb_common::{anyhow::anyhow, log, rand::RngCore, ResultType};
use md5::{Digest as _, Md5};
use once_cell::sync::Lazy;
use sha2::Sha256;
use sqlx::SqlitePool;

/// Result of checking a password against a stored `user.password_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCheck {
    Mismatch,
    Ok,
    /// Correct, but stored in an imported format (bcrypt or `md5:`): re-store it with `hash_password`.
    OkNeedsUpgrade,
}

/// argon2id with the crate's default parameters.
pub fn hash_password(plain: &str) -> ResultType<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map_err(|e| anyhow!("Failed to hash password: {e}"))?
        .to_string())
}

/// Recognizes `$argon2id$…`, bcrypt (`$2a$`/`$2b$`/`$2y$`) and rustdesk-api's `md5:<hex>`
/// (`md5(plain + "rustdesk-api")`, note 05 §3). An empty hash (also what login passes for an
/// unknown user) never matches, but still costs one argon2id check against [`DUMMY_HASH`], so the
/// response time does not tell whether a user name exists or can log in with a password.
pub fn verify_password(plain: &str, stored: &str) -> PasswordCheck {
    let ok = |b: bool, upgrade: bool| match (b, upgrade) {
        (false, _) => PasswordCheck::Mismatch,
        (true, false) => PasswordCheck::Ok,
        (true, true) => PasswordCheck::OkNeedsUpgrade,
    };
    if stored.starts_with("$argon2id$") {
        let matched = match PasswordHash::new(stored) {
            Ok(hash) => Argon2::default()
                .verify_password(plain.as_bytes(), &hash)
                .is_ok(),
            Err(e) => {
                log::error!("Malformed argon2 hash in database: {e}");
                false
            }
        };
        ok(matched, false)
    } else if ["$2a$", "$2b$", "$2y$"].iter().any(|p| stored.starts_with(p)) {
        let matched = match bcrypt::verify(plain, stored) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Malformed bcrypt hash in database: {e}");
                false
            }
        };
        ok(matched, true)
    } else if let Some(hex) = stored.strip_prefix("md5:") {
        let digest = Md5::digest(format!("{plain}rustdesk-api").as_bytes());
        ok(to_hex(&digest) == hex.to_ascii_lowercase(), true)
    } else {
        if let Ok(hash) = PasswordHash::new(&DUMMY_HASH) {
            let _ = Argon2::default().verify_password(plain.as_bytes(), &hash);
        }
        PasswordCheck::Mismatch
    }
}

/// An argon2id hash of a random password with the same parameters as [`hash_password`]; made once.
static DUMMY_HASH: Lazy<String> = Lazy::new(|| hash_password(&new_token()).unwrap_or_default());

/// 32 random bytes, base64url without padding. Only `token_hash` of it is stored.
pub fn new_token() -> String {
    let mut buf = [0u8; 32];
    hbb_common::rand::thread_rng().fill_bytes(&mut buf);
    base64::encode_config(buf, base64::URL_SAFE_NO_PAD)
}

/// sha256 hex, the `token.token_hash` column.
pub fn token_hash(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

/// `(user_id, user_name, device_id)` of a valid token whose account is enabled.
/// Used by the rendezvous side (`PunchHoleRequest.token`); does not touch `last_used_at`.
pub async fn token_owner(db: &SqlitePool, token: &str) -> Option<(i64, String, String)> {
    if token.is_empty() {
        return None;
    }
    let res = sqlx::query_as::<_, (i64, String, String)>(
        "select u.id, u.name, t.device_id from token t join user u on u.id = t.user_id
         where t.token_hash = ? and u.status = 1",
    )
    .bind(token_hash(token))
    .fetch_optional(db)
    .await;
    match res {
        Ok(v) => v,
        Err(e) => {
            log::error!("token_owner: {e}");
            None
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    #[test]
    fn argon2id_roundtrip() {
        let h = hash_password("s3cret").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert_eq!(verify_password("s3cret", &h), PasswordCheck::Ok);
        assert_eq!(verify_password("wrong", &h), PasswordCheck::Mismatch);
    }

    #[test]
    fn imported_formats_need_upgrade() {
        let b = bcrypt::hash("pw", 4).unwrap();
        assert_eq!(verify_password("pw", &b), PasswordCheck::OkNeedsUpgrade);
        assert_eq!(verify_password("px", &b), PasswordCheck::Mismatch);
        for prefix in ["$2a$", "$2y$"] {
            let other = format!("{prefix}{}", &b[4..]);
            assert_eq!(verify_password("pw", &other), PasswordCheck::OkNeedsUpgrade);
        }
        // md5("pw" + "rustdesk-api")
        let hex = to_hex(&Md5::digest(b"pwrustdesk-api"));
        assert_eq!(verify_password("pw", &format!("md5:{hex}")), PasswordCheck::OkNeedsUpgrade);
        assert_eq!(
            verify_password("pw", &format!("md5:{}", hex.to_uppercase())),
            PasswordCheck::OkNeedsUpgrade
        );
        assert_eq!(verify_password("px", &format!("md5:{hex}")), PasswordCheck::Mismatch);
    }

    #[test]
    fn empty_or_unknown_hash_never_matches() {
        assert_eq!(verify_password("", ""), PasswordCheck::Mismatch);
        assert_eq!(verify_password("pw", "pw"), PasswordCheck::Mismatch);
        assert_eq!(verify_password("pw", "$argon2id$garbage"), PasswordCheck::Mismatch);
    }

    #[test]
    fn empty_hash_costs_an_argon2_check() {
        let real = hash_password("pw").unwrap();
        let (dummy, real_parsed) = (PasswordHash::new(&DUMMY_HASH).unwrap(), PasswordHash::new(&real).unwrap());
        assert_eq!(dummy.algorithm, real_parsed.algorithm);
        assert_eq!(dummy.params.to_string(), real_parsed.params.to_string());
        // Fastest of three, so other tests on the same cores do not decide it.
        let fastest = |stored: &str| {
            (0..3)
                .map(|_| {
                    let start = std::time::Instant::now();
                    verify_password("guess", stored);
                    start.elapsed()
                })
                .min()
                .unwrap()
        };
        let (empty, argon2) = (fastest(""), fastest(&real));
        assert!(empty * 4 > argon2, "empty hash {empty:?}, argon2id {argon2:?}");
    }

    #[test]
    fn tokens() {
        let t = new_token();
        assert_eq!(t.len(), 43);
        assert!(t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert_ne!(t, new_token());
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn token_owner_lookup() {
        let (_dir, db) = crate::testutil::pool().await;
        let (uid, token) = crate::testutil::create_user(&db, "alice", "pw", false).await;
        sqlx::query("update token set device_id = '123456789' where user_id = ?")
            .bind(uid)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(
            token_owner(&db, &token).await,
            Some((uid, "alice".to_owned(), "123456789".to_owned()))
        );
        assert_eq!(token_owner(&db, "").await, None);
        assert_eq!(token_owner(&db, "nope").await, None);
        sqlx::query("update user set status = 0 where id = ?")
            .bind(uid)
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(token_owner(&db, &token).await, None);
    }
}
