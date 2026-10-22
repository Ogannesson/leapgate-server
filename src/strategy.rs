//! Effective heartbeat options and their version number (PORTA.md §10).
//! Shared by the heartbeat handler (`api/device.rs`) and the command line.

use hbb_common::ResultType;
use sha2::{Digest as _, Sha256};
use sqlx::SqlitePool;
use std::collections::BTreeMap;

/// `strategy_option.scope` and `device_policy.device_id` of the global rows.
pub const GLOBAL: &str = "*";

/// Effective options of a device (global ⊕ device; a device row overrides the global one even when
/// its value is `''`) and their `rev`. A `''` value is a tombstone: the client deletes that key.
pub async fn effective(db: &SqlitePool, device_id: &str) -> ResultType<(i64, BTreeMap<String, String>)> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "select scope, key, value from strategy_option where scope = ? or scope = ?
         order by scope = ?",
    )
    .bind(GLOBAL)
    .bind(device_id)
    .bind(device_id)
    .fetch_all(db)
    .await?;
    // Global rows come first, so device rows overwrite them.
    let options: BTreeMap<String, String> = rows.into_iter().map(|(_, k, v)| (k, v)).collect();
    let global_epoch = epoch(db, GLOBAL).await?;
    let device_epoch = epoch(db, device_id).await?;
    Ok((rev(&options, global_epoch, device_epoch), options))
}

async fn epoch(db: &SqlitePool, device_id: &str) -> ResultType<i64> {
    Ok(
        sqlx::query_scalar::<_, i64>("select strategy_epoch from device_policy where device_id = ?")
            .bind(device_id)
            .fetch_optional(db)
            .await?
            .unwrap_or(0),
    )
}

/// sha256 of the canonical JSON `[options sorted by key, global_epoch, device_epoch]`;
/// first 8 bytes as big-endian i64, masked to non-negative; 0 becomes 1.
pub fn rev(options: &BTreeMap<String, String>, global_epoch: i64, device_epoch: i64) -> i64 {
    let canonical = serde_json::json!([options, global_epoch, device_epoch]).to_string();
    let digest = Sha256::digest(canonical.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    match i64::from_be_bytes(first) & i64::MAX {
        0 => 1,
        v => v,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    async fn set(db: &SqlitePool, scope: &str, key: &str, value: &str) {
        sqlx::query("insert or replace into strategy_option(scope, key, value) values(?, ?, ?)")
            .bind(scope)
            .bind(key)
            .bind(value)
            .execute(db)
            .await
            .unwrap();
    }

    async fn bump(db: &SqlitePool, device_id: &str) {
        sqlx::query(
            "insert into device_policy(device_id, strategy_epoch) values(?, 1)
             on conflict(device_id) do update set strategy_epoch = strategy_epoch + 1",
        )
        .bind(device_id)
        .execute(db)
        .await
        .unwrap();
    }

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[tokio::test]
    async fn merge_override_tombstone_and_epochs() {
        let (_dir, db) = crate::testutil::pool().await;
        // The migration seeds the global relay-server tombstone.
        let (r0, opts) = effective(&db, "dev1").await.unwrap();
        assert_eq!(opts, map(&[("relay-server", "")]));
        assert!(r0 > 0);
        assert_eq!(effective(&db, "dev2").await.unwrap().0, r0);

        // Device value overrides the global one; other devices keep the global value.
        set(&db, GLOBAL, "a", "1").await;
        set(&db, "dev1", "a", "2").await;
        let (r1, opts) = effective(&db, "dev1").await.unwrap();
        assert_eq!(opts, map(&[("a", "2"), ("relay-server", "")]));
        assert_eq!(effective(&db, "dev2").await.unwrap().1, map(&[("a", "1"), ("relay-server", "")]));
        assert_ne!(r1, r0);

        // A device-level '' still overrides (tells this device to delete the key).
        set(&db, "dev1", "a", "").await;
        let (r2, opts) = effective(&db, "dev1").await.unwrap();
        assert_eq!(opts["a"], "");
        assert_ne!(r2, r1);

        // Forgetting the device row falls back to the global value.
        sqlx::query("delete from strategy_option where scope = 'dev1'")
            .execute(&db)
            .await
            .unwrap();
        let (r3, opts) = effective(&db, "dev1").await.unwrap();
        assert_eq!(opts["a"], "1");
        assert_eq!(r3, effective(&db, "dev2").await.unwrap().0);

        // Epoch bumps change the rev without changing the options.
        bump(&db, "dev1").await;
        let (r4, _) = effective(&db, "dev1").await.unwrap();
        assert_ne!(r4, r3);
        assert_eq!(effective(&db, "dev2").await.unwrap().0, r3);
        bump(&db, GLOBAL).await;
        let (r5, _) = effective(&db, "dev2").await.unwrap();
        assert_ne!(r5, r3);
        assert_ne!(effective(&db, "dev1").await.unwrap().0, r4);
    }

    #[test]
    fn rev_is_stable_and_positive() {
        let m = map(&[("b", "2"), ("a", "1")]);
        assert_eq!(rev(&m, 0, 0), rev(&m.clone(), 0, 0));
        assert!(rev(&m, 0, 0) > 0);
        assert_ne!(rev(&m, 0, 0), rev(&m, 1, 0));
        assert_ne!(rev(&m, 1, 0), rev(&m, 0, 1));
        assert_ne!(rev(&m, 0, 0), rev(&map(&[("a", "1")]), 0, 0));
    }
}
