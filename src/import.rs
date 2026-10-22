//! One-off import from rustdesk-api's SQLite (PORTA.md §15, note 05 §8).

use crate::crypto::SecretBox;
use hbb_common::ResultType;
use sqlx::SqlitePool;
use std::path::Path;

/// `porta-server import rustdesk-api <src> [--dry-run]`: opens `src` read-only and imports into an
/// empty Porta database `db` in one transaction; `dry_run` only prints counts and conflicts.
pub(crate) async fn rustdesk_api(
    _db: &SqlitePool,
    _secret: &SecretBox,
    _src: &Path,
    _dry_run: bool,
) -> ResultType<()> {
    todo!()
}
