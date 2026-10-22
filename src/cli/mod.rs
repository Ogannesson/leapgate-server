//! Command line management (PORTA.md §14): `porta-server <subcommand> …`.
//! Opens the same database (`crate::database::open(&crate::database::db_url())`, which also runs the
//! migrations); subcommands that need runtime state talk to the local console (127.0.0.1:`port-1`).

use hbb_common::ResultType;

/// `args` starts at the subcommand (`["user", "add", "alice", …]`); `main` only dispatches here when
/// the first argument is one of the known subcommands. Note: `.env` / `-c` INI are not loaded in this mode.
pub fn run(_args: Vec<String>) -> ResultType<()> {
    todo!()
}
