fn main() {
    hbb_common::gen_version();
    // sqlx::migrate! embeds the files at compile time; rebuild when they change.
    println!("cargo:rerun-if-changed=migrations");
}
