//! `dn7 container <verb> …` (alias `ct`) — the container runtime, via the shared
//! dispatch in `dn7_container::cli` (the same code `dn7crun` runs).

pub fn run(args: &[String]) -> i32 {
    match dn7_container::cli::run(args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("dn7 container: {msg}");
            1
        }
    }
}
