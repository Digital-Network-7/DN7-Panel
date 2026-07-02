//! `dn7crun` — a thin runc-style entry over the runtime, used to drive + test it
//! directly. The dispatch lives in [`dn7_container::cli`] (shared with the
//! unified `dn7 container` CLI). Linux-only.

#[cfg(target_os = "linux")]
fn main() {
    // If re-exec'd as a container init (`__dn7init ...`), run it and never return.
    dn7_container::container::reexec::run_init_if_invoked();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match dn7_container::cli::run(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("dn7crun: {msg}");
            1
        }
    };
    std::process::exit(code);
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("dn7crun runs on Linux only (it drives namespaces/cgroups directly).");
    std::process::exit(2);
}
