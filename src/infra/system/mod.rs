//! System-account layer: the OS side of a panel user.
//!
//! A panel user maps 1:1 to a real Linux account (same name). The privileged,
//! OS-touching operations (useradd/userdel/usermod, sudo-group, chpasswd,
//! passwd-db lookups) live in `ops`; this root is pure assembly.

mod ops;

pub(crate) use ops::*;
