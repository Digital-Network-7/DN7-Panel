//! Namespace flag mapping. P1 *creates* fresh namespaces (the `path: None` case);
//! *joining* an existing namespace (`setns`, used to share a pod's netns) lands
//! with the networking work in P5.

use nix::sched::CloneFlags;

use crate::oci::spec::{Namespace, NamespaceType};

/// Translate one OCI namespace kind to its `clone(2)` flag.
pub fn flag_for(t: NamespaceType) -> CloneFlags {
    match t {
        NamespaceType::Pid => CloneFlags::CLONE_NEWPID,
        NamespaceType::Network => CloneFlags::CLONE_NEWNET,
        NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
        NamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
        NamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
        NamespaceType::User => CloneFlags::CLONE_NEWUSER,
        NamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
    }
}

/// The combined clone flags for every namespace the spec asks us to *create*
/// (those without a `path` to join). Namespaces with a `path` are joined via
/// `setns` later and contribute no clone flag.
///
/// P1 note: `user` and `cgroup` namespaces are deliberately *excluded* from the
/// clone here even if requested — user-ns id-mapping and cgroup-ns isolation are
/// P3/P7 concerns, and creating them half-configured would break the rootfs/
/// cgroup setup. They parse and are ignored with intent.
pub fn create_flags(namespaces: &[Namespace]) -> CloneFlags {
    let mut flags = CloneFlags::empty();
    for ns in namespaces {
        if ns.path.is_some() {
            continue; // join via setns (P5), not a clone flag
        }
        match ns.typ {
            NamespaceType::User | NamespaceType::Cgroup => {} // deferred (see above)
            other => flags |= flag_for(other),
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::spec::Namespace;

    fn ns(typ: NamespaceType) -> Namespace {
        Namespace { typ, path: None }
    }

    #[test]
    fn maps_requested_namespaces_to_clone_flags() {
        let f = create_flags(&[
            ns(NamespaceType::Pid),
            ns(NamespaceType::Mount),
            ns(NamespaceType::Network),
            ns(NamespaceType::Ipc),
            ns(NamespaceType::Uts),
        ]);
        for want in [
            CloneFlags::CLONE_NEWPID,
            CloneFlags::CLONE_NEWNS,
            CloneFlags::CLONE_NEWNET,
            CloneFlags::CLONE_NEWIPC,
            CloneFlags::CLONE_NEWUTS,
        ] {
            assert!(f.contains(want), "missing {want:?}");
        }
    }

    #[test]
    fn user_and_cgroup_namespaces_are_deferred() {
        let f = create_flags(&[ns(NamespaceType::User), ns(NamespaceType::Cgroup)]);
        assert!(f.is_empty(), "user/cgroup ns should not be cloned in P1");
    }

    #[test]
    fn namespace_with_a_path_is_joined_not_cloned() {
        let joined = Namespace {
            typ: NamespaceType::Network,
            path: Some("/proc/123/ns/net".into()),
        };
        assert!(create_flags(&[joined]).is_empty());
    }
}
