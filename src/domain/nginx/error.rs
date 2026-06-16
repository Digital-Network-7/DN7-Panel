//! Nginx capability error code — the typed, exhaustive replacement for the
//! scattered `anyhow!("ERR_CODE:nginx.*")` string literals. Each variant owns
//! its stable `nginx.*` semantic code (aligned with the frontend `err.<code>`
//! map) in one place, so the code set can't drift or typo. Domain owns only the
//! semantic code; the `ERR_CODE:` transport marker the `op_err_body` boundary
//! parses is added in infra (per §2/§4).

/// An nginx capability error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NginxError {
    AccessNotFound,
    BadAccessName,
    BadAuthPw,
    BadAuthUser,
    BadCertName,
    BadCertNameChars,
    BadClientAddr,
    BadContainer,
    BadContainerPort,
    BadDomain,
    BadFilePath,
    BadStaticDir,
    BadStaticDirName,
    BadTarget,
    BadTrustCidr,
    CertDomainExists,
    CertNotFound,
    DupAuthUser,
    DuplicateDomain,
    ExtraConfBad,
    ExtraConfTooLong,
    LeIssueTimeout,
    LeNeedDomainSpecific,
    LeNoHttp01,
    LeVerifyTimeout,
    LocalRootAbs,
    LocalRootDenied,
    LocalRootMissing,
    LocalRootNotDir,
    ManualNoRenew,
    MissingAccessId,
    MissingCertName,
    MissingFilePath,
    MissingSiteId,
    NeedAccessName,
    NeedAuthPw,
    NeedCertDomain,
    NeedCertKey,
    NeedContainer,
    NeedDomain,
    NeedRoot,
    NeedStaticDir,
    NeedTarget,
    NotSetup,
    SiteNotFound,
    TooManyRules,
    UnknownCertMode,
    UnknownSiteKind,
    UnknownUploadMode,
}

impl NginxError {
    /// The stable, `nginx.`-namespaced semantic code (no transport prefix).
    pub(crate) fn code(self) -> &'static str {
        use NginxError::*;
        match self {
            AccessNotFound => "nginx.access_not_found",
            BadAccessName => "nginx.bad_access_name",
            BadAuthPw => "nginx.bad_auth_pw",
            BadAuthUser => "nginx.bad_auth_user",
            BadCertName => "nginx.bad_cert_name",
            BadCertNameChars => "nginx.bad_cert_name_chars",
            BadClientAddr => "nginx.bad_client_addr",
            BadContainer => "nginx.bad_container",
            BadContainerPort => "nginx.bad_container_port",
            BadDomain => "nginx.bad_domain",
            BadFilePath => "nginx.bad_file_path",
            BadStaticDir => "nginx.bad_static_dir",
            BadStaticDirName => "nginx.bad_static_dir_name",
            BadTarget => "nginx.bad_target",
            BadTrustCidr => "nginx.bad_trust_cidr",
            CertDomainExists => "nginx.cert_domain_exists",
            CertNotFound => "nginx.cert_not_found",
            DupAuthUser => "nginx.dup_auth_user",
            DuplicateDomain => "nginx.duplicate_domain",
            ExtraConfBad => "nginx.extra_conf_bad",
            ExtraConfTooLong => "nginx.extra_conf_too_long",
            LeIssueTimeout => "nginx.le_issue_timeout",
            LeNeedDomainSpecific => "nginx.le_need_domain_specific",
            LeNoHttp01 => "nginx.le_no_http01",
            LeVerifyTimeout => "nginx.le_verify_timeout",
            LocalRootAbs => "nginx.local_root_abs",
            LocalRootDenied => "nginx.local_root_denied",
            LocalRootMissing => "nginx.local_root_missing",
            LocalRootNotDir => "nginx.local_root_not_dir",
            ManualNoRenew => "nginx.manual_no_renew",
            MissingAccessId => "nginx.missing_access_id",
            MissingCertName => "nginx.missing_cert_name",
            MissingFilePath => "nginx.missing_file_path",
            MissingSiteId => "nginx.missing_site_id",
            NeedAccessName => "nginx.need_access_name",
            NeedAuthPw => "nginx.need_auth_pw",
            NeedCertDomain => "nginx.need_cert_domain",
            NeedCertKey => "nginx.need_cert_key",
            NeedContainer => "nginx.need_container",
            NeedDomain => "nginx.need_domain",
            NeedRoot => "nginx.need_root",
            NeedStaticDir => "nginx.need_static_dir",
            NeedTarget => "nginx.need_target",
            NotSetup => "nginx.not_setup",
            SiteNotFound => "nginx.site_not_found",
            TooManyRules => "nginx.too_many_rules",
            UnknownCertMode => "nginx.unknown_cert_mode",
            UnknownSiteKind => "nginx.unknown_site_kind",
            UnknownUploadMode => "nginx.unknown_upload_mode",
        }
    }
}

impl std::fmt::Display for NginxError {
    /// Renders the semantic code only; the infra boundary adds the `ERR_CODE:`
    /// marker when building the wire error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for NginxError {}

#[cfg(test)]
mod nginx_error_tests {
    use super::*;

    #[test]
    fn codes_namespaced_snake_case_and_wire_stable() {
        // A representative code matches the exact frontend `err.*` string.
        assert_eq!(NginxError::DuplicateDomain.code(), "nginx.duplicate_domain");
        // Display is the semantic code only (no transport prefix in domain).
        assert_eq!(NginxError::SiteNotFound.to_string(), "nginx.site_not_found");
        // Exhaustive shape check across every variant.
        for e in [
            NginxError::AccessNotFound,
            NginxError::BadAccessName,
            NginxError::BadAuthPw,
            NginxError::BadAuthUser,
            NginxError::BadCertName,
            NginxError::BadCertNameChars,
            NginxError::BadClientAddr,
            NginxError::BadContainer,
            NginxError::BadContainerPort,
            NginxError::BadDomain,
            NginxError::BadFilePath,
            NginxError::BadStaticDir,
            NginxError::BadStaticDirName,
            NginxError::BadTarget,
            NginxError::BadTrustCidr,
            NginxError::CertDomainExists,
            NginxError::CertNotFound,
            NginxError::DupAuthUser,
            NginxError::DuplicateDomain,
            NginxError::ExtraConfBad,
            NginxError::ExtraConfTooLong,
            NginxError::LeIssueTimeout,
            NginxError::LeNeedDomainSpecific,
            NginxError::LeNoHttp01,
            NginxError::LeVerifyTimeout,
            NginxError::LocalRootAbs,
            NginxError::LocalRootDenied,
            NginxError::LocalRootMissing,
            NginxError::LocalRootNotDir,
            NginxError::ManualNoRenew,
            NginxError::MissingAccessId,
            NginxError::MissingCertName,
            NginxError::MissingFilePath,
            NginxError::MissingSiteId,
            NginxError::NeedAccessName,
            NginxError::NeedAuthPw,
            NginxError::NeedCertDomain,
            NginxError::NeedCertKey,
            NginxError::NeedContainer,
            NginxError::NeedDomain,
            NginxError::NeedRoot,
            NginxError::NeedStaticDir,
            NginxError::NeedTarget,
            NginxError::NotSetup,
            NginxError::SiteNotFound,
            NginxError::TooManyRules,
            NginxError::UnknownCertMode,
            NginxError::UnknownSiteKind,
            NginxError::UnknownUploadMode,
        ] {
            let c = e.code();
            assert!(c.starts_with("nginx."), "{c} not namespaced");
            assert!(
                c[6..]
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{c} not snake_case"
            );
        }
    }
}
