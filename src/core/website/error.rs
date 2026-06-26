//! Nginx capability error code — the typed, exhaustive replacement for the
//! scattered `anyhow!("ERR_CODE:nginx.*")` string literals. Each variant owns
//! its stable `nginx.*` semantic code (aligned with the frontend `err.<code>`
//! map) in one place, so the code set can't drift or typo. Domain owns only the
//! semantic code; the `ERR_CODE:` transport marker the `op_err_body` boundary
//! parses is added in infra (per §2/§4).

/// An nginx capability error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebsiteError {
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

impl WebsiteError {
    /// The stable, `nginx.`-namespaced semantic code (no transport prefix).
    pub(crate) fn code(self) -> &'static str {
        use WebsiteError::*;
        match self {
            AccessNotFound => "website.access_not_found",
            BadAccessName => "website.bad_access_name",
            BadAuthPw => "website.bad_auth_pw",
            BadAuthUser => "website.bad_auth_user",
            BadCertName => "website.bad_cert_name",
            BadCertNameChars => "website.bad_cert_name_chars",
            BadClientAddr => "website.bad_client_addr",
            BadContainer => "website.bad_container",
            BadContainerPort => "website.bad_container_port",
            BadDomain => "website.bad_domain",
            BadFilePath => "website.bad_file_path",
            BadStaticDir => "website.bad_static_dir",
            BadStaticDirName => "website.bad_static_dir_name",
            BadTarget => "website.bad_target",
            BadTrustCidr => "website.bad_trust_cidr",
            CertDomainExists => "website.cert_domain_exists",
            CertNotFound => "website.cert_not_found",
            DupAuthUser => "website.dup_auth_user",
            DuplicateDomain => "website.duplicate_domain",
            ExtraConfBad => "website.extra_conf_bad",
            ExtraConfTooLong => "website.extra_conf_too_long",
            LeIssueTimeout => "website.le_issue_timeout",
            LeNeedDomainSpecific => "website.le_need_domain_specific",
            LeNoHttp01 => "website.le_no_http01",
            LeVerifyTimeout => "website.le_verify_timeout",
            LocalRootAbs => "website.local_root_abs",
            LocalRootDenied => "website.local_root_denied",
            LocalRootMissing => "website.local_root_missing",
            LocalRootNotDir => "website.local_root_not_dir",
            ManualNoRenew => "website.manual_no_renew",
            MissingAccessId => "website.missing_access_id",
            MissingCertName => "website.missing_cert_name",
            MissingFilePath => "website.missing_file_path",
            MissingSiteId => "website.missing_site_id",
            NeedAccessName => "website.need_access_name",
            NeedAuthPw => "website.need_auth_pw",
            NeedCertDomain => "website.need_cert_domain",
            NeedCertKey => "website.need_cert_key",
            NeedContainer => "website.need_container",
            NeedDomain => "website.need_domain",
            NeedRoot => "website.need_root",
            NeedStaticDir => "website.need_static_dir",
            NeedTarget => "website.need_target",
            NotSetup => "website.not_setup",
            SiteNotFound => "website.site_not_found",
            TooManyRules => "website.too_many_rules",
            UnknownCertMode => "website.unknown_cert_mode",
            UnknownSiteKind => "website.unknown_site_kind",
            UnknownUploadMode => "website.unknown_upload_mode",
        }
    }
}

impl std::fmt::Display for WebsiteError {
    /// Renders the semantic code only; the infra boundary adds the `ERR_CODE:`
    /// marker when building the wire error.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for WebsiteError {}

#[cfg(test)]
mod website_error_tests {
    use super::*;

    #[test]
    fn codes_namespaced_snake_case_and_wire_stable() {
        // A representative code matches the exact frontend `err.*` string.
        assert_eq!(
            WebsiteError::DuplicateDomain.code(),
            "website.duplicate_domain"
        );
        // Display is the semantic code only (no transport prefix in domain).
        assert_eq!(
            WebsiteError::SiteNotFound.to_string(),
            "website.site_not_found"
        );
        // Exhaustive shape check across every variant.
        for e in [
            WebsiteError::AccessNotFound,
            WebsiteError::BadAccessName,
            WebsiteError::BadAuthPw,
            WebsiteError::BadAuthUser,
            WebsiteError::BadCertName,
            WebsiteError::BadCertNameChars,
            WebsiteError::BadClientAddr,
            WebsiteError::BadContainer,
            WebsiteError::BadContainerPort,
            WebsiteError::BadDomain,
            WebsiteError::BadFilePath,
            WebsiteError::BadStaticDir,
            WebsiteError::BadStaticDirName,
            WebsiteError::BadTarget,
            WebsiteError::BadTrustCidr,
            WebsiteError::CertDomainExists,
            WebsiteError::CertNotFound,
            WebsiteError::DupAuthUser,
            WebsiteError::DuplicateDomain,
            WebsiteError::ExtraConfBad,
            WebsiteError::ExtraConfTooLong,
            WebsiteError::LeIssueTimeout,
            WebsiteError::LeNeedDomainSpecific,
            WebsiteError::LeNoHttp01,
            WebsiteError::LeVerifyTimeout,
            WebsiteError::LocalRootAbs,
            WebsiteError::LocalRootDenied,
            WebsiteError::LocalRootMissing,
            WebsiteError::LocalRootNotDir,
            WebsiteError::ManualNoRenew,
            WebsiteError::MissingAccessId,
            WebsiteError::MissingCertName,
            WebsiteError::MissingFilePath,
            WebsiteError::MissingSiteId,
            WebsiteError::NeedAccessName,
            WebsiteError::NeedAuthPw,
            WebsiteError::NeedCertDomain,
            WebsiteError::NeedCertKey,
            WebsiteError::NeedContainer,
            WebsiteError::NeedDomain,
            WebsiteError::NeedRoot,
            WebsiteError::NeedStaticDir,
            WebsiteError::NeedTarget,
            WebsiteError::NotSetup,
            WebsiteError::SiteNotFound,
            WebsiteError::TooManyRules,
            WebsiteError::UnknownCertMode,
            WebsiteError::UnknownSiteKind,
            WebsiteError::UnknownUploadMode,
        ] {
            let c = e.code();
            assert!(c.starts_with("website."), "{c} not namespaced");
            assert!(
                c["website.".len()..]
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "{c} not snake_case"
            );
        }
    }
}
