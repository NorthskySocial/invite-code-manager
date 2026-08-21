use crate::access::AccessConfig;

#[derive(Debug, Clone)]
pub struct Config {
    pub pds_admin_password: String,
    pub pds_endpoint: String,
    /// Present only when Cloudflare Access is configured. `None` leaves the
    /// machine-facing endpoint refusing every request, which is the safe
    /// default: a half-configured auth path is worse than none.
    pub access: Option<AccessConfig>,
}
