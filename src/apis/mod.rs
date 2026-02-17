use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub mod add_admin;
pub mod create_invite_codes;
pub mod disable_invite_codes;
pub mod generate_otp;
pub mod get_invite_codes;
pub mod health;
pub mod list_admins;
pub mod login;
pub mod remove_admin;
pub mod validate_otp;
pub mod verify_otp;

pub use add_admin::*;
pub use create_invite_codes::*;
pub use disable_invite_codes::*;
pub use generate_otp::*;
pub use get_invite_codes::*;
pub use health::*;
pub use list_admins::*;
pub use login::*;
pub use remove_admin::*;
pub use validate_otp::*;
pub use verify_otp::*;

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;

#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Use {
    #[serde(rename = "usedBy")]
    pub used_by: String,
    #[serde(rename = "usedByHandle")]
    pub used_by_handle: Option<String>,
    #[serde(rename = "usedAt")]
    pub used_at: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Code {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    #[serde(rename = "forAccount")]
    pub for_account: String,
    #[serde(rename = "forAccountHandle")]
    pub for_account_handle: Option<String>,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub uses: Vec<Use>,
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct InviteCodes {
    pub cursor: Option<String>,
    pub codes: Vec<Code>,
}

pub fn invite_code_admin_to_response(user: &InviteCodeAdmin) -> InviteCodeAdminData {
    InviteCodeAdminData {
        username: user.username.to_owned(),
        otp_auth_url: user.otp_auth_url.to_owned(),
        otp_base32: user.otp_base32.to_owned(),
        otp_enabled: user.otp_enabled.eq(&1),
        otp_verified: user.otp_verified.eq(&1),
    }
}
