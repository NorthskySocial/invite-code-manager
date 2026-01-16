use crate::user::{InviteCodeAdmin, InviteCodeAdminData};
use diesel::SqliteConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use serde::{Deserialize, Serialize};

pub mod add_admin;
pub mod create_invite_codes;
pub mod disable_invite_codes;
pub mod generate_otp;
pub mod get_invite_codes;
pub mod health;
pub mod login;
pub mod remove_admin;
pub mod validate_otp;
pub mod verify_otp;

pub type DBPool = Pool<ConnectionManager<SqliteConnection>>;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Use {
    #[serde(rename = "usedBy")]
    pub used_by: String,
    #[serde(rename = "usedAt")]
    pub used_at: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Code {
    pub code: String,
    pub available: i32,
    pub disabled: bool,
    #[serde(rename = "forAccount")]
    pub for_account: String,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub uses: Vec<Use>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct InviteCodes {
    pub cursor: Option<String>,
    pub codes: Vec<Code>,
}

fn invite_code_admin_to_response(user: &InviteCodeAdmin) -> InviteCodeAdminData {
    InviteCodeAdminData {
        username: user.username.to_owned(),
        otp_auth_url: user.otp_auth_url.to_owned(),
        otp_base32: user.otp_base32.to_owned(),
        otp_enabled: user.otp_enabled.eq(&1),
        otp_verified: user.otp_verified.eq(&1),
    }
}
