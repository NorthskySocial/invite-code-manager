// @generated automatically by Diesel CLI.

diesel::table! {
    invite_code_admin (rowid) {
        rowid -> Integer,
        username -> Text,
        password -> Text,
        otp_base32 -> Nullable<Text>,
        otp_auth_url -> Nullable<Text>,
        otp_enabled -> Integer,
        otp_verified -> Integer,
    }
}
