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

diesel::table! {
    user_session (rowid) {
        rowid -> Integer,
        username -> Text,
        otp_validated -> Integer,
        active -> Integer,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    invite_code_admin,
    user_session,
);
