-- Your SQL goes here
CREATE TABLE invite_code_admin
(
    username     VARCHAR NOT NULL,
    password     VARCHAR NOT NULL,
    otp_base32   VARCHAR,
    otp_auth_url VARCHAR,
    otp_enabled  INTEGER NOT NULL DEFAULT 0,
    otp_verified INTEGER NOT NULL DEFAULT 0,
);