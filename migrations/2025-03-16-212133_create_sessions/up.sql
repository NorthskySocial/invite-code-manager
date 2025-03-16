-- Your SQL goes here
CREATE TABLE user_session
(
    username      VARCHAR NOT NULL,
    otp_validated INTEGER NOT NULL DEFAULT 0,
    active        INTEGER NOT NULL
);