use crate::{CREATE_INVITE_CODE, CREATE_INVITE_CODES, Code, GET_INVITE_CODES, InviteCodes, DISABLE_INVITE_CODES};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub async fn get_invite_codes() -> Vec<Code> {
    let mut codes = vec![];
    let client = reqwest::Client::new();
    let mut keep_fetching = true;
    let mut cursor = String::from("");
    while keep_fetching {
        let request_url = if cursor.is_empty() {
            "https://pds.ripperoni.com".to_string() + GET_INVITE_CODES
        } else {
            "https://pds.ripperoni.com".to_string() + GET_INVITE_CODES + "?" + cursor.as_str()
        };
        let res = client
            .get(request_url)
            .header("Content-Type", "application/json")
            .basic_auth("admin", Some("password"))
            .send()
            .await
            .unwrap();
        if !res.status().is_success() {
            panic!("not success")
        }
        let invite_codes = res.json::<InviteCodes>().await;
        match invite_codes {
            Ok(invite_codes) => {
                codes.append(&mut invite_codes.codes.clone());
                if invite_codes.cursor.is_empty() {
                    keep_fetching = false;
                } else {
                    cursor = invite_codes.cursor;
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                panic!("Invite Codes")
            }
        }
    }

    codes
}

#[derive(Serialize, Deserialize)]
pub struct CreateInviteCodeSchema {
    #[serde(rename = "codeCount")]
    pub code_count: i32,
    #[serde(rename = "useCount")]
    pub use_count: i32,
}

#[derive(Serialize, Deserialize)]
pub struct CreateInviteCodeResponseSchema {
    pub account: String,
    pub codes: Vec<String>,
}

pub async fn create_invite_code(code_count: i32, use_count: i32) -> Vec<String> {
    let mut codes = vec![];
    let client = reqwest::Client::new();
    let request_url = "https://pds.ripperoni.com".to_string() + CREATE_INVITE_CODES;
    let res = client
        .post(request_url)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some("password"))
        .json(&CreateInviteCodeSchema {
            code_count,
            use_count,
        })
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        panic!("not success")
    }
    let invite_codes = res.json::<CreateInviteCodeResponseSchema>().await;
    match invite_codes {
        Ok(invite_codes) => {
            codes.append(&mut invite_codes.codes.clone());
        }
        Err(e) => {
            eprintln!("{}", e);
            panic!("Invite Codes")
        }
    }

    codes
}

#[derive(Serialize, Deserialize)]
pub struct DisableInviteCodeSchema {
    #[serde(rename = "codeCount")]
    pub code_count: i32,
    #[serde(rename = "useCount")]
    pub use_count: i32,
}

pub async fn disable_invite_code() {
    let client = reqwest::Client::new();
    let res = client
        .post("https://pds.ripperoni.com".to_string() + DISABLE_INVITE_CODES)
        .header("Content-Type", "application/json")
        .basic_auth("admin", Some("password"))
        .json(&DisableInviteCodeSchema {
            code_count: 1,
            use_count: 1,
        })
        .send()
        .await
        .unwrap();
    if !res.status().is_success() {
        panic!("not success")
    }
    let invite_codes = res.json::<InviteCodes>().await;
    match invite_codes {
        Ok(invite_codes) => {
        }
        Err(e) => {
            eprintln!("{}", e);
            panic!("Invite Codes")
        }
    }
}
