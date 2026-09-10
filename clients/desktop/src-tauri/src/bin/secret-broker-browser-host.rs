use reqwest::{StatusCode, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const ORIGIN: &str = "https://broker.52trz.com";
const SERVICE: &str = "com.secretbroker.desktop";
const ACCOUNT: &str = "browser-bridge-api-key";
const MAX_MESSAGE_BYTES: u32 = 64 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum NativeRequest {
    #[serde(rename = "consume-approved-otp")]
    Claim {
        tab_id: u64,
        frame_id: u64,
        document_id: String,
        origin: String,
        provider: String,
        account_ref: String,
    },
    #[serde(rename = "complete-approved-otp")]
    Finish { receipt: String, completed: bool },
}

#[derive(Serialize)]
struct ClaimBody<'a> {
    tab_id: u64,
    frame_id: u64,
    document_id: &'a str,
    origin: &'a str,
    provider: &'a str,
    account_ref: &'a str,
}

#[derive(Serialize)]
struct FinishBody<'a> {
    receipt: &'a str,
    completed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimResponse {
    #[serde(rename = "type")]
    kind: String,
    provider: String,
    account_ref: String,
    origin: String,
    tab_id: u64,
    frame_id: u64,
    document_id: String,
    expires_at_ms: u64,
    code: String,
    receipt: String,
}

#[derive(Serialize)]
struct CompletionResponse {
    #[serde(rename = "type")]
    kind: &'static str,
    completed: bool,
}

fn allowed_origin(provider: &str) -> Option<&'static str> {
    match provider {
        "aliyun" => Some("https://account.aliyun.com"),
        "tencent" => Some("https://cloud.tencent.com"),
        _ => None,
    }
}

fn valid_token(value: &str) -> bool {
    value.starts_with("mb_") && (24..=256).contains(&value.len())
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        })
}

fn client() -> Result<Client, ()> {
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| ())
}

fn read_native_message() -> Result<Vec<u8>, ()> {
    let mut length = [0_u8; 4];
    io::stdin().read_exact(&mut length).map_err(|_| ())?;
    let length = u32::from_le_bytes(length);
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(());
    }
    let mut body = vec![0_u8; length as usize];
    io::stdin().read_exact(&mut body).map_err(|_| ())?;
    Ok(body)
}

fn write_native_message<T: Serialize>(value: &T) -> Result<(), ()> {
    let body = serde_json::to_vec(value).map_err(|_| ())?;
    if body.len() > MAX_MESSAGE_BYTES as usize {
        return Err(());
    }
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&(body.len() as u32).to_le_bytes())
        .and_then(|_| stdout.write_all(&body))
        .and_then(|_| stdout.flush())
        .map_err(|_| ())
}

fn api_key() -> Result<Zeroizing<String>, ()> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT).map_err(|_| ())?;
    let key = Zeroizing::new(entry.get_password().map_err(|_| ())?);
    if !valid_token(key.as_str()) {
        return Err(());
    }
    Ok(key)
}

fn post_json<T: Serialize>(path: &str, body: &T) -> Result<Vec<u8>, ()> {
    let token = api_key()?;
    let mut response = client()?
        .post(format!("{ORIGIN}{path}"))
        .bearer_auth(token.as_str())
        .json(body)
        .send()
        .map_err(|_| ())?;
    if response.status() != StatusCode::OK {
        return Err(());
    }
    if response.content_length().unwrap_or(0) > MAX_MESSAGE_BYTES as u64 {
        return Err(());
    }
    let mut output = Vec::new();
    response
        .by_ref()
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| ())?;
    if output.len() > MAX_MESSAGE_BYTES as usize {
        return Err(());
    }
    Ok(output)
}

fn run() -> Result<(), ()> {
    let request: NativeRequest = serde_json::from_slice(&read_native_message()?).map_err(|_| ())?;
    match request {
        NativeRequest::Claim {
            tab_id,
            frame_id,
            document_id,
            origin,
            provider,
            account_ref,
        } => {
            if frame_id != 0
                || allowed_origin(&provider) != Some(origin.as_str())
                || !valid_text(&document_id, 256)
                || !valid_identifier(&account_ref)
            {
                return Err(());
            }
            let body = ClaimBody {
                tab_id,
                frame_id,
                document_id: &document_id,
                origin: &origin,
                provider: &provider,
                account_ref: &account_ref,
            };
            let bytes = post_json("/api/v2/browser/otp/claim", &body)?;
            let mut response: ClaimResponse = serde_json::from_slice(&bytes).map_err(|_| ())?;
            let valid = response.kind == "approved-otp"
                && response.provider == provider
                && response.account_ref == account_ref
                && response.origin == origin
                && response.tab_id == tab_id
                && response.frame_id == frame_id
                && response.document_id == document_id
                && response.code.len() >= 4
                && response.code.len() <= 10
                && response.code.bytes().all(|value| value.is_ascii_digit())
                && valid_text(&response.receipt, 128);
            if !valid {
                response.code.zeroize();
                return Err(());
            }
            let result = write_native_message(&response);
            response.code.zeroize();
            result
        }
        NativeRequest::Finish { receipt, completed } => {
            if !valid_text(&receipt, 128) {
                return Err(());
            }
            let body = FinishBody {
                receipt: &receipt,
                completed,
            };
            let _: serde_json::Value =
                serde_json::from_slice(&post_json("/api/v2/browser/otp/finish", &body)?)
                    .map_err(|_| ())?;
            write_native_message(&CompletionResponse {
                kind: "otp-completion",
                completed,
            })
        }
    }
}

fn main() {
    let _ = run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_fixed_per_provider() {
        assert_eq!(allowed_origin("aliyun"), Some("https://account.aliyun.com"));
        assert_eq!(allowed_origin("tencent"), Some("https://cloud.tencent.com"));
        assert_eq!(allowed_origin("github"), None);
    }

    #[test]
    fn token_and_text_validation_are_bounded() {
        assert!(valid_token("mb_123456789012345678901"));
        assert!(!valid_token("not-a-token"));
        assert!(!valid_text("bad\nvalue", 128));
    }
}
