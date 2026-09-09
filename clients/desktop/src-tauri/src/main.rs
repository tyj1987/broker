use reqwest::{Client, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri_plugin_opener::OpenerExt;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_ORIGIN: &str = "https://broker.52trz.com";
const SERVICE: &str = "com.secretbroker.desktop";
const ACCOUNT: &str = "operation-api-key";
const BROWSER_ACCOUNT: &str = "browser-bridge-api-key";

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationRequest {
    provider: String,
    operation_id: String,
    account_ref: String,
    environment: String,
    typed_parameters: TypedParameters,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TypedParameters {
    resource_ref: String,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:-".contains(&b))
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| "http_client_unavailable".to_string())
}

fn validated_origin(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "invalid_broker_origin".to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("invalid_broker_origin".into());
    }
    Ok(url)
}

fn broker_url(path: &str) -> Result<Url, String> {
    let origin = option_env!("SECRET_BROKER_ORIGIN").unwrap_or(DEFAULT_ORIGIN);
    validated_origin(origin)?
        .join(path)
        .map_err(|_| "invalid_broker_path".to_string())
}

fn credential(account: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, account).map_err(|_| "credential_store_unavailable".to_string())
}

fn store_credential(account: &str, secret: &mut String) -> Result<(), String> {
    if !secret.starts_with("mb_") || secret.len() < 24 || secret.len() > 256 {
        return Err("invalid_key".into());
    }
    let result = credential(account)?
        .set_password(secret)
        .map_err(|_| "credential_store_write_failed".to_string());
    secret.zeroize();
    result
}

#[tauri::command]
async fn broker_health() -> Result<Health, String> {
    let response = http_client()?
        .get(broker_url("/health")?)
        .send()
        .await
        .map_err(|_| "broker_unavailable".to_string())?;
    if response.status() != StatusCode::OK {
        return Err("broker_unavailable".into());
    }
    Ok(Health { status: "ok" })
}

#[tauri::command]
fn open_approvals(app: tauri::AppHandle) -> Result<(), String> {
    let url = broker_url("/approvals")?;
    app.opener()
        .open_url(url.as_str(), None::<&str>)
        .map_err(|_| "approval_browser_unavailable".to_string())
}

#[tauri::command]
fn store_api_key(mut secret: String) -> Result<(), String> {
    store_credential(ACCOUNT, &mut secret)
}

#[tauri::command]
fn delete_api_key() -> Result<(), String> {
    credential(ACCOUNT)?
        .delete_credential()
        .map_err(|_| "credential_store_delete_failed".to_string())
}

#[tauri::command]
fn store_browser_bridge_key(mut secret: String) -> Result<(), String> {
    store_credential(BROWSER_ACCOUNT, &mut secret)
}

#[tauri::command]
fn delete_browser_bridge_key() -> Result<(), String> {
    credential(BROWSER_ACCOUNT)?
        .delete_credential()
        .map_err(|_| "credential_store_delete_failed".to_string())
}

#[tauri::command]
async fn create_operation(request: OperationRequest) -> Result<Value, String> {
    if !valid_id(&request.provider)
        || !valid_id(&request.operation_id)
        || !valid_id(&request.account_ref)
        || !valid_id(&request.typed_parameters.resource_ref)
        || !["development", "staging", "production"].contains(&request.environment.as_str())
    {
        return Err("invalid_request".into());
    }
    let token = Zeroizing::new(
        credential(ACCOUNT)?
            .get_password()
            .map_err(|_| "credential_missing".to_string())?,
    );
    let response = http_client()?
        .post(broker_url("/api/v2/operations")?)
        .bearer_auth(token.as_str())
        .json(&request)
        .send()
        .await
        .map_err(|_| "broker_unavailable".to_string())?;
    if response.status() != StatusCode::ACCEPTED {
        return Err("operation_denied".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| "invalid_response".to_string())?;
    if body.len() > 256 * 1024 {
        return Err("response_too_large".into());
    }
    serde_json::from_slice(&body).map_err(|_| "invalid_response".to_string())
}

#[tauri::command]
async fn get_operation(operation_id: String) -> Result<Value, String> {
    if !valid_id(&operation_id) || !operation_id.contains('-') {
        return Err("invalid_operation_id".into());
    }
    let token = Zeroizing::new(
        credential(ACCOUNT)?
            .get_password()
            .map_err(|_| "credential_missing".to_string())?,
    );
    let response = http_client()?
        .get(broker_url(&format!("/api/v2/operations/{operation_id}"))?)
        .bearer_auth(token.as_str())
        .send()
        .await
        .map_err(|_| "broker_unavailable".to_string())?;
    if response.status() != StatusCode::OK {
        return Err("operation_unavailable".into());
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| "invalid_response".to_string())?;
    if body.len() > 256 * 1024 {
        return Err("response_too_large".into());
    }
    serde_json::from_slice(&body).map_err(|_| "invalid_response".to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            broker_health,
            open_approvals,
            store_api_key,
            delete_api_key,
            store_browser_bridge_key,
            delete_browser_bridge_key,
            create_operation,
            get_operation
        ])
        .run(tauri::generate_context!())
        .expect("desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_allowlisted() {
        assert!(valid_id("aliyun:billing.read"));
        assert!(!valid_id("https://evil.invalid"));
        assert!(!valid_id("UPPERCASE"));
        assert!(!valid_id("../escape"));
    }

    #[test]
    fn operation_request_denies_unknown_parameters() {
        let body = r#"{"provider":"aliyun","operation_id":"billing.read","account_ref":"primary","environment":"production","typed_parameters":{"resource_ref":"summary","url":"https://evil.invalid"}}"#;
        assert!(serde_json::from_str::<OperationRequest>(body).is_err());
    }

    #[test]
    fn origin_is_https_and_authority_only() {
        assert!(validated_origin("https://broker.example.com").is_ok());
        assert!(validated_origin("http://broker.example.com").is_err());
        assert!(validated_origin("https://user@broker.example.com").is_err());
        assert!(validated_origin("https://broker.example.com/path").is_err());
        assert_eq!(
            validated_origin("https://broker.example.com")
                .unwrap()
                .join("/approvals")
                .unwrap()
                .as_str(),
            "https://broker.example.com/approvals"
        );
    }
}
