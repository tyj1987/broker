fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "broker_health",
            "open_approvals",
            "store_api_key",
            "delete_api_key",
            "create_operation",
            "get_operation",
        ]),
    ))
    .expect("failed to generate the desktop command ACL")
}
