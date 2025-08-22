use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn root() {
    let app = TestApp::new().await;

    let response = app.get("/").send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn signup() {
    let app = TestApp::new().await;

    let response = app.post("/signup").json(&json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    })).send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn signup_malformed_body() {
    let app = TestApp::new().await;

    let response = app.post("/signup").json(&json!({
        "password": "password123",
        "requires2FA": true
    })).send().await.unwrap();

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn login() {
    let app = TestApp::new().await;

    let response = app.post("/login").send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    let response = app.post("/verify-2fa").send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout() {
    let app = TestApp::new().await;

    let response = app.post("/logout").send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token() {
    let app = TestApp::new().await;

    let response = app.post("/verify-token").send().await.unwrap();

    assert_eq!(response.status().as_u16(), 200);
}
