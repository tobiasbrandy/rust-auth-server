use auth_service::api::{ErrorResponse, SignupResponse};
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

    let body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 201);
    assert_eq!(
        response.json::<SignupResponse>().await.unwrap(),
        SignupResponse {
            message: "User test@example.com created successfully!".to_string(),
        }
    );
}

#[tokio::test]
async fn signup_malformed_body() {
    let app = TestApp::new().await;

    let body = json!({
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn signup_should_return_400_if_invalid_input() {
    let invalid_inputs = vec![
        // Empty email
        json!({
            "email": "",
            "password": "password123",
            "requires2FA": true
        }),
        // Email without @
        json!({
            "email": "invalid_email",
            "password": "password123",
            "requires2FA": true
        }),
        // Password less than 8 characters
        json!({
            "email": "valid_email@example.com",
            "password": "pass",
            "requires2FA": true
        }),
    ];

    let app = TestApp::new().await;

    for input in invalid_inputs {
        let response = app.post("/signup").json(&input).send().await.unwrap();

        assert_eq!(response.status().as_u16(), 400);
        assert_eq!(
            response.json::<ErrorResponse>().await.unwrap().error,
            "Invalid credentials".to_string()
        );
    }
}

#[tokio::test]
async fn signup_should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "User already exists".to_owned()
    );
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
