use auth_service::api::{ErrorResponse, SignupResponse};
use axum::http::StatusCode;
use serde_json::json;

use crate::helpers::TestApp;

#[tokio::test]
async fn root() {
    let app = TestApp::new().await;

    let response = app.get("/").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
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
    assert_eq!(response.status(), StatusCode::CREATED);
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
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn signup_invalid_input() {
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<ErrorResponse>().await.unwrap().error,
            "Invalid credentials".to_string()
        );
    }
}

#[tokio::test]
async fn signup_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "User already exists".to_owned()
    );
}

#[tokio::test]
async fn login() {
    let app = TestApp::new().await;

    // First, create a user to login with
    let signup_body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    });

    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status().as_u16(), 201);

    // Now test login with valid credentials
    let login_body = json!({
        "email": "test@example.com",
        "password": "password123"
    });

    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_malformed_body() {
    let app = TestApp::new().await;

    let body = json!({
        "password": "password123"
    });

    let response = app.post("/login").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn login_invalid_input() {
    let invalid_inputs = vec![
        // Empty email
        json!({
            "email": "",
            "password": "password123"
        }),
        // Email without @
        json!({
            "email": "invalid_email",
            "password": "password123"
        }),
        // Password less than 8 characters
        json!({
            "email": "valid_email@example.com",
            "password": "pass"
        }),
    ];

    let app = TestApp::new().await;

    for input in invalid_inputs {
        let response = app.post("/login").json(&input).send().await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<ErrorResponse>().await.unwrap().error,
            "Invalid credentials".to_string()
        );
    }
}

#[tokio::test]
async fn login_user_does_not_exist() {
    let app = TestApp::new().await;

    let body = json!({
        "email": "nonexistent@example.com",
        "password": "password123"
    });

    let response = app.post("/login").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "Incorrect credentials".to_string()
    );
}

#[tokio::test]
async fn login_password_is_incorrect() {
    let app = TestApp::new().await;

    // First, create a user
    let signup_body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": true
    });

    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status().as_u16(), 201);

    // Now try to login with wrong password
    let login_body = json!({
        "email": "test@example.com",
        "password": "wrongpassword"
    });

    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "Incorrect credentials".to_string()
    );
}

#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    let response = app.post("/verify-2fa").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn logout() {
    let app = TestApp::new().await;

    let response = app.post("/logout").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn verify_token() {
    let app = TestApp::new().await;

    let response = app.post("/verify-token").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
