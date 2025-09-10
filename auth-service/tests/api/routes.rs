use auth_service::{
    api::routes::{
        ErrorResponse, Login2FAResponse, LoginRequest, SignupRequest, SignupResponse,
        Verify2FARequest, VerifyTokenRequest,
    },
    config,
    models::user::User,
    service,
};
use axum::http::StatusCode;
use serde_json::json;

use crate::common::TestApp;

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

    let body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.json::<SignupResponse>().await.unwrap();
    assert_eq!(
        body.message,
        "User test@example.com created successfully!".to_string()
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
        SignupRequest {
            email: "".to_string(),
            password: "password123".to_string(),
            requires_2fa: true,
        },
        // Email without @
        SignupRequest {
            email: "invalid_email".to_string(),
            password: "password123".to_string(),
            requires_2fa: true,
        },
        // Password less than 8 characters
        SignupRequest {
            email: "valid_email@example.com".to_string(),
            password: "pass".to_string(),
            requires_2fa: true,
        },
    ];

    let app = TestApp::new().await;

    for input in invalid_inputs {
        let response = app.post("/signup").json(&input).send().await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn signup_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;

    let body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

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
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };

    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now test login with valid credentials
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };

    let response = app.post("/login").json(&login_body).send().await.unwrap();

    assert!(
        app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME)
            .is_some()
    );
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_2fa() {
    let app = TestApp::new().await;

    // First, create a user to login with
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now test login with valid credentials
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };

    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = response.json::<Login2FAResponse>().await.unwrap();
    assert_eq!(body.message, "2FA required");
    assert_eq!(
        app.state
            .two_fa_code_store
            .read()
            .await
            .get_code("test@example.com")
            .await
            .unwrap()
            .0,
        body.login_attempt_id
    );
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
        LoginRequest {
            email: "".to_string(),
            password: "password123".to_string(),
        },
        // Email without @
        LoginRequest {
            email: "invalid_email".to_string(),
            password: "password123".to_string(),
        },
        // Password less than 8 characters
        LoginRequest {
            email: "valid_email@example.com".to_string(),
            password: "pass".to_string(),
        },
    ];

    let app = TestApp::new().await;

    for input in invalid_inputs {
        let response = app.post("/login").json(&input).send().await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn login_user_does_not_exist() {
    let app = TestApp::new().await;

    let body = LoginRequest {
        email: "nonexistent@example.com".to_string(),
        password: "password123".to_string(),
    };

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
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };

    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Now try to login with wrong password
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "wrongpassword".to_string(),
    };

    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn verify_2fa() {
    let app = TestApp::new().await;

    // Create a user requiring 2FA
    let signup_body = SignupRequest {
        email: "twofa@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Start login to generate login_attempt_id and send code
    let login_body = LoginRequest {
        email: "twofa@example.com".to_string(),
        password: "password123".to_string(),
    };
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = response.json::<Login2FAResponse>().await.unwrap();

    // Retrieve the stored code and use it to verify
    let (login_attempt_id, code) = app
        .state
        .two_fa_code_store
        .read()
        .await
        .get_code("twofa@example.com")
        .await
        .unwrap();

    assert_eq!(login_attempt_id, body.login_attempt_id);

    let verify_body = Verify2FARequest {
        email: "twofa@example.com".to_string(),
        login_attempt_id,
        code,
    };
    let response = app
        .post("/verify-2fa")
        .json(&verify_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // Cookie should be set after successful verification
    assert!(
        app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME)
            .is_some()
    );
}

#[tokio::test]
async fn logout() {
    let app = TestApp::new().await;

    // Signup
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify that the cookie is added
    let auth_cookie = app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME).unwrap();
    let token = auth_cookie.value().to_string();

    // Verify token is not in banned store before logout
    assert!(
        !app.state
            .banned_token_store
            .read()
            .await
            .contains_token(&token)
            .await
    );

    // Logout
    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify that the cookie is removed
    assert!(
        app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME)
            .is_none()
    );

    // Verify token was added to banned store
    assert!(
        app.state
            .banned_token_store
            .read()
            .await
            .contains_token(&token)
            .await
    );

    // Try to logout again
    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_missing_cookie() {
    let app = TestApp::new().await;

    let response = app.post("/logout").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_invalid_jwt() {
    let app = TestApp::new().await;

    app.add_cookie(
        cookie::Cookie::build((config::AUTH_TOKEN_COOKIE_NAME, "invalid_jwt"))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(cookie::SameSite::Lax)
            .max_age(::cookie::time::Duration::seconds(
                service::auth::JWT_TTL.as_secs().try_into().unwrap(),
            )),
    );

    let response = app.post("/logout").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn me_with_valid_cookie() {
    let app = TestApp::new().await;

    // Signup
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login to receive auth cookie
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Call /me using cookie-based auth
    let response = app.get("/me").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.json::<User>().await.unwrap();
    assert_eq!(
        body,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        }
    );
}

#[tokio::test]
async fn me_with_valid_authorization_header() {
    let app = TestApp::new().await;

    // Signup
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login to generate a token we can use in the Authorization header
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Extract token from cookie
    let auth_cookie = app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME).unwrap();
    let token = auth_cookie.value().to_string();
    app.clear_cookies();

    // Call /me using Authorization header (Bearer token)
    let response = app
        .get("/me")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.json::<User>().await.unwrap();
    assert_eq!(
        body,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        }
    );
}

#[tokio::test]
async fn me_missing_token() {
    let app = TestApp::new().await;

    let response = app.get("/me").send().await.unwrap();

    // Missing token should be treated as a bad request by the extractor
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn me_invalid_token() {
    let app = TestApp::new().await;

    // Inject an invalid JWT cookie
    app.add_cookie(
        cookie::Cookie::build((config::AUTH_TOKEN_COOKIE_NAME, "invalid_jwt"))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(cookie::SameSite::Lax)
            .max_age(::cookie::time::Duration::seconds(
                service::auth::JWT_TTL.as_secs().try_into().unwrap(),
            )),
    );

    let response = app.get("/me").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_token() {
    let app = TestApp::new().await;

    // Signup
    let signup_body = json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": false
    });
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login
    let login_body = json!({
        "email": "test@example.com",
        "password": "password123"
    });
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Get token from cookie
    let auth_cookie = app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME).unwrap();

    let body = VerifyTokenRequest {
        token: auth_cookie.value().to_string(),
    };
    let response = app.post("/verify-token").json(&body).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn verify_token_malformed_body() {
    let app = TestApp::new().await;

    let body: serde_json::Value = json!({
        "nottoken": "test_token",
    });
    let response = app.post("/verify-token").json(&body).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

    // Signup
    let signup_body = SignupRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: false,
    };
    let signup_response = app.post("/signup").json(&signup_body).send().await.unwrap();
    assert_eq!(signup_response.status(), StatusCode::CREATED);

    // Login
    let login_body = LoginRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
    };
    let response = app.post("/login").json(&login_body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Get token from cookie
    let auth_cookie = app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME).unwrap();
    let token = auth_cookie.value().to_string();

    // Logout to ban the token
    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify that the banned token is rejected
    let body = VerifyTokenRequest { token };
    let response = app.post("/verify-token").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
