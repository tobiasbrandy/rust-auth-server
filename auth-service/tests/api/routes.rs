use auth_service::{
    api::routes::{
        ErrorResponse, Login2FAResponse, LoginRequest, SignupRequest, Verify2FARequest,
        VerifyTokenRequest, auth_cookie,
    },
    config,
    models::user::User,
};
use axum::http::StatusCode;
use rstest::rstest;
use serde_json::json;

use crate::common::TestApp;

// --- Fixtures --- //

#[rstest::fixture]
pub async fn app() -> TestApp {
    TestApp::new().await
}

// --- Helpers --- //

async fn create_user(app: &TestApp, user: User) -> User {
    let response = app.post("/signup").json(&SignupRequest {
        email: user.email.clone(),
        password: user.password.clone(),
        requires_2fa: user.requires_2fa,
    }).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json::<User>().await.unwrap()
}

async fn login_user(app: &TestApp, user: &User) {
    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: user.email.clone(),
            password: user.password.clone(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(app.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));
}

async fn logout_user(app: &TestApp) {
    let token = get_auth_token(app);

    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    assert!(!app.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));

    assert!(app.has_banned_token(&token).await);
}

fn get_auth_token(app: &TestApp) -> String {
    app.get_cookie("/", config::AUTH_TOKEN_COOKIE_NAME)
        .unwrap()
        .value()
        .to_string()
}

// --- Tests --- //

#[rstest]
#[awt]
#[tokio::test]
async fn root(#[future] app: TestApp) {
    let response = app.get("/").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[rstest]
#[awt]
#[tokio::test]
async fn signup(#[future] app: TestApp) {
    let user = User {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        requires_2fa: true,
    };

    let created_user = create_user(&app, user.clone()).await;
    assert_eq!(created_user, user);
}

#[rstest]
#[awt]
#[tokio::test]
async fn signup_malformed_body(#[future] app: TestApp) {
    let body = json!({
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post("/signup").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[rstest]
#[awt]
#[case(SignupRequest { email: "".to_string(), password: "password123".to_string(), requires_2fa: true })]
#[case(SignupRequest { email: "invalid_email".to_string(), password: "password123".to_string(), requires_2fa: true })]
#[case(SignupRequest { email: "valid_email@example.com".to_string(), password: "pass".to_string(), requires_2fa: true })]
#[tokio::test]
async fn signup_invalid_input(#[future] app: TestApp, #[case] input: SignupRequest) {
    let response = app.post("/signup").json(&input).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[awt]
#[tokio::test]
async fn signup_email_already_exists(#[future] app: TestApp) {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
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

#[rstest]
#[awt]
#[tokio::test]
async fn login(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: user.email,
            password: user.password,
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(app.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));
}

#[rstest]
#[awt]
#[tokio::test]
async fn login_2fa(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: true,
        },
    )
    .await;

    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: user.email,
            password: user.password,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

    let body = response.json::<Login2FAResponse>().await.unwrap();
    assert_eq!(body.message, "2FA required");
    assert_eq!(
        app.get_2fa_code("test@example.com").await.unwrap().0,
        body.login_attempt_id
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn login_malformed_body(#[future] app: TestApp) {
    let body = json!({
        "password": "password123"
    });

    let response = app.post("/login").json(&body).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[rstest]
#[awt]
#[case(LoginRequest { email: "".to_string(), password: "password123".to_string() })]
#[case(LoginRequest { email: "invalid_email".to_string(), password: "password123".to_string() })]
#[case(LoginRequest { email: "valid_email@example.com".to_string(), password: "pass".to_string() })]
#[tokio::test]
async fn login_invalid_input(#[future] app: TestApp, #[case] input: LoginRequest) {
    let response = app.post("/login").json(&input).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[rstest]
#[awt]
#[tokio::test]
async fn login_user_does_not_exist(#[future] app: TestApp) {
    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: "nonexistent@example.com".to_string(),
            password: "password123".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "Incorrect credentials".to_string()
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn login_password_is_incorrect(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: user.email,
            password: "wrongpassword".to_string(),
        })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<ErrorResponse>().await.unwrap().error,
        "Incorrect credentials".to_string()
    );
}

#[rstest]
#[awt]
#[tokio::test]
async fn verify_2fa(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "twofa@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: true,
        },
    )
    .await;

    let response = app
        .post("/login")
        .json(&LoginRequest {
            email: user.email.clone(),
            password: user.password,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = response.json::<Login2FAResponse>().await.unwrap();

    let (login_attempt_id, code) = app.get_2fa_code(&user.email).await.unwrap();
    assert_eq!(login_attempt_id, body.login_attempt_id);

    let verify_body = Verify2FARequest {
        email: user.email,
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
    assert!(app.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));
}

#[rstest]
#[awt]
#[tokio::test]
async fn logout(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    login_user(&app, &user).await;

    let token = get_auth_token(&app);

    assert!(!app.has_banned_token(&token).await);

    logout_user(&app).await;

    // Can't logout twice
    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn logout_missing_cookie(#[future] app: TestApp) {
    let response = app.post("/logout").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn logout_invalid_jwt(#[future] app: TestApp) {
    app.add_cookie(auth_cookie("invalid_jwt".to_string()));

    let response = app.post("/logout").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn me_with_valid_cookie(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    login_user(&app, &user).await;

    // Call /me using cookie-based auth
    let response = app.get("/me").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<User>().await.unwrap(), user);
}

#[rstest]
#[awt]
#[tokio::test]
async fn me_with_valid_authorization_header(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    login_user(&app, &user).await;

    let response = app.get("/me").send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let token = get_auth_token(&app);

    app.clear_cookies();

    // Call /me using Authorization header (Bearer token)
    let response = app
        .get("/me")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<User>().await.unwrap(), user);
}

#[rstest]
#[awt]
#[tokio::test]
async fn me_missing_token(#[future] app: TestApp) {
    let response = app.get("/me").send().await.unwrap();

    // Missing token should be treated as a unauthorized by the extractor
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn me_invalid_token(#[future] app: TestApp) {
    // Inject an invalid JWT cookie
    app.add_cookie(auth_cookie("invalid_jwt".to_string()));

    let response = app.get("/me").send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn verify_token(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    login_user(&app, &user).await;

    let token = get_auth_token(&app);

    let response = app
        .post("/verify-token")
        .json(&VerifyTokenRequest { token })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[rstest]
#[awt]
#[tokio::test]
async fn verify_token_malformed_body(#[future] app: TestApp) {
    let body: serde_json::Value = json!({
        "nottoken": "test_token",
    });
    let response = app.post("/verify-token").json(&body).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[rstest]
#[awt]
#[tokio::test]
async fn verify_token_invalid_token(#[future] app: TestApp) {
    let response = app
        .post("/verify-token")
        .json(&VerifyTokenRequest { token: "invalid_token".to_string() })
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[rstest]
#[awt]
#[tokio::test]
async fn should_return_401_if_banned_token(#[future] app: TestApp) {
    let user = create_user(
        &app,
        User {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            requires_2fa: false,
        },
    )
    .await;

    login_user(&app, &user).await;

    let token = get_auth_token(&app);

    logout_user(&app).await;

    let response = app.post("/verify-token").json(&VerifyTokenRequest { token }).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
