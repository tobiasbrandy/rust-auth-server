use std::sync::Arc;

use auth_service::{
    Application,
    api::{
        app_state::AppState,
        routes::{LoginRequest, SignupRequest},
    },
    config,
    models::{
        two_fa::{LoginAttemptId, TwoFACode},
        user::User,
    },
    persistence::{
        TwoFACodeStoreError, in_memory_2fa_code_store::InMemory2FACodeStore,
        in_memory_banned_token_store::InMemoryBannedTokenStore, pg_user_store::PgUserStore,
    },
    service::email::mock_email_client::MockEmailClient,
};
use reqwest::StatusCode;

use sqlx::Connection;

static TEST_APP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static JANITOR: std::sync::LazyLock<std::sync::RwLock<Janitor>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(Janitor::new()));

pub struct TestApp {
    pub state: AppState,
    pub address: String,
    pub url: reqwest::Url,
    pub cookies: Arc<reqwest_cookie_store::CookieStoreRwLock>,
    pub client: reqwest::Client,
    pub pg_pool: sqlx::PgPool,
    pub server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}
impl TestApp {
    pub async fn new() -> Self {
        TEST_APP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

        let mut config = config::AppConfig::load("APP").expect("Failed to load config");

        // Config overrides for test environment
        config.host = "127.0.0.1".to_string();
        config.port = 0;
        config.db.max_connections = 1;
        config.db.database = config.db.database + "-" + &uuid::Uuid::new_v4().to_string();

        let ack = JANITOR
            .read()
            .unwrap()
            .create_db(config.db.database.clone());
        ack.await.expect("Failed to create database");

        let pg_pool = config
            .db
            .build_pool()
            .await
            .expect("Failed to create Postgresql pool");

        let state = AppState::new(
            config,
            PgUserStore::new(pg_pool.clone()),
            InMemoryBannedTokenStore::default(),
            InMemory2FACodeStore::default(),
            MockEmailClient,
        );

        let app = Application::build(state.clone())
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());
        let url = reqwest::Url::parse(&address).unwrap();

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        let server = tokio::spawn(app.run());

        let cookies = Arc::new(reqwest_cookie_store::CookieStoreRwLock::default());

        let client = reqwest::Client::builder()
            .cookie_provider(cookies.clone())
            .build()
            .expect("Failed to build http client");

        Self {
            state,
            address,
            url,
            cookies,
            client,
            pg_pool,
            server,
        }
    }

    // --- Client Helpers --- //

    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", &self.address, path))
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }

    // --- Cookie Helpers --- //

    pub fn add_cookie<'a, C>(&self, cookie: C)
    where
        C: Into<cookie::Cookie<'a>>,
    {
        self.cookies
            .write()
            .unwrap()
            .insert_raw(&cookie.into(), &self.url)
            .unwrap();
    }

    pub fn get_cookie(&'_ self, path: &str, name: &str) -> Option<cookie::Cookie<'_>> {
        self.cookies
            .read()
            .unwrap()
            .get(&self.url.host().unwrap().to_string(), path, name)
            .cloned()
            .map(|c| cookie::Cookie::from(c).into_owned())
    }

    pub fn get_cookie_value(&self, path: &str, name: &str) -> Option<String> {
        self.get_cookie(path, name).map(|c| c.value().to_string())
    }

    pub fn has_cookie(&self, path: &str, name: &str) -> bool {
        self.get_cookie(path, name).is_some()
    }

    #[allow(dead_code)]
    pub fn cookies(&'_ self) -> Vec<cookie::Cookie<'_>> {
        self.cookies
            .read()
            .unwrap()
            .iter_unexpired()
            .cloned()
            .map(|c| cookie::Cookie::from(c).into_owned())
            .collect()
    }

    pub fn clear_cookies(&self) {
        self.cookies.write().unwrap().clear();
    }

    // --- Store Helpers --- //

    pub async fn get_2fa_code(
        &self,
        email: &str,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        self.state.two_fa_code_store.get_code(email).await
    }

    pub async fn has_banned_token(&self, token: &str) -> bool {
        self.state.banned_token_store.contains_token(token).await
    }

    // --- Api Helpers --- //

    pub fn get_auth_token(&self) -> String {
        self.get_cookie_value("/", config::AUTH_TOKEN_COOKIE_NAME)
            .unwrap()
    }

    pub async fn create_user(&self, email: String, password: String, requires_2fa: bool) -> User {
        let response = self
            .post("/signup")
            .json(&SignupRequest {
                email,
                password,
                requires_2fa,
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        response.json::<User>().await.unwrap()
    }

    pub async fn login_user(&self, user: &User) {
        let response = self
            .post("/login")
            .json(&LoginRequest {
                email: user.email.clone(),
                password: user.password.clone(),
            })
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(self.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));
    }

    pub async fn logout_user(&self) {
        let token = self.get_auth_token();

        let response = self.post("/logout").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        assert!(!self.has_cookie("/", config::AUTH_TOKEN_COOKIE_NAME));

        assert!(self.has_banned_token(&token).await);
    }
}

impl Drop for TestApp {
    fn drop(&mut self) {
        // Abort server
        self.server.abort();

        // Close pg pool
        let pg_pool = self.pg_pool.clone();
        tokio::spawn(async move { pg_pool.close().await });

        // Drop database
        JANITOR
            .read()
            .unwrap()
            .drop_db(self.state.config.db.database.clone());

        if TEST_APP_COUNTER.fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
            JANITOR.write().unwrap().close();
        }
    }
}

#[derive(Debug)]
enum JanitorJob {
    CreateDb(String, tokio::sync::oneshot::Sender<()>),
    DropDb(String),
}
impl std::fmt::Display for JanitorJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JanitorJob::CreateDb(db_name, _) => write!(f, "create db {db_name}"),
            JanitorJob::DropDb(db_name) => write!(f, "drop db {db_name}"),
        }
    }
}
struct Janitor {
    tx: Option<tokio::sync::mpsc::UnboundedSender<JanitorJob>>,
    handle: Option<std::thread::JoinHandle<()>>,
}
impl Janitor {
    const WORKER_THREADS: usize = 4;
    const JOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    pub fn new() -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<JanitorJob>();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(Self::WORKER_THREADS)
                .enable_all()
                .build()
                .expect("Janitor: Failed to build janitor runtime");

            let mut config =
                config::AppConfig::load("APP").expect("Janitor: Failed to load config");
            config.db.database += "-template";

            let template_db = config.db.database.clone();

            rt.block_on(async {
                let pool = config
                    .db
                    .build_admin_pool()
                    .await
                    .expect("Janitor: Failed to create Postgresql pool");

                // Don't fail, we assume it already exists
                let _ = sqlx::query(format!(r#"CREATE DATABASE "{template_db}""#).as_str())
                    .execute(&pool)
                    .await;

                let mut template_conn = config
                    .db
                    .build_connection()
                    .await
                    .expect("Janitor: Failed to create Postgresql connection");

                sqlx::migrate!()
                    .run(&mut template_conn)
                    .await
                    .expect("Failed to run migrations");

                tokio::spawn(template_conn.close());

                let mut join_set = tokio::task::JoinSet::new();

                loop {
                    async fn handle_recv(pool: sqlx::PgPool, template_db: String, job: JanitorJob) {
                        let job_fmt = job.to_string();
                        tokio::time::timeout(
                            Janitor::JOB_TIMEOUT,
                            Janitor::handle_job(pool, template_db, job),
                        )
                        .await
                        .unwrap_or_else(|_| {
                            eprintln!(
                                "Janitor: Job timed out ({}s): {job_fmt}",
                                Janitor::JOB_TIMEOUT.as_secs()
                            );
                        });
                    }

                    tokio::select! {
                        Some(job) = rx.recv() => {
                            join_set.spawn(handle_recv(pool.clone(), template_db.clone(), job));
                        }
                        Some(join_result) = join_set.join_next(), if !join_set.is_empty() => {
                            if let Err(e) = join_result {
                                eprintln!("Janitor: Join error: {e:?}");
                            }
                        }
                        else => break,
                    }
                }

                while let Some(join_result) = join_set.join_next().await {
                    if let Err(e) = join_result {
                        eprintln!("Janitor: Join error: {e:?}");
                    }
                }

                Self::handle_job(
                    pool.clone(),
                    template_db.clone(),
                    JanitorJob::DropDb(template_db),
                )
                .await;

                pool.close().await;
            });
        });

        Self {
            tx: Some(tx),
            handle: Some(handle),
        }
    }

    async fn handle_job(pool: sqlx::PgPool, template_db: String, job: JanitorJob) {
        match job {
            JanitorJob::CreateDb(db_name, ack_tx) => {
                sqlx::query(
                    format!(r#"CREATE DATABASE "{db_name}" TEMPLATE "{template_db}""#).as_str(),
                )
                .execute(&pool)
                .await
                .map(|_| println!("Created database: {db_name}"))
                .unwrap_or_else(|e| panic!("Janitor: Failed to create database {db_name}: {e}"));

                ack_tx
                    .send(())
                    .unwrap_or_else(|_| eprintln!("Janitor: Failed to send ack"));
            }
            JanitorJob::DropDb(db_name) => {
                sqlx::query(format!(r#"DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)"#).as_str())
                    .execute(&pool)
                    .await
                    .map(|_| println!("Dropped database: {db_name}"))
                    .unwrap_or_else(|e| {
                        eprintln!("Janitor: Failed to drop database {db_name}: {e}")
                    })
            }
        }
    }

    pub fn create_db(&self, db_name: String) -> tokio::sync::oneshot::Receiver<()> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.tx
            .as_ref()
            .unwrap()
            .send(JanitorJob::CreateDb(db_name, ack_tx))
            .expect("Janitor: Failed to send job");

        ack_rx
    }

    pub fn drop_db(&self, db_name: String) {
        if let Err(e) = self.tx.as_ref().unwrap().send(JanitorJob::DropDb(db_name)) {
            eprintln!("Janitor: Failed to send job: {e}");
        }
    }

    pub fn close(&mut self) {
        // Drop tx
        self.tx.take();

        // Dropping `tx` closes the channel; worker loop ends; then we join.
        if let Some(handle) = self.handle.take() {
            let _ = handle
                .join()
                .inspect_err(|e| eprintln!("Janitor: Failed to join: {e:?}"));
        }
    }
}
impl Drop for Janitor {
    fn drop(&mut self) {
        self.close()
    }
}
