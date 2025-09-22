use std::{
    pin::Pin,
    sync::{Arc, OnceLock, Weak},
};

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
        BannedTokenStoreError, TwoFACodeStoreError, in_memory_2fa_code_store::InMemory2FACodeStore,
        pg_user_store::PgUserStore, redis_banned_user_store::RedisBannedUserStore,
    },
    postgres::PgConfig,
    service::email::mock_email_client::MockEmailClient,
};

use reqwest::StatusCode;

use secrecy::ExposeSecret;
use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};

type PostgresContainer = testcontainers_modules::testcontainers::core::ContainerAsync<
    testcontainers_modules::postgres::Postgres,
>;
type RedisContainer = testcontainers_modules::testcontainers::core::ContainerAsync<
    testcontainers_modules::redis::Redis,
>;

struct TestCtx {
    pub config: config::AppConfig,
    pub _postgres: PostgresContainer,
    pub _redis: RedisContainer,
    pub template_db: String,
    pub janitor: Janitor,
}
impl TestCtx {
    async fn tests_init() -> Self {
        // Load config
        let config = config::AppConfig::load_env("APP", config::AppEnv::Test)
            .expect("Failed to load config");

        // Start postgres container
        let postgres = {
            let config = &config.db;
            testcontainers_modules::postgres::Postgres::default()
                .with_db_name(&config.database)
                .with_user(&config.user)
                .with_password(config.password.expose_secret())
                .with_mapped_port(config.port, 5432.into())
                .with_tag("17.6-alpine")
                .start()
                .await
                .expect("Failed to start postgres container")
        };

        // Start redis container
        let redis = {
            let config = &config.redis;
            testcontainers_modules::redis::Redis::default()
                .with_tag("8.2-alpine")
                .with_mapped_port(
                    config.port,
                    testcontainers_modules::redis::REDIS_PORT.into(),
                )
                .with_cmd(vec![
                    "redis-server",
                    "--requirepass",
                    config.password.expose_secret(),
                ])
                .start()
                .await
                .expect("Failed to start redis container")
        };

        // Create janitor
        let janitor = Janitor::new(4, std::time::Duration::from_secs(30), config.db.clone());

        // Create template database so we only run migrations once
        let template_db = {
            let template_db = config.db.database.clone() + "-template";
            let mut template_config = config.db.clone();
            template_config.database = template_db.clone();

            janitor
                .run_with_pool(|pool| async move {
                    // Don't fail, we assume it already exists
                    let _ = sqlx::query(
                        format!(r#"CREATE DATABASE "{}""#, template_config.database).as_str(),
                    )
                    .execute(&pool)
                    .await;

                    let template_conn = template_config
                        .build_pool()
                        .await
                        .expect("Failed to create Postgresql template connection");

                    sqlx::migrate!()
                        .run(&template_conn)
                        .await
                        .expect("Failed to run migrations");

                    tokio::spawn(async move { template_conn.close().await });
                })
                .await;

            template_db
        };

        Self {
            config,
            _postgres: postgres,
            _redis: redis,
            template_db,
            janitor,
        }
    }

    fn tests_shutdown(&mut self) {
        // Nothing to do :)
    }

    pub async fn get() -> Arc<Self> {
        static STATE: OnceLock<tokio::sync::Mutex<Weak<TestCtx>>> = OnceLock::new();

        let mut guard = STATE
            .get_or_init(|| tokio::sync::Mutex::new(Weak::new()))
            .lock()
            .await;

        if let Some(state) = guard.upgrade() {
            return state;
        }

        let state = Arc::new(Self::tests_init().await);
        *guard = Arc::downgrade(&state);

        state
    }
}
impl Drop for TestCtx {
    fn drop(&mut self) {
        self.tests_shutdown();
    }
}

pub struct TestApp {
    _ctx: Arc<TestCtx>,
    pub state: AppState,
    pub address: String,
    pub url: reqwest::Url,
    pub cookies: Arc<reqwest_cookie_store::CookieStoreRwLock>,
    pub client: reqwest::Client,
    pub _pg_pool: sqlx::PgPool,
    pub _redis: auth_service::redis::RedisClient,
    pub server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}
impl TestApp {
    pub async fn new() -> Self {
        let ctx = TestCtx::get().await;
        let test_id = uuid::Uuid::new_v4().to_string();

        // Config overrides for test environment
        let mut config = ctx.config.clone();
        config.host = "127.0.0.1".to_string();
        config.port = 0;

        config.db.max_connections = 1;
        config.db.database = config.db.database + "-" + &test_id;

        config.redis.user = Some(test_id.clone());
        config.redis.namespace = Some(test_id.clone());

        // Connect to postgres
        let pg_pool = {
            // Create database
            let db_name = config.db.database.clone();
            let template_db = ctx.template_db.clone();
            ctx.janitor
                .run_with_pool(|pool| async move {
                    sqlx::query(
                        format!(r#"CREATE DATABASE "{db_name}" TEMPLATE "{template_db}""#,)
                            .as_str(),
                    )
                    .execute(&pool)
                    .await
                    .unwrap_or_else(|e| panic!("Failed to create database {db_name}: {e}"));
                })
                .await;
            println!("Created database: {}", config.db.database);

            config
                .db
                .build_pool()
                .await
                .expect("Failed to create Postgresql pool")
        };

        // Connect to redis
        let redis = {
            let config = &mut config.redis;

            let admin_client = {
                let user = config.user.take();
                let admin_client = config
                    .build_client()
                    .await
                    .expect("Failed to build redis admin client");
                config.user = user;
                admin_client
            };

            // Enforce test isolation by setting a user which requires the namespace for the test
            redis::cmd("ACL")
                .arg("SETUSER")
                .arg(config.user.as_ref().unwrap())
                .arg("on")
                .arg(format!(">{}", config.password.expose_secret()))
                .arg("+@all")
                .arg("-@dangerous")
                .arg(format!("~{}:*", config.namespace.as_ref().unwrap())) // key pattern
                .arg("resetchannels")
                .arg(format!("&{}:*", config.namespace.as_ref().unwrap())) // pub/sub pattern
                .query_async::<()>(&mut admin_client.conn())
                .await
                .expect("Failed to create redis user");

            config
                .build_client()
                .await
                .expect("Failed to build redis client")
        };

        let state = AppState::new(
            config,
            PgUserStore::new(pg_pool.clone()),
            RedisBannedUserStore::new(redis.clone()),
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
            _ctx: ctx,
            state,
            address,
            url,
            cookies,
            client,
            _pg_pool: pg_pool,
            _redis: redis,
            server,
        }
    }
}
impl Drop for TestApp {
    fn drop(&mut self) {
        // Abort server
        self.server.abort();
    }
}

type JanitorFut = Pin<Box<dyn Future<Output = ()> + Send>>;
enum JanitorJob {
    Run(JanitorFut, tokio::sync::oneshot::Sender<()>),
    RunWithPool(
        Box<dyn FnOnce(sqlx::PgPool) -> JanitorFut + Send>,
        tokio::sync::oneshot::Sender<()>,
    ),
    Drop(JanitorFut),
    DropWithPool(Box<dyn FnOnce(sqlx::PgPool) -> JanitorFut + Send>),
}
struct Janitor {
    tx: Option<tokio::sync::mpsc::UnboundedSender<JanitorJob>>,
    handle: Option<std::thread::JoinHandle<()>>,
}
impl Janitor {
    pub fn new(threads: usize, timeout: std::time::Duration, pool_config: PgConfig) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<JanitorJob>();

        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .expect("Janitor: Failed to build janitor runtime");

            rt.block_on(async {
                let admin_pool = pool_config
                    .build_pool()
                    .await
                    .expect("janitor: Failed to create Postgresql admin pool");

                let mut join_set = tokio::task::JoinSet::new();

                loop {
                    async fn handle_job(
                        job: JanitorJob,
                        timeout: std::time::Duration,
                        admin_pool: sqlx::PgPool,
                    ) {
                        let job = async {
                            match job {
                                JanitorJob::Run(job, sender) => {
                                    job.await;
                                    sender.send(()).unwrap_or_else(|_| {
                                        eprintln!("Janitor: Failed to send job ack")
                                    });
                                }
                                JanitorJob::RunWithPool(job, sender) => {
                                    job(admin_pool).await;
                                    sender.send(()).unwrap_or_else(|_| {
                                        eprintln!("Janitor: Failed to send job ack")
                                    });
                                }
                                JanitorJob::Drop(job) => job.await,
                                JanitorJob::DropWithPool(job) => job(admin_pool).await,
                            }
                        };

                        tokio::time::timeout(timeout, job)
                            .await
                            .unwrap_or_else(|_| {
                                eprintln!("Janitor: Job timed out ({}s)", timeout.as_secs());
                            });
                    }

                    tokio::select! {
                        Some(job) = rx.recv() => {
                            join_set.spawn(handle_job(job, timeout, admin_pool.clone()));
                        }
                        Some(join_result) = join_set.join_next(), if !join_set.is_empty() => {
                            if let Err(e) = join_result {
                                eprintln!("Janitor: Join error: {e}");
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
            });
        });

        Self {
            tx: Some(tx),
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub async fn run(&self, job: impl Future<Output = ()> + Send + 'static) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();

        self.tx
            .as_ref()
            .unwrap()
            .send(JanitorJob::Run(Box::pin(job), ack_tx))
            .expect("Janitor: Failed to send job");

        ack_rx
            .await
            .unwrap_or_else(|_| eprintln!("Janitor: Failed to receive job ack"));
    }

    pub async fn run_with_pool<F, Fut>(&self, job: F)
    where
        F: FnOnce(sqlx::PgPool) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();

        self.tx
            .as_ref()
            .unwrap()
            .send(JanitorJob::RunWithPool(
                Box::new(|pool| Box::pin(job(pool))),
                ack_tx,
            ))
            .expect("Janitor: Failed to send job");

        ack_rx
            .await
            .unwrap_or_else(|_| eprintln!("Janitor: Failed to receive job ack"));
    }

    #[allow(dead_code)]
    pub fn async_drop(&self, job: impl Future<Output = ()> + Send + 'static) {
        self.tx
            .as_ref()
            .unwrap()
            .send(JanitorJob::Drop(Box::pin(job)))
            .expect("Janitor: Failed to send job");
    }

    #[allow(dead_code)]
    pub fn async_drop_with_pool<F, Fut>(&self, job: F)
    where
        F: FnOnce(sqlx::PgPool) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.tx
            .as_ref()
            .unwrap()
            .send(JanitorJob::DropWithPool(Box::new(|pool| {
                Box::pin(job(pool))
            })))
            .expect("Janitor: Failed to send job");
    }
}
impl Drop for Janitor {
    fn drop(&mut self) {
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

// --- TestApp Helpers --- //

impl TestApp {
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

    pub async fn has_banned_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
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

    pub async fn login_user(&self, email: String, password: String) {
        let response = self
            .post("/login")
            .json(&LoginRequest { email, password })
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

        assert!(self.has_banned_token(&token).await.unwrap());
    }
}
