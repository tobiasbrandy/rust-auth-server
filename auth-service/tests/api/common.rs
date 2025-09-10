use std::sync::Arc;

use auth_service::{
    api::app_state::AppState, config, persistence::{
        in_memory_2fa_code_store::InMemory2FACodeStore,
        in_memory_banned_token_store::InMemoryBannedTokenStore,
        in_memory_user_store::InMemoryUserStore,
    }, service::email::mock_email_client::MockEmailClient, Application
};

pub struct TestApp {
    pub state: AppState,
    pub address: String,
    pub url: reqwest::Url,
    pub cookies: Arc<reqwest_cookie_store::CookieStoreRwLock>,
    pub client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app_config = config::load_config("APP").expect("Failed to load config");

        let state = AppState::new(
            app_config,
            InMemoryUserStore::default(),
            InMemoryBannedTokenStore::default(),
            InMemory2FACodeStore::default(),
            MockEmailClient,
        );

        let app = Application::build("127.0.0.1:0", state.clone())
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());
        let url = reqwest::Url::parse(&address).unwrap();

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        tokio::spawn(app.run());

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
        }
    }

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
}
