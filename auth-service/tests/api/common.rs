use std::sync::Arc;

use auth_service::{
    Application, app_state::AppState, config, services::hashmap_user_store::HashmapUserStore,
};

pub struct TestApp {
    pub address: String,
    pub url: reqwest::Url,
    pub cookies: Arc<reqwest_cookie_store::CookieStoreRwLock>,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let app_config = config::load_config("APP").expect("Failed to load config");

        let app_state = AppState::new(app_config, HashmapUserStore::default());

        let app = Application::build("127.0.0.1:0", app_state)
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());
        let url = reqwest::Url::parse(&address).unwrap();

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        tokio::spawn(app.run());

        let cookies = Arc::new(reqwest_cookie_store::CookieStoreRwLock::default());

        let http_client = reqwest::Client::builder()
            .cookie_provider(cookies.clone())
            .build()
            .expect("Failed to build http client");

        Self {
            address,
            url,
            cookies,
            http_client,
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

    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http_client
            .request(method, format!("{}{}", &self.address, path))
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::GET, path)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.request(reqwest::Method::POST, path)
    }
}
