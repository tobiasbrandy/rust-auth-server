pub mod mock_email_client;

use async_trait::async_trait;

#[async_trait]
pub trait EmailClient: std::fmt::Debug + Send + Sync {
    async fn send_email(&self, recipient: &str, subject: &str, content: &str)
    -> Result<(), String>;
}
