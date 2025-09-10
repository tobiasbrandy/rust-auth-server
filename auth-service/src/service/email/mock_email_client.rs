use async_trait::async_trait;

use crate::service::email::EmailClient;

#[derive(Debug, Clone, Default)]
pub struct MockEmailClient;

#[async_trait]
impl EmailClient for MockEmailClient {
    async fn send_email(
        &self,
        recipient: &str,
        subject: &str,
        content: &str,
    ) -> Result<(), String> {
        // Our mock email client will simply log the recipient, subject, and content to standard output
        println!("Sending email to {recipient} with subject: {subject} and content: {content}",);

        Ok(())
    }
}
