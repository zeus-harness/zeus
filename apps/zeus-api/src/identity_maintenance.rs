use std::{sync::Arc, time::Duration};

use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{FromRow, PgPool};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use uuid::Uuid;

use crate::crypto::{EnvelopeCipher, SealedSecret};

const MAX_EMAIL_ATTEMPTS: i32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum IdentityMaintenanceError {
    #[error("SMTP configuration is invalid")]
    InvalidSmtpConfiguration,
    #[error("mail sender address is invalid")]
    InvalidMailFrom,
}

#[derive(Debug, FromRow)]
struct ClaimedEmail {
    email_id: Uuid,
    message_kind: String,
    recipient_email: String,
    encrypted_subject: Vec<u8>,
    subject_nonce: Vec<u8>,
    encrypted_body: Vec<u8>,
    body_nonce: Vec<u8>,
    key_id: String,
    fence_token: i64,
    attempt_count: i32,
}

pub struct IdentityMaintenance {
    database: PgPool,
    envelope: Arc<dyn EnvelopeCipher>,
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    mail_from: Mailbox,
    node_id: String,
    poll_interval: Duration,
    lease_duration: Duration,
    shutdown: CancellationToken,
}

impl IdentityMaintenance {
    /// Creates the durable identity-mail dispatcher.
    ///
    /// # Errors
    ///
    /// Returns an error without including SMTP credentials when the URL or
    /// sender mailbox cannot be parsed.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database: PgPool,
        envelope: Arc<dyn EnvelopeCipher>,
        smtp_url: &SecretString,
        mail_from: &str,
        node_id: String,
        poll_interval: Duration,
        lease_duration: Duration,
        shutdown: CancellationToken,
    ) -> Result<Self, IdentityMaintenanceError> {
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp_url.expose_secret())
            .map_err(|_| IdentityMaintenanceError::InvalidSmtpConfiguration)?
            .build();
        let mail_from = mail_from
            .parse()
            .map_err(|_| IdentityMaintenanceError::InvalidMailFrom)?;
        Ok(Self {
            database,
            envelope,
            mailer,
            mail_from,
            node_id,
            poll_interval,
            lease_duration,
            shutdown,
        })
    }

    pub async fn run(self) {
        info!(node_id = %self.node_id, "identity maintenance started");
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            match self.claim().await {
                Ok(Some(email)) => self.deliver(email).await,
                Ok(None) => {
                    tokio::select! {
                        () = self.shutdown.cancelled() => break,
                        () = tokio::time::sleep(self.poll_interval) => {}
                    }
                }
                Err(error) => {
                    warn!(
                        error_kind = database_error_kind(&error),
                        "identity email claim failed"
                    );
                    tokio::select! {
                        () = self.shutdown.cancelled() => break,
                        () = tokio::time::sleep(self.poll_interval) => {}
                    }
                }
            }
        }
        info!(node_id = %self.node_id, "identity maintenance stopped");
    }

    async fn claim(&self) -> Result<Option<ClaimedEmail>, sqlx::Error> {
        sqlx::query_as::<_, ClaimedEmail>("select * from zeus_private.claim_identity_email($1, $2)")
            .bind(&self.node_id)
            .bind(i32::try_from(self.lease_duration.as_secs()).unwrap_or(i32::MAX))
            .fetch_optional(&self.database)
            .await
    }

    async fn deliver(&self, email: ClaimedEmail) {
        let aad = format!(
            "identity-email/{}/{}",
            email.message_kind, email.recipient_email
        );
        let subject = self.open_text(
            email.encrypted_subject.clone(),
            email.subject_nonce.clone(),
            email.key_id.clone(),
            format!("{aad}/subject").as_bytes(),
        );
        let body = self.open_text(
            email.encrypted_body.clone(),
            email.body_nonce.clone(),
            email.key_id.clone(),
            format!("{aad}/body").as_bytes(),
        );
        let (Ok(subject), Ok(body)) = (subject, body) else {
            self.finish(&email, "failed", None, Some("decrypt_failed"), 0)
                .await;
            return;
        };
        let Ok(recipient) = email.recipient_email.parse::<Mailbox>() else {
            self.finish(&email, "failed", None, Some("recipient_invalid"), 0)
                .await;
            return;
        };
        let Ok(message) = Message::builder()
            .from(self.mail_from.clone())
            .to(recipient)
            .subject(subject)
            .body(body)
        else {
            self.finish(&email, "failed", None, Some("message_invalid"), 0)
                .await;
            return;
        };
        match self.mailer.send(message).await {
            Ok(_) => self.finish(&email, "sent", None, None, 0).await,
            Err(_) if email.attempt_count >= MAX_EMAIL_ATTEMPTS => {
                self.finish(&email, "failed", None, Some("smtp_failed"), 0)
                    .await;
            }
            Err(_) => {
                self.finish(
                    &email,
                    "queued",
                    None,
                    Some("smtp_retry"),
                    retry_delay_seconds(email.attempt_count),
                )
                .await;
            }
        }
    }

    fn open_text(
        &self,
        ciphertext: Vec<u8>,
        nonce: Vec<u8>,
        key_id: String,
        aad: &[u8],
    ) -> Result<String, ()> {
        let plaintext = self
            .envelope
            .open(
                &SealedSecret {
                    ciphertext,
                    nonce,
                    key_id,
                },
                aad,
            )
            .map_err(|_| ())?;
        String::from_utf8(plaintext).map_err(|_| ())
    }

    async fn finish(
        &self,
        email: &ClaimedEmail,
        status: &str,
        provider_message_id: Option<&str>,
        error_code: Option<&str>,
        retry_seconds: i32,
    ) {
        let completed = sqlx::query_scalar::<_, bool>(
            "select zeus_private.finish_identity_email($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(email.email_id)
        .bind(&self.node_id)
        .bind(email.fence_token)
        .bind(status)
        .bind(provider_message_id)
        .bind(error_code)
        .bind(retry_seconds)
        .fetch_one(&self.database)
        .await;
        match completed {
            Ok(true) => {}
            Ok(false) => {
                warn!(email_id = %email.email_id, "identity email fence rejected completion");
            }
            Err(error) => warn!(
                email_id = %email.email_id,
                error_kind = database_error_kind(&error),
                "identity email completion failed"
            ),
        }
    }
}

fn retry_delay_seconds(attempt: i32) -> i32 {
    let exponent = u32::try_from(attempt.clamp(1, 9)).unwrap_or(1);
    5_i32
        .saturating_mul(2_i32.saturating_pow(exponent))
        .min(3600)
}

fn database_error_kind(error: &sqlx::Error) -> &'static str {
    match error {
        sqlx::Error::PoolTimedOut => "pool_timed_out",
        sqlx::Error::PoolClosed => "pool_closed",
        sqlx::Error::Io(_) => "io",
        sqlx::Error::Database(_) => "database",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::retry_delay_seconds;

    #[test]
    fn email_retry_backoff_is_bounded() {
        assert_eq!(retry_delay_seconds(1), 10);
        assert!(retry_delay_seconds(5) > retry_delay_seconds(2));
        assert_eq!(retry_delay_seconds(100), 2560);
    }
}
