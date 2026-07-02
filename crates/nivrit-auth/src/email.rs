use lettre::{
    message::Mailbox, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};
use nivrit_core::{NivritError, Result};

#[derive(Debug, Clone)]
pub enum EmailConfig {
    /// Log the email body instead of sending. Useful for local development.
    Log,
    /// Send via SMTP.
    Smtp {
        host: String,
        port: u16,
        user: String,
        pass: String,
        from: String,
    },
}

impl EmailConfig {
    pub fn from_env(
        mode: &str,
        host: Option<String>,
        port: Option<u16>,
        user: Option<String>,
        pass: Option<String>,
        from: Option<String>,
    ) -> Result<Self> {
        match mode {
            "log" => Ok(EmailConfig::Log),
            "smtp" => {
                let host =
                    host.ok_or_else(|| NivritError::Validation("NIVRIT_SMTP_HOST missing".into()))?;
                let port = port.unwrap_or(587);
                let user =
                    user.ok_or_else(|| NivritError::Validation("NIVRIT_SMTP_USER missing".into()))?;
                let pass =
                    pass.ok_or_else(|| NivritError::Validation("NIVRIT_SMTP_PASS missing".into()))?;
                let from = from.unwrap_or_else(|| user.clone());
                Ok(EmailConfig::Smtp {
                    host,
                    port,
                    user,
                    pass,
                    from,
                })
            }
            _ => Err(NivritError::Validation(format!(
                "unknown email mode: {}",
                mode
            ))),
        }
    }
}

/// Send a password-reset email. In `Log` mode the link is printed to tracing.
pub async fn send_password_reset(
    email: &str,
    reset_link: &str,
    config: &EmailConfig,
) -> Result<()> {
    let subject = "Reset your Nivrit password";
    let body = format!(
        "Hello,\n\nYou requested a password reset. Click the link below to continue:\n\n{}\n\nThis link expires in 15 minutes. If you did not request this, you can ignore this email.\n",
        reset_link
    );

    match config {
        EmailConfig::Log => {
            tracing::info!(
                target: "nivrit_email",
                "[DEV EMAIL] to={} subject={}\n{}\nlink={}",
                email,
                subject,
                body,
                reset_link
            );
            Ok(())
        }
        EmailConfig::Smtp {
            host,
            port,
            user,
            pass,
            from,
        } => {
            let from: Mailbox = from
                .parse()
                .map_err(|e| NivritError::Validation(format!("invalid from address: {}", e)))?;
            let to: Mailbox = email
                .parse()
                .map_err(|e| NivritError::Validation(format!("invalid recipient: {}", e)))?;

            let message = Message::builder()
                .from(from)
                .to(to)
                .subject(subject)
                .body(body)
                .map_err(|e| NivritError::Internal(e.to_string()))?;

            let creds = Credentials::new(user.clone(), pass.clone());
            let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
                .map_err(|e| NivritError::Internal(e.to_string()))?
                .port(*port)
                .credentials(creds)
                .build();

            transport
                .send(message)
                .await
                .map_err(|e| NivritError::Internal(format!("failed to send email: {}", e)))?;
            Ok(())
        }
    }
}
