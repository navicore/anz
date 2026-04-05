use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    LoginSuccess,
    LoginFailure,
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    PasswordChanged,
    SessionCreated,
    RateLimited,
}

#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub realm: String,
    pub action: AuditAction,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub success: bool,
    pub detail: Option<String>,
}

#[derive(Clone)]
pub struct AuditLogger {
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl AuditLogger {
    pub fn new(enabled: bool, path: &str) -> Self {
        if !enabled {
            return Self { file: None };
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Self {
                file: Some(Arc::new(Mutex::new(f))),
            },
            Err(e) => {
                tracing::warn!("Could not open audit log {path}: {e}; audit logging disabled");
                Self { file: None }
            }
        }
    }

    pub fn log(&self, event: AuditEvent) {
        let Some(file) = &self.file else {
            return;
        };
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        if let Ok(mut f) = file.lock() {
            let _ = writeln!(f, "{line}");
        }
    }

    pub fn log_event(&self, params: LogEventParams<'_>) {
        self.log(AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            realm: params.realm.to_string(),
            action: params.action,
            user_id: params.user_id.map(|s| s.to_string()),
            client_id: params.client_id.map(|s| s.to_string()),
            ip_address: params.ip.map(|a| a.to_string()),
            success: params.success,
            detail: params.detail.map(|s| s.to_string()),
        });
    }
}

pub struct LogEventParams<'a> {
    pub realm: &'a str,
    pub action: AuditAction,
    pub user_id: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub ip: Option<IpAddr>,
    pub success: bool,
    pub detail: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_logger_does_not_panic() {
        let logger = AuditLogger::new(false, "/dev/null");
        logger.log_event(LogEventParams {
            realm: "test",
            action: AuditAction::LoginSuccess,
            user_id: None,
            client_id: None,
            ip: None,
            success: true,
            detail: None,
        });
    }

    #[test]
    fn enabled_logger_writes_to_file() {
        let dir = std::env::temp_dir().join(format!("anz_test_{}", uuid::Uuid::new_v4()));
        let path = dir.join("audit.log");
        std::fs::create_dir_all(&dir).unwrap();

        let logger = AuditLogger::new(true, path.to_str().unwrap());
        logger.log_event(LogEventParams {
            realm: "myrealm",
            action: AuditAction::LoginFailure,
            user_id: Some("user1"),
            client_id: None,
            ip: Some("127.0.0.1".parse().unwrap()),
            success: false,
            detail: Some("bad password"),
        });

        let contents = std::fs::read_to_string(&path).unwrap();
        let event: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(event["realm"], "myrealm");
        assert_eq!(event["action"], "login_failure");
        assert_eq!(event["success"], false);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn audit_action_serializes_to_snake_case() {
        let json = serde_json::to_string(&AuditAction::TokenRevoked).unwrap();
        assert_eq!(json, "\"token_revoked\"");
    }
}
