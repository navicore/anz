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
