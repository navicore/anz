use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RealmBranding {
    #[serde(default = "default_title")]
    pub title: String,

    #[serde(default)]
    pub logo_path: Option<String>,

    #[serde(default = "default_primary_color")]
    pub primary_color: String,

    #[serde(default = "default_background_color")]
    pub background_color: String,

    #[serde(default)]
    pub custom_css: Option<String>,
}

fn default_title() -> String {
    "Sign In".to_string()
}

fn default_primary_color() -> String {
    "#2563eb".to_string()
}

fn default_background_color() -> String {
    "#f5f5f5".to_string()
}

impl Default for RealmBranding {
    fn default() -> Self {
        Self {
            title: default_title(),
            logo_path: None,
            primary_color: default_primary_color(),
            background_color: default_background_color(),
            custom_css: None,
        }
    }
}

impl RealmBranding {
    /// Build a URL for the logo if logo_path is set.
    pub fn logo_url(&self, realm: &str) -> Option<String> {
        self.logo_path
            .as_ref()
            .map(|p| format!("/realms/{realm}/static/{p}"))
    }
}

pub fn load_branding(realms_dir: &str, realm_name: &str) -> RealmBranding {
    let path = Path::new(realms_dir)
        .join(realm_name)
        .join("branding")
        .join("branding.toml");

    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml::from_str(&contents) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("Failed to parse {}: {e}; using defaults", path.display());
                RealmBranding::default()
            }
        },
        Err(_) => RealmBranding::default(),
    }
}
