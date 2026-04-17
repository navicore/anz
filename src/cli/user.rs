use std::io::Write;

use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Subcommand;
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::crypto::password::hash_password;
use crate::crypto::totp;
use crate::crypto::{self};
use crate::db;

#[derive(Subcommand)]
pub enum UserAction {
    /// Add a user to a realm
    Add {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
        /// Email
        #[arg(long)]
        email: String,
        /// Comma-separated group names
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
    },
    /// Update a user's groups
    UpdateGroups {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
        /// Comma-separated group names (replaces existing groups)
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
    },
    /// List users in a realm
    List {
        /// Realm name
        #[arg(long)]
        realm: String,
    },
    /// Remove a user from a realm
    Remove {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
    /// Enroll a user in TOTP-based MFA. Generates a secret and 10 single-use
    /// recovery codes; prints both the otpauth:// URI and a terminal QR code so
    /// the user can scan or paste into their authenticator app.
    EnrollMfa {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
    /// Disable MFA for a user. Removes the TOTP secret and all recovery codes.
    /// Use as a recovery path for users who have lost their authenticator and
    /// exhausted (or also lost) their recovery codes.
    DisableMfa {
        /// Realm name
        #[arg(long)]
        realm: String,
        /// Username
        #[arg(long)]
        username: String,
    },
}

pub fn handle(action: UserAction, conn: &Connection) -> Result<()> {
    match action {
        UserAction::Add {
            realm,
            username,
            email,
            groups,
        } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            eprint!("Password: ");
            std::io::stderr().flush()?;
            let password = rpassword::read_password()?;
            if password.is_empty() {
                bail!("Password cannot be empty");
            }
            eprint!("Confirm password: ");
            std::io::stderr().flush()?;
            let confirm = rpassword::read_password()?;
            if password != confirm {
                bail!("Passwords do not match");
            }

            let pw_hash = hash_password(&password)?;
            let user =
                db::user::create_user(conn, &realm_obj.id, &username, &email, &pw_hash, &groups)?;
            println!(
                "Created user '{}' in realm '{}' (id: {})",
                user.username, realm, user.id
            );
            if !user.groups.is_empty() {
                println!("  groups: {}", user.groups.join(", "));
            }
        }
        UserAction::List { realm } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let users = db::user::list_users(conn, &realm_obj.id)?;
            if users.is_empty() {
                println!("No users in realm '{realm}'.");
            } else {
                for u in users {
                    println!("{:<20} {:<30} {}", u.username, u.email, u.id);
                }
            }
        }
        UserAction::UpdateGroups {
            realm,
            username,
            groups,
        } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            let user = db::user::get_user_by_username(conn, &realm_obj.id, &username)?;
            let user = match user {
                Some(u) => u,
                None => bail!("User '{username}' not found in realm '{realm}'"),
            };

            db::user::update_groups(conn, &user.id, &groups)?;
            if groups.is_empty() {
                println!("Cleared groups for '{username}' in realm '{realm}'");
            } else {
                println!(
                    "Updated groups for '{username}' in realm '{realm}': {}",
                    groups.join(", ")
                );
            }
        }
        UserAction::Remove { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?;
            let realm_obj = match realm_obj {
                Some(r) => r,
                None => bail!("Realm '{realm}' not found"),
            };

            if db::user::delete_user(conn, &realm_obj.id, &username)? {
                println!("Removed user '{username}' from realm '{realm}'");
            } else {
                println!("User '{username}' not found in realm '{realm}'");
            }
        }
        UserAction::EnrollMfa { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?
                .ok_or_else(|| anyhow::anyhow!("Realm '{realm}' not found"))?;
            let user = db::user::get_user_by_username(conn, &realm_obj.id, &username)?
                .ok_or_else(|| anyhow::anyhow!("User '{username}' not found in realm '{realm}'"))?;

            let (secret_b32, _) = totp::generate_secret();
            // Account label = "<realm>:<username>" so multiple realms can share an authenticator.
            let account = user.username.to_string();
            let issuer = format!("anz ({})", realm);
            let uri = totp::build_otpauth_uri(&issuer, &account, &secret_b32);

            // Generate 10 recovery codes. Show plaintext to the user once; persist hashes.
            let mut recovery_plain = Vec::with_capacity(10);
            let mut recovery_hashes = Vec::with_capacity(10);
            for _ in 0..10 {
                let mut bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut bytes);
                let code = URL_SAFE_NO_PAD.encode(bytes);
                let hash = crypto::hex_encode(&Sha256::digest(code.as_bytes()));
                recovery_plain.push(code);
                recovery_hashes.push(hash);
            }

            db::user_mfa::enroll(conn, &user.id, &secret_b32, &recovery_hashes)?;

            // Render QR to terminal (Unicode half-block — compact and scannable).
            let qr = QrCode::new(uri.as_bytes())?;
            let qr_text = qr
                .render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .build();

            println!("Enrolled '{username}' in MFA (realm '{realm}').");
            println!();
            println!("Scan this QR code with your authenticator app:");
            println!();
            println!("{qr_text}");
            println!("Or enter manually:");
            println!("  Account:   {account}");
            println!("  Issuer:    {issuer}");
            println!("  Secret:    {secret_b32}");
            println!("  Algorithm: SHA1, 6 digits, 30s period");
            println!();
            println!("Recovery codes (each can be used once — store them somewhere safe):");
            for code in &recovery_plain {
                println!("  {code}");
            }
            println!();
            println!("These will not be shown again.");
        }
        UserAction::DisableMfa { realm, username } => {
            let realm_obj = db::realm::get_realm_by_name(conn, &realm)?
                .ok_or_else(|| anyhow::anyhow!("Realm '{realm}' not found"))?;
            let user = db::user::get_user_by_username(conn, &realm_obj.id, &username)?
                .ok_or_else(|| anyhow::anyhow!("User '{username}' not found in realm '{realm}'"))?;

            if db::user_mfa::disable(conn, &user.id)? {
                println!("Disabled MFA for '{username}' in realm '{realm}'");
            } else {
                println!("User '{username}' did not have MFA enabled");
            }
        }
    }
    Ok(())
}
