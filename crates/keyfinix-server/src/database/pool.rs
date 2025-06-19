use std::sync::OnceLock;

use tracing::{info, warn};
use reqwest::Url;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbBackend};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing_log::log::LevelFilter;

use crate::{
    abstraction::{Backoff, KeepAlivable, KeepAlive},
    config::DatabaseConfig,
};

use super::metrics;

/// Database pool type
pub type DbPool = KeepAlive<DBPoolProto>;

/// The role of this database connection, used in privilege separation
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum DBRole {
    /// The master database role which can perform all operations
    Master,
}

impl DBRole {
    /// Get the vault representation of this role
    #[must_use]
    pub fn vault_repr(&self) -> &'static str {
        match self {
            DBRole::Master => "master",
        }
    }
}

#[derive(Debug, thiserror::Error)]
/// Database initialization error
pub enum DBInitError {
    #[error("Failed to connect to database (tcp probe failed, is the database running?): {0}")]
    /// Failed to connect to database (tcp probe failed, is the database running?)
    TcpProbe(tokio::io::Error),
    #[error("Unsupported database backend: {0:?}")]
    /// Unsupported database backend
    UnsupportedBackend(String),
    #[error("Failed to connect to database: {0}")]
    /// Failed to connect to database
    ORM(#[from] sea_orm::error::DbErr),
    #[error("Failed to fetch DB password from external source: {0}")]
    /// Failed to fetch DB password from external source
    Reqwest(#[from] reqwest::Error),
}

impl Backoff for DBInitError {
    fn next_try(&self, count: u32) -> Option<std::time::Duration> {
        match count {
            1..=3 => Some(std::time::Duration::from_secs(3)),
            4..=6 => Some(std::time::Duration::from_secs(10)),
            _ => Some(std::time::Duration::from_secs(60)),
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct VaultResponse<T> {
    data: T,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct VaultDBCreds {
    username: String,
    password: String,
}


#[derive(Debug, Clone)]
/// Database pool prototype
pub struct DBPoolProto {
    role: DBRole,
    config: DatabaseConfig,

    #[cfg(feature = "metrics")]
    metrics: std::sync::Arc<metrics::DBMetrics>,
}

impl DBPoolProto {
    #[cfg(feature = "metrics")]
    /// Get the metrics
    #[must_use] pub fn metrics(&self) -> &metrics::DBMetrics {
        &self.metrics
    }

    /// Probe the database connection to see if it is ready
    pub async fn tcp_probe(&self) -> Result<(), DBInitError> {
        let url = get_db_url(&self.role, &self.config).await?;
        let host = url.host_str().unwrap();
        #[allow(clippy::wildcard_in_or_patterns)]
        let port = url.port().unwrap_or(match url.scheme() {
            "sqlite" => 5061,
            "mysql" | "mariadb" => 3306,
            "cockroachdb" => 26257,
            "postgres" | _ => 5432,
        });
        let mut conn = TcpStream::connect((host, port))
            .await
            .map_err(DBInitError::TcpProbe)?;
        conn.shutdown().await.unwrap();
        Ok(())
    }

    #[must_use]
    /// Create a new database pool prototype
    pub fn new(role: DBRole, config: DatabaseConfig) -> Self {
        Self {
            role,
            config,
            #[cfg(feature = "metrics")]
            metrics: std::sync::Arc::new(metrics::DBMetrics::new()),
        }
    }
}

static DB_PASSWORD_ENV_LOCK: OnceLock<Option<String>> = OnceLock::new();

/// Get the database URL using the specified role and configuration
pub async fn get_db_url(role: &DBRole, config: &DatabaseConfig) -> Result<Url, DBInitError> {
    let mut url = Url::parse(&config.url).expect("Failed to parse database URL");
    let mut url_sanitized = url.clone();
    url_sanitized
        .set_password(if url.password().is_some() {
            Some("********")
        } else {
            None
        })
        .expect("Failed to sanitize password");

    if let Some(db_env) = &config.db_env {
        if let Ok(db_from_env) = std::env::var(db_env) {
            url.set_path(&db_from_env);
        }
    }

    let password_from_env = DB_PASSWORD_ENV_LOCK.get_or_init(|| {
        if let Some(password_env) = &config.password_env {
            // safety: we are in a once lock so this is only called once across all threads
            let mut password = std::env::var(password_env).unwrap_or_else(|_| panic!("Failed to get password from specified environment variable: {password_env}"));
            assert!(!password.is_empty(), 
                    "Password from {password_env} is empty, did you specify a password in the environment variable?"
                );
            assert!(!password.chars().all(|c| c == '*'), "Password in {password_env} is zeroized, did you use fork()?");
            unsafe {
                std::env::set_var(password_env, "*".repeat(password.len()));
            }
            Some(password)
        } else {
            None
        }
    });

    let span = tracing::info_span!("database_pool_init", url = %url_sanitized, role = ?role);
    let _guard = span.enter();


    match (url.password(), password_from_env, &config.passwd_vault) {
        (None, None, None) => {
            warn!("No password provided for database connection");
        }
        (Some(_), None, None) => {
            warn!("Plaintext DB password in config file is not recommended");
        }
        (None, Some(pass), None) => {
            url.set_password(Some(pass))
                .expect("Failed to set password");
        }
        (None, None, Some(vault)) => {
            let span = tracing::info_span!("vault_db_password_fetch", role = ?role);
            let _guard = span.enter();
            info!("Obtaining DB password from HashiCorp Vault");
            let token = match &vault.token {
                Some(token) => token.clone(),
                None => std::env::var("VAULT_TOKEN")
                    .expect("Failed to get Vault token from environment variable"),
            };
            let addr = match &vault.address {
                Some(addr) => addr.clone(),
                None => std::env::var("VAULT_ADDR")
                    .expect("Failed to get Vault address from environment variable"),
            };
            let client = reqwest::Client::new();
            let resp = match client
                .get(format!(
                    "{}/v1/{}/creds/{}",
                    addr,
                    vault.mount,
                    role.vault_repr()
                ))
                .header("X-Vault-Token", token)
                .send()
                .await
            {
                Ok(resp) => resp.error_for_status()?,
                Err(e) => {
                    warn!("Failed to fetch DB password from Vault: {}", e);
                    return Err(DBInitError::Reqwest(e));
                }
            };
            let data = resp.json::<VaultResponse<VaultDBCreds>>().await?;
            url.set_username(data.data.username.as_str())
                .expect("Failed to set username");
            url.set_password(Some(data.data.password.as_str()))
                .expect("Failed to set password");
        }
        _ => panic!(
            "Invalid database configuration, did you specify passwords over multiple methods?"
        ),
    }
    Ok(url)
}

impl KeepAlivable for DBPoolProto {
    type Value = DatabaseConnection;
    type Error = DBInitError;

    fn name(&self) -> &'static str {
        "database"
    }

    fn health_check_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(10)
    }

    async fn initialize(&self) -> Result<Self::Value, Self::Error> {
        // fast-track allow sqlite in unit tests
        #[cfg(test)]
        if self.config.url.starts_with("sqlite:") {
            return Ok(Database::connect(self.config.url.clone()).await?);
        }

        let url = get_db_url(&self.role, &self.config).await?;

        #[allow(unused)]
        let is_postgres = DbBackend::Postgres.is_prefix_of(url.to_string().as_str());

        if !is_postgres {
            warn!(
                "Database backend is not Postgres, not proceeding"
            );
            return Err(DBInitError::UnsupportedBackend(url.scheme().to_string()));

        }

        let mut opts = ConnectOptions::new(url.clone());
        opts.max_connections(64)
            .min_connections(5)
            .connect_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(300))
            .acquire_timeout(std::time::Duration::from_secs(10))
            .max_lifetime(std::time::Duration::from_secs(10))
            .sqlx_logging(true)
            .sqlx_logging_level(if cfg!(any(feature = "debug", debug_assertions)) {
                LevelFilter::Debug
            } else {
                LevelFilter::Trace
            })
            .sqlx_slow_statements_logging_settings(
                LevelFilter::Info,
                std::time::Duration::from_secs(1),
            )
            .test_before_acquire(true);

        tracing::info!("Connecting to database");

        #[allow(unused_mut)]
        let mut db = Database::connect(opts).await.map_err(DBInitError::ORM)?;

        #[cfg(feature = "metrics")]
        {
            if is_postgres {
                if let Some((_, analyze_threshold)) =
                    url.query_pairs().find(|(k, _)| k == "analyze_threshold_us")
                {
                    self.metrics.set_dump_threshold(
                        analyze_threshold
                            .parse::<u64>()
                            .expect("Failed to parse analyze threshold"),
                    );
                }

                let dump_analyze = if let Some((_, analyze_file)) =
                    url.query_pairs().find(|(k, _)| k == "analyze_file")
                {
                    let analyze_file = std::fs::File::create(analyze_file.as_ref())
                        .expect("Failed to create analyze file");
                    Some((url, analyze_file))
                } else {
                    None
                };

                db.set_metric_callback(self.metrics.clone().callback(dump_analyze));
            }
        }

        Ok(db)
    }
}
