use std::{str::FromStr, sync::Arc};

use hashbrown::HashMap;
use http::{HeaderMap, HeaderName, HeaderValue};
use secrecy::SecretString;
use serde::{Deserialize, Deserializer};

use crate::http::header::default_extra_headers;

/// Application configuration
#[derive(Debug, serde::Deserialize)]
pub struct Config {
    /// Identity configuration
    pub identity: IdentityConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// HTTP listener configuration
    pub http_listen: HTTPListenConfig,

    /// Security configuration
    pub security: SecurityConfig,
}

/// Identity configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IdentityConfig {
    /// The ID string of the server, used for various signing and machine-readable identification purposes
    ///
    /// For example: "server.example.com"
    pub id: String,

    /// The public URL of the server, used for various signing and machine-readable identification purposes
    ///
    /// Changing this will invalidate all existing tokens and require users to re-login
    ///
    /// For example: "https://server.example.com"
    pub public_url: url::Url,
}

/// Database configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DatabaseConfig {
    /// The database URL
    pub url: String,

    /// Override the password part of the database URL using the specified environment variable
    ///
    /// There is a tiny sentinel value where if your password will be rejected if it is just a repeat of '*'.
    pub password_env: Option<String>,

    /// Override the database name part of the database URL using the specified environment variable
    ///
    /// This will be applied to the 'path' part of the URL
    pub db_env: Option<String>,

    /// Obtain database password using `HashiCorp` Vault
    pub passwd_vault: Option<DBVaultConfig>,
}

/// Database Vault configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DBVaultConfig {
    /// The path to the secret in Vault
    pub mount: String,
    /// The Vault address, if not provided the value of the `VAULT_ADDR` environment variable is used
    pub address: Option<String>,
    /// The Vault token, if not provided the value of the `VAULT_TOKEN` environment variable is used
    pub token: Option<String>,
}

/// HTTP listener configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HTTPListenConfig {
    /// The address to listen on
    pub address: String,

    /// Whether to enable `SO_REUSEPORT`
    ///
    /// This is useful for load balancing when it has been made possible
    #[serde(default)]
    pub reuse_port: bool,

    /// TLS configuration
    pub tls: Option<TLSConfig>,

    /// Maximum number of forwarded-for headers to accept
    #[serde(default)]
    pub max_forwarded_for: u8,

    /// Extra headers configuration
    #[serde(default)]
    pub extra_headers: Arc<HTTPExtraHeadersConfig>,
}

fn deserialize_header_map<'de, D>(deserializer: D) -> Result<HeaderMap, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let inner: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let mut map = HeaderMap::new();
    for (k, v) in inner {
        map.insert(
            HeaderName::from_str(k.as_str())
                .map_err(|e| D::Error::custom(format!("invalid header name: {e}")))?,
            HeaderValue::from_str(&v)
                .map_err(|e| D::Error::custom(format!("invalid header value for {k}: {e}")))?,
        );
    }
    Ok(map)
}

/// Extra headers configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct HTTPExtraHeadersConfig {
    /// The headers to override
    #[serde(default, deserialize_with = "deserialize_header_map")]
    pub overriding: HeaderMap,

    /// The headers to append
    #[serde(default, deserialize_with = "deserialize_header_map")]
    pub appending: HeaderMap,

    /// The headers to append if the header is not set
    #[serde(default, deserialize_with = "deserialize_header_map")]
    pub if_not_set: HeaderMap,
}

impl Default for HTTPExtraHeadersConfig {
    fn default() -> Self {
        default_extra_headers()
    }
}

/// TLS configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TLSConfig {
    /// The path to the certificate file
    pub cert: String,

    /// Optional OCSP stapling file
    pub ocsp: Option<String>,

    /// The path to the private key file
    pub key: String,

    /// The alternative certificates to use
    #[serde(default)]
    pub alternatives: Vec<TLSConfig>,
}

/// Security configuration
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SecurityConfig {
    /// The secret key used for signing tokens and encrypting at-rest data
    ///
    /// do not change this value after initialization, or fully stop the service and use the re-key tool to rotate it
    pub secret: SecretString,
}

pub(crate) fn test_config() -> Config {
    Config {
        identity: IdentityConfig {
            id: "test".to_string(),
            public_url: url::Url::parse("https://test.example.com").unwrap(),
        },
        database: DatabaseConfig {
            url: "postgres://test:test@localhost:5432/test".to_string(),
            password_env: None,
            db_env: None,
            passwd_vault: None,
        },
        http_listen: HTTPListenConfig {
            address: "127.0.0.1:8080".to_string(),
            reuse_port: false,
            tls: None,
            max_forwarded_for: 10,
            extra_headers: Arc::new(HTTPExtraHeadersConfig::default()),
        },
        security: SecurityConfig {
            secret: "demo".into(),
        },
    }
}
