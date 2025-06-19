use std::{io::Read, sync::Arc};

use crate::config::TLSConfig;
use itertools::Itertools;

use hashbrown::HashMap;
use rustls::{
    pki_types::{CertificateDer, DnsName, PrivateKeyDer},
    server::ResolvesServerCert,
    sign::CertifiedKey,
    sign::SigningKey,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use tracing::{Level, event};
use x509_parser::pem::Pem;

use super::ServerInitError;

pub(crate) fn read_cert(path: &str) -> Result<Vec<CertificateDer<'static>>, ServerInitError> {
    let data = std::fs::read(path)?;
    let ret = if data.starts_with(&b"-----BEGIN CERTIFICATE-----"[..]) {
        Pem::iter_from_buffer(&data)
            .filter_map(std::result::Result::ok)
            .filter(|p| p.label.contains("CERTIFICATE"))
            .map(|p| CertificateDer::from(p.contents))
            .collect()
    } else {
        vec![CertificateDer::from(data)]
    };

    Ok(ret)
}

pub(crate) fn extract_dns_names<'a>(
    der: &'a CertificateDer<'a>,
) -> Result<Vec<(bool, DnsName<'static>)>, ServerInitError> {
    let x509 = x509_parser::parse_x509_certificate(der.as_ref())
        .map_err(|e| e.clone())?
        .1;

    Ok(x509
        .subject_alternative_name()?
        .ok_or(ServerInitError::MissingSAN)?
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => {
                Some(dns.strip_prefix("*.").map_or((false, *dns), |s| (true, s)))
            }
            _ => None,
        })
        .map(|(wildcard, name)| DnsName::try_from(name.to_string()).map(|name| (wildcard, name)))
        .try_collect()?)
}

// make sure there is no trace of the private key left except into the keyloader
pub(crate) fn read_key(
    loader: &impl KeyLoader,
    path: &str,
) -> Result<Arc<dyn SigningKey>, ServerInitError> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    #[allow(clippy::cast_possible_truncation)]
    let mut buf = SecretSlice::new(vec![0; len as usize].into_boxed_slice());
    file.read_exact(buf.expose_secret_mut())?;

    let data = buf.expose_secret();
    if data.starts_with(&b"-----BEGIN PRIVATE"[..]) {
        // we use the RystCrypto decoder which is zero-alloc and thus safer here
        let mut decoder = pem_rfc7468::Decoder::new(data).map_err(|e| {
            event!(Level::ERROR, "Failed to parse the private key: {}", e);
            ServerInitError::Pem(e)
        })?;

        let mut der =
            SecretSlice::new(vec![0; decoder.remaining_len() as usize].into_boxed_slice());
        decoder.decode(der.expose_secret_mut()).map_err(|e| {
            event!(Level::ERROR, "Failed to parse the private key: {}", e);
            ServerInitError::Pem(e)
        })?;

        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(der.expose_secret()).map_err(|e| {
                event!(Level::ERROR, "Failed to parse the private key: {}", e);
                ServerInitError::PrivateKey(e.to_string())
            })?;

        loader.load_key(&key_der)
    } else {
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(data).map_err(|e| {
            event!(Level::ERROR, "Failed to parse the private key: {}", e);
            ServerInitError::PrivateKey(e.to_string())
        })?;

        loader.load_key(&key_der)
    }
}

/// A keyloader that takes a borrowed key
pub trait KeyLoader {
    /// Load a key
    fn load_key(&self, key: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, ServerInitError>;
}

impl KeyLoader for () {
    fn load_key(&self, _key: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, ServerInitError> {
        Err(ServerInitError::NoKeyLoader)
    }
}

/// A keyloader that uses the [rustls-aws-lc](https://github.com/awslabs/aws-lc-rs) crate.
///
/// We will make sure there are no trace of private key left after it got to the crypto backend but after that we will
/// trust AWS-LC to handle it.
pub struct AwsLcRsLeyLoader;

impl KeyLoader for AwsLcRsLeyLoader {
    fn load_key(&self, key: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, ServerInitError> {
        rustls::crypto::aws_lc_rs::sign::any_supported_type(key).map_err(|e| {
            event!(Level::ERROR, "Failed to load the private key: {}", e);
            ServerInitError::PrivateKey(e.to_string())
        })
    }
}

#[derive(Debug)]
pub(crate) struct ServerKeyRouter {
    primary_key: Arc<CertifiedKey>,
    sni_map: HashMap<String, Arc<CertifiedKey>>,
    wildcard_map: HashMap<String, Arc<CertifiedKey>>,
}

impl ServerKeyRouter {
    pub fn new(load_key: &impl KeyLoader, config: &TLSConfig) -> Result<Self, ServerInitError> {
        let key = read_key(load_key, &config.key)?;

        let cert = read_cert(&config.cert)?;
        let ocsp = config.ocsp.as_ref().map(std::fs::read).transpose()?;

        let mut certified = CertifiedKey::new(cert, key);
        certified.keys_match()?;
        certified.ocsp = ocsp;

        let ret = Self {
            primary_key: Arc::new(certified),
            sni_map: HashMap::new(),
            wildcard_map: HashMap::new(),
        };

        Ok(ret)
    }
    pub fn add_sni(
        &mut self,
        load_key: &impl KeyLoader,
        config: &TLSConfig,
    ) -> Result<(), ServerInitError> {
        // read the key first so stacks are overwritten
        let key = read_key(load_key, &config.key)?;

        let cert = read_cert(&config.cert)?;
        let names = extract_dns_names(cert.first().ok_or(ServerInitError::NoCertificates)?)?;
        let ocsp = config.ocsp.as_ref().map(std::fs::read).transpose()?;

        let mut certified = CertifiedKey::new(cert, key);
        certified.keys_match()?;
        certified.ocsp = ocsp;

        let key = Arc::new(certified);
        for (wildcard, name) in names {
            if wildcard {
                self.wildcard_map
                    .insert(name.as_ref().to_string(), key.clone());
            } else {
                self.sni_map.insert(name.as_ref().to_string(), key.clone());
            }
        }

        Ok(())
    }
}

impl ResolvesServerCert for ServerKeyRouter {
    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            if let Some(key) = self.sni_map.get(name).or_else(|| {
                name.split_once('.')
                    .map(|(_, s)| s)
                    .and_then(|s| self.wildcard_map.get(s))
            }) {
                return Some(key.clone());
            }
        }
        Some(self.primary_key.clone())
    }
}
