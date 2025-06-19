use std::{
    borrow::{Borrow, Cow},
    fmt::Display,
};

use lettre::{
    Address,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
};
use serde::{Serialize, Serializer};

use idna::{
    AsciiDenyList,
    uts46::{DnsLength, Hyphens, Uts46},
};

const UTS46: Uts46 = Uts46::new();
const UTS46_DENYLIST: AsciiDenyList = AsciiDenyList::STD3;
const UTS46_HYPHENS: Hyphens = Hyphens::Allow;
const UTS46_DNS_LENGTH: DnsLength = DnsLength::Verify;

/// Signup template
pub mod signup;

/// Transport adapters
pub mod transport;

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// An error that occurs when rendering an email message
pub enum MessageRenderError {
    #[error("askama (template engine) error: {0}")]
    Askama(#[from] askama::Error),
    #[error("lettre (email handling) error: {0}")]
    Lettre(#[from] lettre::error::Error),
}

/// An extension trait for [`lettre::message::MessageBuilder`] that adds methods for rendering email messages
pub trait MessageBuilderExt {
    /// Render a single-part email message using an Askama template
    fn render_askama_single_part<T>(
        self,
        template: impl Borrow<T>,
        ct: ContentType,
    ) -> Result<lettre::Message, MessageRenderError>
    where
        T: askama::Template;

    /// Render a two-part email message using two Askama templates
    fn render_askama_two_part<T1: askama::Template, T2: askama::Template>(
        self,
        templates: (
            (impl Borrow<T1>, ContentType),
            (impl Borrow<T2>, ContentType),
        ),
    ) -> Result<lettre::Message, MessageRenderError>;
}

impl MessageBuilderExt for lettre::message::MessageBuilder {
    fn render_askama_single_part<T>(
        self,
        template: impl Borrow<T>,
        ct: ContentType,
    ) -> Result<lettre::Message, MessageRenderError>
    where
        T: askama::Template,
    {
        self.singlepart(
            SinglePart::builder()
                .header(ct)
                .body(template.borrow().render()?),
        )
        .map_err(Into::into)
    }

    fn render_askama_two_part<T1: askama::Template, T2: askama::Template>(
        self,
        ((template1, ct1), (template2, ct2)): (
            (impl Borrow<T1>, ContentType),
            (impl Borrow<T2>, ContentType),
        ),
    ) -> Result<lettre::Message, MessageRenderError> {
        self.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ct1)
                        .body(template1.borrow().render()?),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ct2)
                        .body(template2.borrow().render()?),
                ),
        )
        .map_err(Into::into)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// A uniform representation of a domain
pub struct Domain<'a> {
    repr: Cow<'a, str>,
}

impl Display for Domain<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ascii_str())
    }
}

impl<'a> Domain<'a> {
    #[must_use]
    pub fn to_static(&self) -> Domain<'static> {
        Domain {
            repr: Cow::Owned(self.repr.to_string()),
        }
    }
    pub fn parse(domain: &'a str) -> Option<Self> {
        let span = tracing::trace_span!("uts46", domain);
        let _guard = span.enter();

        let mut domain = UTS46
            .to_ascii(
                domain.as_bytes(),
                UTS46_DENYLIST,
                UTS46_HYPHENS,
                UTS46_DNS_LENGTH,
            )
            .inspect_err(|e| {
                tracing::warn!("Failed to convert domain {domain} to ASCII: {e:?}");
            })
            .ok()?;

        if !domain.is_ascii() {
            return None;
        }

        if domain.chars().any(|c| c.is_ascii_uppercase()) {
            domain = Cow::Owned(domain.to_ascii_lowercase());
        }

        Some(Domain { repr: domain })
    }

    /// Get the public suffix of the domain
    #[must_use]
    pub fn public_suffix(&self) -> Option<psl::Domain> {
        psl::domain(self.as_ascii_str().as_bytes())
    }

    /// Check if the domain is unicode
    #[must_use]
    pub fn is_unicode(&self) -> bool {
        self.repr.starts_with("xn--")
    }

    /// Get the domain as an ASCII string (always lowercase, after punycode if needed)
    #[must_use]
    pub fn as_ascii_str(&self) -> &str {
        self.repr.as_ref()
    }

    /// Get the domain as a unicode string (if it is unicode)
    pub fn to_unicode_string(&self) -> Result<Cow<'_, str>, idna::Errors> {
        let span = tracing::trace_span!("uts46", domain = %self.as_ascii_str());
        let _guard = span.enter();
        if self.is_unicode() {
            let (out, err) = UTS46.to_unicode(
                self.as_ascii_str().as_bytes(),
                UTS46_DENYLIST,
                UTS46_HYPHENS,
            );

            match err {
                Ok(()) => Ok(out),
                Err(err) => {
                    tracing::event!(
                        tracing::Level::ERROR,
                        partial = %out,
                        "Failed to convert domain to unicode"
                    );
                    Err(err)
                }
            }
        } else {
            Ok(Cow::Borrowed(self.as_ascii_str()))
        }
    }
}

/// An email address
pub struct Email<'a> {
    local: &'a str,

    domain: Domain<'a>,
}

impl Serialize for Email<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'a> Email<'a> {
    /// Get the domain part of the email address
    #[must_use]
    pub fn domain(&self) -> &Domain<'a> {
        &self.domain
    }

    /// Get the local part of the email address
    #[must_use]
    pub fn local(&self) -> &str {
        self.local
    }

    /// Start composing a new email message to this address
    #[must_use]
    pub fn compose_to(&self, name: Option<String>) -> lettre::message::MessageBuilder {
        lettre::Message::builder()
            .date_now()
            .to(Mailbox::new(
                name,
                Address::new(self.local, self.domain.as_ascii_str()).unwrap(),
            ))
            .user_agent(concat!("keyfinix-server/", env!("CARGO_PKG_VERSION")).into())
    }

    /// Parse an email address
    #[must_use]
    pub fn parse(full: &'a str) -> Option<Self> {
        if full.len() >= 128 {
            return None;
        }

        let (local, domain) = full.split_once('@')?;

        // https://html.spec.whatwg.org/multipage/input.html#valid-e-mail-address
        // but I refuse to use regex
        if local.is_empty()
            || !local
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".!#$%&'*+\\/=?^_`{|}~-".contains(c))
        {
            return None;
        }

        Some(Self {
            local,
            domain: Domain::parse(domain).and_then(|d| {
                // double check with the sending agent
                if Address::new(local, d.as_ascii_str()).is_err() {
                    return None;
                }

                Some(d)
            })?,
        })
    }
}

impl Display for Email<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.local, self.domain.as_ascii_str())
    }
}
