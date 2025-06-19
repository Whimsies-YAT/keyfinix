use std::marker::PhantomData;

use lettre::{AsyncTransport, address::Envelope};

#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
/// Error for any transport
pub enum AnySinkError {
    #[error("SMTP sink error: {0}")]
    SMTP(#[from] lettre::transport::smtp::Error),
    #[error("File sink error: {0}")]
    File(#[from] lettre::transport::file::Error),
}

/// Transport adapter to bridge types between different transports
pub struct AsyncTransportMap<
    T: AsyncTransport + Sync,
    R: Sync,
    F: Fn(<T as AsyncTransport>::Ok) -> R + Send + Sync + 'static,
    E: Fn(<T as AsyncTransport>::Error) -> AnySinkError + Send + Sync + 'static,
> {
    transport: T,
    map: F,
    error_map: E,
    _marker: PhantomData<R>,
}

impl<
    T: AsyncTransport + Sync,
    R: Sync,
    F: Fn(<T as AsyncTransport>::Ok) -> R + Send + Sync + 'static,
    E: Fn(<T as AsyncTransport>::Error) -> AnySinkError + Send + Sync + 'static,
> AsyncTransportMap<T, R, F, E>
{
    /// Create a new transport adapter
    pub fn new(transport: T, map: F, error_map: E) -> Self {
        Self {
            transport,
            map,
            error_map,
            _marker: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<
    T: AsyncTransport + Sync,
    R: Sync,
    F: Fn(<T as AsyncTransport>::Ok) -> R + Send + Sync + 'static,
    E: Fn(<T as AsyncTransport>::Error) -> AnySinkError + Send + Sync + 'static,
> AsyncTransport for AsyncTransportMap<T, R, F, E>
{
    type Ok = R;
    type Error = AnySinkError;

    async fn send_raw(&self, envelope: &Envelope, email: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.transport
            .send_raw(envelope, email)
            .await
            .map(|ok| (self.map)(ok))
            .map_err(|err| (self.error_map)(err))
    }
}
