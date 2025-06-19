use std::{str::FromStr, sync::OnceLock};
use tracing_subscriber::{EnvFilter, filter::Directive, layer::SubscriberExt};

static GLOBAL_LOGGER: OnceLock<()> = OnceLock::new();

/// Initialize the global logger
pub fn initialize_global_logger(pretty: bool) {
    GLOBAL_LOGGER.get_or_init(|| {
        macro_rules! create_subscriber {
            ($format:expr) => {
                tracing_subscriber::registry()
                    .with(
                        EnvFilter::builder()
                            .with_default_directive(
                                if cfg!(any(feature = "debug", debug_assertions)) {
                                    Directive::from_str("debug").unwrap()
                                } else {
                                    Directive::from_str("info").unwrap()
                                },
                            )
                            .parse_lossy(
                                ["RUST_LOG", "KEYFINIX_LOG"]
                                    .into_iter()
                                    .find_map(|name| std::env::var(name).ok())
                                    .unwrap_or_else(|| String::new()),
                            ),
                    )
                    .with({
                        let layer = tracing_subscriber::fmt::layer()
                            .with_writer(std::io::stderr)
                            .with_thread_names(true)
                            .with_target(true);

                        ($format)(layer)
                    })
            };
        }

        if pretty {
            tracing::subscriber::set_global_default(create_subscriber!(
                |layer: tracing_subscriber::fmt::Layer<_, _, _, _>| layer.pretty()
            ))
        } else {
            tracing::subscriber::set_global_default(create_subscriber!(
                |layer: tracing_subscriber::fmt::Layer<_, _, _, _>| layer.compact()
            ))
        }
        .expect("setting default subscriber failed");
    });
}
