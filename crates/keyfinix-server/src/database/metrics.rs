#![allow(unused_imports)]
use serde_json::value::RawValue;
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    sync::{Arc, LazyLock, Mutex, atomic::AtomicBool},
};
use url::Url;

use hashbrown::HashMap;
use prometheus::{HistogramOpts, HistogramVec, core::AtomicU64};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    Statement, Values, metric::Info,
};
use tokio::runtime::Runtime;
use tracing::warn;

#[derive(Debug)]
/// Database metrics holder
pub struct DBMetrics {
    /// The threshold of minimum query duration in microseconds to dump SQL ANALYZE results
    ///
    /// This has no effect when the 'testing-with-sql-dump' feature is not enabled
    dump_threshold: std::sync::atomic::AtomicU64,
    query_duration: HistogramVec,
}

fn inline_values(sql: &str, values: Option<Values>) -> String {
    if let Some(values) = values {
        let mut sql = sql.to_string();
        for (i, value) in values.iter().enumerate() {
            let mut val_sql = String::new();
            let backend = DatabaseBackend::Postgres;
            backend
                .get_query_builder()
                .prepare_constant(value, &mut val_sql);
            sql = sql.replace(&format!("${}", i + 1), &val_sql);
        }
        sql
    } else {
        sql.to_string()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LogEntry {
    failed: bool,
    duration_us: u64,
    statement: String,
    statement_inline: String,
    explain_generic: String,
    explain_specialized: String,
    analyze: Result<Option<Vec<ExplainResult>>, String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ExplainResult {
    #[serde(flatten)]
    extras: HashMap<String, serde_json::Value>,
}

// this needs postgres 16+
fn generate_generic_analyze(sql: &str) -> String {
    format!("EXPLAIN (GENERIC_PLAN, FORMAT JSON)\n\t{sql};")
}

fn generate_specialized_analyze(sql: &str) -> String {
    format!("EXPLAIN (ANALYZE, COSTS, FORMAT JSON)\n\t{sql};")
}

async fn execute_analyze(
    url: Url,
    sql: String,
    values: Option<Values>,
) -> Result<Option<Vec<ExplainResult>>, DbErr> {
    let conn = Database::connect(url)
        .await
        .expect("Failed to connect to database");
    if conn.get_database_backend() != DatabaseBackend::Postgres {
        return Ok(None);
    }
    let res = conn
        .query_one(if let Some(values) = values {
            Statement::from_sql_and_values(conn.get_database_backend(), sql, values)
        } else {
            Statement::from_string(conn.get_database_backend(), sql)
        })
        .await?
        .map(|r| r.try_get_by_index(0))
        .transpose()?
        .map(|r| serde_json::from_value(r).expect("Failed to parse EXPLAIN result"));

    Ok(res)
}

impl Default for DBMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl DBMetrics {
    #[must_use]
    /// Create a new database metrics holder
    pub fn new() -> Self {
        Self {
            dump_threshold: std::sync::atomic::AtomicU64::new(0),
            query_duration: HistogramVec::new(
                HistogramOpts::new("keyfinix_query_duration", "Query duration in seconds")
                    .buckets(vec![0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0]),
                &["success"],
            )
            .expect("Failed to create prometheus histogram"),
        }
    }

    /// Set the threshold of minimum query duration in microseconds to dump SQL ANALYZE results
    pub fn set_dump_threshold(&self, threshold_us: u64) {
        self.dump_threshold
            .store(threshold_us, std::sync::atomic::Ordering::SeqCst);
    }

    /// Register the metrics to the registry
    pub fn register(&self, registry: &prometheus::Registry) -> prometheus::Result<()> {
        registry.register(Box::new(self.query_duration.clone()))
    }

    /// Create a query callback for the database metrics
    ///
    /// The url parameter is only used for testing to run EXPLAIN queries
    pub fn callback(
        self: Arc<Self>,
        #[cfg_attr(not(feature = "testing-with-sql-dump"), expect(unused))] dump_analyze: Option<(
            Url,
            impl Write + Send + 'static,
        )>,
    ) -> impl Fn(&Info) + Send + Sync + 'static {
        let copy = self.clone();

        #[cfg(feature = "testing-with-sql-dump")]
        thread_local! {
            static ANALYZE_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                });
        };

        #[cfg(feature = "testing-with-sql-dump")]
        let tp = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();

        #[cfg(feature = "testing-with-sql-dump")]
        let dump_analyze = dump_analyze.map(|(url, dump)| (url, Mutex::new(BufWriter::new(dump))));

        move |info: &Info| {
            #[cfg(feature = "testing-with-sql-dump")]
            if let Some((url, dump)) = dump_analyze.as_ref() {
                const ANALYZABLE: &[&str] = &["INSERT", "UPDATE", "DELETE", "SELECT"];

                let threshold = copy
                    .dump_threshold
                    .load(std::sync::atomic::Ordering::SeqCst);

                #[allow(clippy::cast_possible_truncation)]
                if threshold <= info.elapsed.as_micros() as u64
                    && ANALYZABLE
                        .iter()
                        .any(|s| info.statement.sql.trim_start().starts_with(s))
                {
                    let idempotent = ["INSERT", "UPDATE", "DELETE"]
                        .iter()
                        .all(|s| !info.statement.sql.trim_start().starts_with(s));

                    let generic = generate_generic_analyze(&info.statement.sql);
                    let specialized = if info.statement.values.is_some() {
                        generate_specialized_analyze(&inline_values(
                            &info.statement.sql,
                            info.statement.values.clone(),
                        ))
                    } else {
                        generate_specialized_analyze(&info.statement.sql)
                    };

                    let generic_clone = generic.clone();
                    let specialized_clone = specialized.clone();

                    let url = url.clone();
                    let result = tp
                        .install(|| {
                            ANALYZE_RUNTIME.with(|runtime| {
                                runtime.block_on(async move {
                                    execute_analyze(
                                        url,
                                        if idempotent { specialized } else { generic },
                                        if idempotent {
                                            None
                                        } else {
                                            info.statement.values.clone()
                                        },
                                    )
                                    .await
                                })
                            })
                        })
                        .map_err(|e| e.to_string());

                    let mut out_file = dump.lock().unwrap();

                    serde_json::to_writer_pretty(
                        &mut *out_file,
                        &LogEntry {
                            failed: info.failed,
                            duration_us: info.elapsed.as_micros() as u64,
                            statement: info.statement.sql.clone(),
                            statement_inline: inline_values(
                                &info.statement.sql,
                                info.statement.values.clone(),
                            ),
                            explain_generic: generic_clone,
                            explain_specialized: specialized_clone,
                            analyze: result,
                        },
                    )
                    .unwrap();

                    write!(out_file, "\n\n").unwrap();

                    out_file.flush().unwrap();
                }
            }

            copy.query_duration
                .with_label_values(&[if info.failed { "false" } else { "true" }])
                .observe(info.elapsed.as_secs_f64());
        }
    }
}
