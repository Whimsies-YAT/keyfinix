use std::{
    sync::{Arc, atomic::AtomicI64},
    time::Duration,
};

use chrono::{DateTime, Utc};
use governor::clock::{QuantaClock, ReasonablyRealtime};
use rustls::time_provider::TimeProvider;

#[derive(Clone, Debug)]
/// A wrapper around [`::chrono::Utc`] to support Rustls
pub struct ChronoRtc;

/// A UTC real-time clock
pub trait UtcClock: TimeProvider {
    /// Get the current time
    fn now(&self) -> DateTime<Utc>;
}

impl UtcClock for ChronoRtc {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

impl TimeProvider for ChronoRtc {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_secs(Utc::now().timestamp() as u64),
        ))
    }
}

/// A set of clocks used by the service, used for abstracting away logic that depends on time
pub trait ClockSet: Clone + Send + Sync + 'static {
    /// The TSC clock used for rate limiting
    type Tsc: governor::clock::Clock + ReasonablyRealtime + Clone + Send + Sync + 'static;
    /// The UTC real-time clock
    type Utc: UtcClock + Clone + Send + Sync + 'static;

    /// Get the TSC clock
    fn tsc(&self) -> Self::Tsc;
    /// Get the UTC real-time clock
    fn utc(&self) -> Self::Utc;
}

/// A clock set that is used for testing
pub trait MockClockSet: ClockSet {
    /// Create a new clock at the epoch
    fn epoch() -> Self;
    /// Advance the clock by a number of nanoseconds
    fn advance_nanos(&self, nanos: i64);
    /// Advance the clock by a number of milliseconds
    fn advance_millis(&self, millis: i64) {
        self.advance_nanos(millis * 1_000_000);
    }
    /// Advance the clock by a number of seconds
    fn advance_seconds(&self, seconds: i64) {
        self.advance_nanos(seconds * 1_000_000_000);
    }
    /// Advance the clock by a number of minutes
    fn advance_minutes(&self, minutes: i64) {
        self.advance_seconds(minutes * 60);
    }
}

#[derive(Clone, Debug)]
/// A mock UTC real-time clock that can be manually advanced
pub struct MockUtc {
    nanos: Arc<AtomicI64>,
}

impl TimeProvider for MockUtc {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        #[allow(clippy::cast_sign_loss)]
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            Duration::from_nanos(self.nanos.load(std::sync::atomic::Ordering::SeqCst) as u64),
        ))
    }
}

impl UtcClock for MockUtc {
    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(self.nanos.load(std::sync::atomic::Ordering::SeqCst))
    }
}

#[derive(Clone, Debug)]
/// The normal clock set used by the service
pub struct NormalClock;

impl ClockSet for NormalClock {
    type Tsc = governor::clock::QuantaClock;
    type Utc = ChronoRtc;

    fn tsc(&self) -> Self::Tsc {
        governor::clock::QuantaClock::default()
    }

    fn utc(&self) -> Self::Utc {
        ChronoRtc
    }
}

#[derive(Clone, Debug)]
/// A mock clock set that can be manually advanced
pub struct MockClock {
    governor: QuantaClock,
    utc: MockUtc,
}

impl ClockSet for MockClock {
    type Tsc = QuantaClock;
    type Utc = MockUtc;

    fn tsc(&self) -> Self::Tsc {
        self.governor.clone()
    }

    fn utc(&self) -> Self::Utc {
        self.utc.clone()
    }
}

impl MockClockSet for MockClock {
    fn epoch() -> Self {
        Self {
            governor: QuantaClock::default(),
            utc: MockUtc {
                nanos: Arc::new(AtomicI64::new(0)),
            },
        }
    }

    fn advance_nanos(&self, nanos: i64) {
        self.utc
            .nanos
            .fetch_add(nanos, std::sync::atomic::Ordering::SeqCst);
    }
}
