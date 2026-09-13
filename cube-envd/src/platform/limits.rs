// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! Startup limits that a deployment may tune: the blocking-pool size, and the
//! share of it the `/files` data plane is allowed to pin.
//!
//! They live below `app/` because two layers need the same number: `main.rs`
//! sizes the tokio runtime with it, and the filesystem data plane derives its
//! prefetch budget from it (the layer rule forbids `filesystem` reaching into
//! `app/`). The env-var shape copies `process::cgroup`: a `CUBE_ENVD_*` name,
//! parsed once, an invalid value warns and falls back to the default instead of
//! failing startup, and the adjudication is a pure function so it is testable
//! without touching the process environment.

use std::sync::OnceLock;

/// Blocking-pool thread cap (`max_blocking_threads`). 64 keeps the pool's
/// worst-case touched RSS (~13 KiB/thread) inside this daemon's budget while
/// leaving headroom for the sandbox's dozens-of-ops workload; over the cap,
/// work queues instead of erroring. It is a *deployment* property — a guest
/// with a larger memory budget, or a platform that expects many concurrent
/// downloads and uploads, may legitimately want more — so it is configurable.
pub const DEFAULT_BLOCKING_THREADS: usize = 64;
const BLOCKING_THREADS_ENV: &str = "CUBE_ENVD_BLOCKING_THREADS";
/// Below this the pool cannot serve the daemon's own concurrent work; above it
/// the idle-thread RSS stops being defensible inside a guest.
const BLOCKING_THREADS_MIN: usize = 4;
const BLOCKING_THREADS_MAX: usize = 256;

/// `/files` may pin at most `pool / this` blocking threads on prefetch
/// producers. Downloads are the only user that holds a pool thread for the
/// whole duration of a client stall, so they get a quarter of the pool and
/// everything else (process reaping, uploads, filesystem RPCs) keeps the rest.
/// Derived, never configured on its own: a budget larger than the pool would
/// reintroduce exactly the starvation it exists to bound.
const DOWNLOAD_PREFETCH_DIVISOR: usize = 4;

static BLOCKING_THREADS: OnceLock<usize> = OnceLock::new();

/// Blocking-pool cap: `CUBE_ENVD_BLOCKING_THREADS`, else the default.
pub fn blocking_threads() -> usize {
    *BLOCKING_THREADS.get_or_init(|| {
        let raw = match std::env::var(BLOCKING_THREADS_ENV) {
            Ok(raw) => Some(raw),
            Err(std::env::VarError::NotPresent) => None,
            Err(e) => {
                tracing::warn!("limits: cannot read {BLOCKING_THREADS_ENV}: {e}");
                None
            }
        };
        blocking_threads_from(raw.as_deref())
    })
}

/// Prefetch budget for the `/files` body pipeline, derived from the pool size.
pub fn download_prefetch() -> usize {
    prefetch_from(blocking_threads())
}

/// Adjudicate a configured value: unset or unparsable falls back to the
/// default, and anything outside the sane range is clamped rather than
/// refused (an in-guest daemon that refuses to start over a typo is worse than
/// one that runs with a warned-about value).
fn blocking_threads_from(raw: Option<&str>) -> usize {
    let Some(raw) = raw else {
        return DEFAULT_BLOCKING_THREADS;
    };
    match raw.parse::<usize>() {
        Ok(0) | Err(_) => {
            tracing::warn!(
                "limits: ignoring invalid {BLOCKING_THREADS_ENV}={raw:?}; \
                 expected a positive thread count"
            );
            DEFAULT_BLOCKING_THREADS
        }
        Ok(n) if !(BLOCKING_THREADS_MIN..=BLOCKING_THREADS_MAX).contains(&n) => {
            let clamped = n.clamp(BLOCKING_THREADS_MIN, BLOCKING_THREADS_MAX);
            tracing::warn!("limits: clamping {BLOCKING_THREADS_ENV}={n} to {clamped}");
            clamped
        }
        Ok(n) => n,
    }
}

fn prefetch_from(pool: usize) -> usize {
    (pool / DOWNLOAD_PREFETCH_DIVISOR).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_or_invalid_value_falls_back_to_the_default() {
        assert_eq!(blocking_threads_from(None), DEFAULT_BLOCKING_THREADS);
        for raw in ["", "abc", "0", "-1", "64.5", " 64"] {
            assert_eq!(
                blocking_threads_from(Some(raw)),
                DEFAULT_BLOCKING_THREADS,
                "{raw:?} must fall back, not fail startup"
            );
        }
    }

    #[test]
    fn a_valid_value_is_used_and_an_extreme_one_is_clamped() {
        assert_eq!(blocking_threads_from(Some("8")), 8);
        assert_eq!(blocking_threads_from(Some("256")), 256);
        assert_eq!(blocking_threads_from(Some("1")), BLOCKING_THREADS_MIN);
        assert_eq!(blocking_threads_from(Some("100000")), BLOCKING_THREADS_MAX);
    }

    /// The budget is derived, so lowering the pool lowers it too: that is the
    /// invariant that keeps downloads from pinning the whole pool.
    #[test]
    fn the_prefetch_budget_is_a_quarter_of_the_pool_and_never_zero() {
        assert_eq!(prefetch_from(DEFAULT_BLOCKING_THREADS), 16);
        assert_eq!(prefetch_from(8), 2);
        assert_eq!(prefetch_from(1), 1);
        assert_eq!(prefetch_from(0), 1);
    }
}
