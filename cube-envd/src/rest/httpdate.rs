// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! RFC 1123 / HTTP-date formatting and parsing, matching Go's
//! `time.Time.Format(TimeFormat)` and the primary `ParseTime` layout.
//!
//! Go renders dates as `Mon, 02 Jan 2006 15:04:05 GMT` in UTC with whole-second
//! precision (callers truncate first, like upstream's
//! `Truncate(time.Second)`); parsing accepts only that fixed-width form. RFC
//! 850 / asctime fallbacks are intentionally not implemented: real callers
//! never send them, and upstream only uses a parse result to gate a 304/412,
//! where a failed parse means "condition does not apply" either way.
//!
//! Implemented on the `time` crate (already a dependency; this file needs its
//! `parsing` + `formatting` features, enabled in Cargo.toml).

use time::format_description::FormatDescriptionV3;
use time::PrimitiveDateTime;

/// `Mon, 02 Jan 2006 15:04:05 GMT` — literal `GMT`, parsed/formatted in UTC.
/// Syntax version 3 (the `time` crate's current format-description language).
const HTTP_DATE: &str =
    "[weekday repr:short], [day padding:zero] [month repr:short] [year] [hour]:[minute]:[second] GMT";

fn http_date_desc() -> &'static FormatDescriptionV3<'static> {
    // Parsed once at first use; the description is static data.
    use std::sync::OnceLock;
    static DESC: OnceLock<FormatDescriptionV3<'static>> = OnceLock::new();
    DESC.get_or_init(|| {
        time::format_description::parse_owned::<3>(HTTP_DATE)
            .expect("static HTTP-date description is valid")
    })
}

/// Go `modtime.UTC().Format(TimeFormat)` — RFC 1123 with `GMT`, second
/// precision, for a Unix timestamp already truncated to whole seconds.
pub fn format_http_date(unix_secs: i64) -> String {
    let dt = time::OffsetDateTime::from_unix_timestamp(unix_secs)
        .expect("file mtimes after the epoch fit i64 seconds");
    dt.format(http_date_desc())
        .expect("OffsetDateTime always formats with this description")
}

/// Go `ParseTime` on the main `imf-fixdate` layout (see module docs for the
/// deliberate scope). `None` = "condition does not apply" to the caller.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let dt = PrimitiveDateTime::parse(s, http_date_desc()).ok()?;
    Some(dt.assume_utc().unix_timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_date_epoch_and_known() {
        // 1970-01-01T00:00:00Z was a Thursday.
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // Verified civil dates (python datetime).
        assert_eq!(
            format_http_date(1_788_678_000),
            "Sun, 06 Sep 2026 07:00:00 GMT"
        );
        // Leap day (2024 was a leap year); Thu 2024-02-29 12:34:56 UTC.
        assert_eq!(
            format_http_date(1_709_210_096),
            "Thu, 29 Feb 2024 12:34:56 GMT"
        );
    }

    #[test]
    fn http_date_roundtrip() {
        for secs in [0, 1_788_678_000, 1_709_210_096] {
            let s = format_http_date(secs);
            assert_eq!(parse_http_date(&s), Some(secs), "{s}");
        }
    }

    #[test]
    fn http_date_parse_failures() {
        for bad in [
            "",
            "not a date",
            "Sunday, 06-Sep-26 07:00:00 GMT", // RFC 850: unsupported
            "Sun Sep  6 07:00:00 2026",       // asctime: unsupported
            "Sun, 06 Sep 2026 07:00:00 +0000", // zone written out, not GMT
            "Sun, 32 Sep 2026 07:00:00 GMT",  // day out of range
            "Sun, 06 Sep 2026 24:00:00 GMT",  // hour out of range
        ] {
            assert_eq!(parse_http_date(bad), None, "accepted {bad:?}");
        }
    }
}
