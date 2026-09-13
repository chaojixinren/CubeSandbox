// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! GET `/files`: download, Range and conditional request handling.

use std::collections::HashMap;

use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use super::errors::{check_token_rest, resolve_request_user};
use crate::filesystem::http::{content_disposition, encoding, httpdate, preconditions, ranges};
use crate::platform::config::Config;
use crate::platform::identity;
use crate::protocol::RestError;

/// GET /files — stream a file back with upstream `http.ServeContent`
/// semantics: Last-Modified, conditional requests (If-Match / If-Unmodified-
/// Since / If-None-Match / If-Modified-Since / If-Range → 304/412), Range
/// (single range → 206, unsatisfiable → 416), Accept-Ranges, and the two 406
/// Accept-Encoding exits — in upstream download.go's exact order. The stages
/// below are extracted as helpers so each mirrors one upstream step; the
/// order of the calls *is* the pipeline order.
pub async fn download(
    config: &Config,
    params: HashMap<String, String>,
    headers: HeaderMap,
) -> axum::response::Response {
    // Stage 1: token → user → path → stat/isdir (error order unchanged).
    let ResolvedFile { path, meta } = match resolve_download(config, &params, &headers).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // Stage 2: Accept-Encoding gates (parse 406 before Vary is set, identity
    // gate after it — upstream's order).
    if let Err(resp) = gate_accept_encoding(&headers) {
        return resp;
    }
    // Stage 3: open once; the handle is reused for sniffing, seek and stream.
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            return RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': {e}"),
            )
            .into_response();
        }
    };
    // Stage 4: preset headers (Vary / Content-Disposition / Last-Modified)
    // and the modtime the conditional steps key off.
    let preset = Preset::new(&path, &meta);
    // Stage 5: conditional requests → 304/412. Runs before the Content-Type
    // probe so those answers carry no Content-Type, exactly like upstream.
    if let Some(resp) = preset.condition_response(&headers) {
        return resp;
    }
    // Stage 6: Content-Type sniff (approximates Go's DetectContentType); a
    // failed rewind reopens the file so the body still starts at byte 0.
    // Known difference, left deliberately: fs.go's sniff path 500s on a
    // rewind failure, we reopen and continue — unreachable for practical
    // files, and a genuinely non-seekable handle is caught by the Seek(End)
    // in stage 6b below anyway. Do not "fix" this toward Go.
    let content_type = match sniff_content_type_or_reopen(&mut file, &path).await {
        Ok(ct) => ct,
        Err(resp) => return resp,
    };
    // Stage 6b: response size from the open handle — Go's sizeFunc is
    // Seek(End) + Seek(Start), NOT the earlier path stat (fs.go serveContent
    // via ServeContent's sizeFunc). This makes /dev/zero-style devices
    // (SeekEnd = 0) answer Content-Length: 0 with an empty body instead of
    // streaming forever, and a non-seekable file (/proc/* reports EINVAL on
    // SeekEnd) fail exactly like Go's errSeeker path. It also closes the
    // stat-vs-handle size race: only the modtime still comes from the path
    // stat, like download.go.
    use tokio::io::AsyncSeekExt;
    // Either seek failing is Go's errSeeker → serveError(500, "seeker can't
    // seek") — including the (unreachable on Linux) case of Seek(End)
    // succeeding but Seek(Start) failing. Never panic here: this is the
    // request path's only non-builder expect, and the panic handler answers
    // a JSON shape, not Go's text/plain serveError.
    let seek_end = file.seek(std::io::SeekFrom::End(0)).await;
    let size = match seek_end {
        Ok(s) => s,
        Err(_) => {
            // fs.go: serveError(w, "seeker can't seek", 500) — plain_error
            // is that exact shape (Vary/Disposition kept, Last-Modified
            // stripped, text/plain + nosniff, "text\n").
            return preset.plain_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                "seeker can't seek\n".to_string(),
            );
        }
    };
    if file.seek(std::io::SeekFrom::Start(0)).await.is_err() {
        return preset.plain_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "seeker can't seek\n".to_string(),
        );
    }
    // Stage 7: Range dispatch — If-Range gate, parse, single-range seek.
    let single = match plan_range(&mut file, &headers, &preset, size).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // Stage 8: assemble the success response (200 full / 206 range).
    // Both arms stream exactly their send size: Go io.CopyN(sendSize) reads
    // nothing for size 0 (/dev/zero → CL: 0, empty body) and never overruns
    // the Seek(End) size.
    let (code, stream_limit) = match &single {
        Some(r) => (StatusCode::PARTIAL_CONTENT, Some(r.length as u64)),
        None => (StatusCode::OK, Some(size)),
    };

    // Common success headers: Content-Type always; Content-Range only on
    // 206; Accept-Ranges always; Content-Length always on 200 — Go's
    // serveContent sets it unconditionally for identity responses, so a
    // size-0 answer (empty file, /dev/zero) carries an explicit CL: 0.
    let mut b = axum::response::Response::builder().status(code);
    b = preset.apply(b);
    b = b.header(axum::http::header::CONTENT_TYPE, content_type);
    if let Some(r) = single {
        b = b.header(
            axum::http::header::CONTENT_RANGE,
            r.content_range(size as i64),
        );
    }
    b = b.header(axum::http::header::ACCEPT_RANGES, "bytes");
    let body_len = match single {
        Some(r) => Some(r.length as u64),
        None => Some(size),
    };
    if let Some(len) = body_len {
        b = b.header(axum::http::header::CONTENT_LENGTH, len);
    }
    // Global cap on concurrent large bodies: a stalled client must not be able
    // to grow the daemon's memory with the connection count, and a request that
    // does not get a slot is refused rather than queued (see acquire_in_flight).
    let in_flight = match acquire_in_flight(stream_limit, &in_flight_budget()) {
        Ok(permit) => permit,
        Err(()) => {
            return RestError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "too many concurrent file downloads (limit {}); retry when some finish",
                    crate::platform::limits::download_max_bodies()
                ),
            )
            .into_response();
        }
    };
    let stream = reader_stream(file, stream_limit, in_flight).await;
    b.body(axum::body::Body::from_stream(stream))
        .expect("build download response")
}

/// Stage 1 result: the request resolved to a path whose stat succeeded and
/// which is not a directory.
pub(crate) struct ResolvedFile {
    pub(crate) path: String,
    pub(crate) meta: std::fs::Metadata,
}

/// Stage 1 — token → user → path → stat. Mirrors download.go's order; every
/// error exit keeps its baseline status and message.
#[allow(clippy::result_large_err)] // axum helpers propagate prebuilt responses, not an error type
async fn resolve_download(
    config: &Config,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<ResolvedFile, axum::response::Response> {
    if let Err(e) = check_token_rest(config, headers) {
        return Err(e.into_response());
    }
    let user = match resolve_request_user(config, params, headers) {
        Ok(u) => u,
        Err(e) => return Err(e.into_response()),
    };
    // Baseline: a missing `path` parameter falls back to the user's home
    // directory (which then fails with the "is a directory" error). A
    // `/init`-configured defaultWorkdir takes that slot instead — upstream
    // resolves an empty path through ResolveDefaultWorkdir first
    // (`execcontext/context.go:15`) and only then anchors it at the home dir.
    let raw_path = params
        .get("path")
        .filter(|p| !p.is_empty())
        .cloned()
        .or_else(|| config.default_workdir())
        .unwrap_or_else(|| user.home.clone());
    let path = identity::resolve_path(&raw_path, &user);

    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(RestError::new(
                StatusCode::NOT_FOUND,
                format!("path '{path}' does not exist"),
            )
            .into_response());
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': permission denied"),
            )
            .into_response());
        }
        Err(e) => {
            return Err(RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': {e}"),
            )
            .into_response());
        }
    };
    if meta.is_dir() {
        return Err(RestError::new(
            StatusCode::BAD_REQUEST,
            format!("path '{path}' is a directory"),
        )
        .into_response());
    }
    Ok(ResolvedFile { path, meta })
}

/// Stage 2 — the two Accept-Encoding 406 exits, in upstream order: the parse
/// failure answers before `Vary` is set; the Range/conditional identity gate
/// answers after it and therefore carries `Vary` itself (nginx's `add_header
/// Vary` has no `always`, so error responses must carry it when upstream
/// does).
#[allow(clippy::result_large_err)] // axum helpers propagate prebuilt responses, not an error type
fn gate_accept_encoding(headers: &HeaderMap) -> Result<(), axum::response::Response> {
    let ae_value = header_str(headers, axum::http::header::ACCEPT_ENCODING);
    let ae = ae_value.as_deref().unwrap_or("");
    if encoding::parse_accept_encoding(ae).is_err() {
        return Err(RestError::new(
            StatusCode::NOT_ACCEPTABLE,
            "error parsing Accept-Encoding: no acceptable encoding found, supported: [gzip]",
        )
        .into_response());
    }
    // cube-envd serves identity only: the parsed best encoding is
    // deliberately unused, but the rejection above must stay.
    let has_range_or_conditional = [
        axum::http::header::RANGE,
        axum::http::header::IF_MODIFIED_SINCE,
        axum::http::header::IF_NONE_MATCH,
        axum::http::header::IF_RANGE,
    ]
    .iter()
    .any(|h| {
        header_str(headers, h.clone())
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    });
    if has_range_or_conditional && !encoding::is_identity_acceptable(ae) {
        // This 406 answers AFTER Vary was set, so it must carry Vary itself
        // (see fn doc). Body shape matches RestError / upstream jsonError.
        let body = serde_json::json!({
            "code": 406,
            "message": "identity encoding not acceptable for Range or conditional request",
        })
        .to_string();
        return Err(axum::response::Response::builder()
            .status(StatusCode::NOT_ACCEPTABLE)
            .header(axum::http::header::VARY, "Accept-Encoding")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(axum::body::Body::from(body))
            .expect("build 406 response"));
    }
    Ok(())
}

/// The header set shared by every download answer: Vary + Content-Disposition
/// (+ Last-Modified when the mtime is meaningful), plus the variant that
/// drops Last-Modified for 416 (fs.go serveError).
struct Preset {
    /// fs.go `checkPreconditions`/`setLastModified` view of the mtime:
    /// `None` = `isZeroTime` (exactly the epoch, or unavailable) — no
    /// Last-Modified and the date-based conditions do not apply.
    modtime: Option<i64>,
    /// fs.go `checkIfRange` view: no zero-time gate there, only
    /// `t.Unix() == modtime.Unix()` — so this is the floor seconds whenever
    /// the mtime is known at all (epoch included).
    if_range_secs: Option<i64>,
    headers: Vec<(axum::http::HeaderName, String)>,
    no_last_modified: Vec<(axum::http::HeaderName, String)>,
}

/// fs.go's mtime semantics (net/http): the raw mtime is compared against the
/// exact epoch (`isZeroTime`) *before* any truncation, so a sub-second mtime
/// near 1970 is not "no time" — Last-Modified prints its floor second and
/// the date conditions compare the floor (`Truncate(time.Second)`, which
/// floors). A pre-epoch mtime is kept too: Go `Truncate` floors on the
/// absolute timeline, so -1.5s lands on -2s. Only an exactly-epoch (or
/// unreportable) mtime means "no time".
pub(crate) fn modtime_of(
    res: std::io::Result<std::time::SystemTime>,
) -> (Option<i64>, Option<i64>) {
    let Ok(t) = res else {
        // Go: a failed ModTime() is the zero Time → isZeroTime.
        return (None, None);
    };
    let (secs, is_exact_epoch) = match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.is_zero()),
        Err(e) => {
            // Pre-epoch: duration_since yields the distance back to the
            // epoch; floor on the epoch axis (Go Truncate floors).
            let d = e.duration();
            let mut s = -(d.as_secs() as i64);
            if d.subsec_nanos() > 0 {
                s -= 1;
            }
            (s, false)
        }
    };
    let precondition_secs = if is_exact_epoch { None } else { Some(secs) };
    (precondition_secs, Some(secs))
}

impl Preset {
    /// Upstream sets Content-Disposition before http.ServeContent, which then
    /// adds Last-Modified from the stat mtime (unless isZeroTime).
    fn new(path: &str, meta: &std::fs::Metadata) -> Preset {
        let disposition = content_disposition::format_content_disposition(
            std::path::Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download"),
        );
        let (modtime, if_range_secs) = modtime_of(meta.modified());
        let mut headers = Vec::with_capacity(3);
        headers.push((axum::http::header::VARY, "Accept-Encoding".to_string()));
        headers.push((axum::http::header::CONTENT_DISPOSITION, disposition));
        if let Some(mt) = modtime {
            headers.push((
                axum::http::header::LAST_MODIFIED,
                httpdate::format_http_date(mt),
            ));
        }
        let no_last_modified = headers
            .iter()
            .filter(|(k, _)| *k != axum::http::header::LAST_MODIFIED)
            .cloned()
            .collect();
        Preset {
            modtime,
            if_range_secs,
            headers,
            no_last_modified,
        }
    }

    fn apply(&self, mut b: axum::http::response::Builder) -> axum::http::response::Builder {
        for (k, v) in &self.headers {
            b = b.header(k.clone(), v.clone());
        }
        b
    }

    fn apply_without_last_modified(
        &self,
        mut b: axum::http::response::Builder,
    ) -> axum::http::response::Builder {
        for (k, v) in &self.no_last_modified {
            b = b.header(k.clone(), v.clone());
        }
        b
    }

    /// Stage 5 — fs.go checkPreconditions: 304 (writeNotModified header set)
    /// or 412 (bare) when a condition fires, else the download continues.
    fn condition_response(&self, headers: &HeaderMap) -> Option<axum::response::Response> {
        use preconditions::CondOutcome;
        match preconditions::check_preconditions(
            header_str(headers, axum::http::header::IF_MATCH).as_deref(),
            header_str(headers, axum::http::header::IF_UNMODIFIED_SINCE).as_deref(),
            header_str(headers, axum::http::header::IF_NONE_MATCH).as_deref(),
            header_str(headers, axum::http::header::IF_MODIFIED_SINCE).as_deref(),
            self.modtime,
        ) {
            CondOutcome::NotModified => {
                // fs.go writeNotModified: strips Content-Type/Content-Length/
                // Content-Encoding (none set yet here) and keeps Last-Modified
                // (no ETag).
                Some(self.empty(StatusCode::NOT_MODIFIED))
            }
            CondOutcome::PreconditionFailed => {
                // fs.go: bare 412, no body, no Content-Type.
                Some(self.empty(StatusCode::PRECONDITION_FAILED))
            }
            CondOutcome::Serve => None,
        }
    }

    /// Empty-bodied 304/412 answer carrying the preset headers.
    fn empty(&self, code: StatusCode) -> axum::response::Response {
        self.apply(axum::response::Response::builder().status(code))
            .body(axum::body::Body::empty())
            .expect("build error response")
    }

    /// fs.go serveError shape: text/plain + nosniff, optional Content-Range,
    /// explicit Content-Length, Last-Modified stripped (416 and the 206 seek
    /// failure both answer this way).
    fn plain_error(
        &self,
        code: StatusCode,
        content_range: Option<String>,
        body: String,
    ) -> axum::response::Response {
        let mut b =
            self.apply_without_last_modified(axum::response::Response::builder().status(code));
        if let Some(cr) = content_range {
            b = b.header(axum::http::header::CONTENT_RANGE, cr);
        }
        b.header(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )
        .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(axum::http::header::CONTENT_LENGTH, body.len())
        .body(axum::body::Body::from(body))
        .expect("build plain error response")
    }
}

/// Stage 6 — approximate Go's DetectContentType with a text/binary split
/// (the full table is a non-goal). A failed rewind means a non-seekable
/// special file: reopen so the stream still starts at byte 0.
#[allow(clippy::result_large_err)] // axum helpers propagate prebuilt responses, not an error type
async fn sniff_content_type_or_reopen(
    file: &mut tokio::fs::File,
    path: &str,
) -> Result<&'static str, axum::response::Response> {
    match sniff_content_type(file).await {
        Ok(ct) => Ok(ct),
        Err(_) => match tokio::fs::File::open(path).await {
            Ok(f) => {
                *file = f;
                Ok("application/octet-stream")
            }
            Err(e) => Err(RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': {e}"),
            )
            .into_response()),
        },
    }
}

/// Stage 7 — fs.go serveContent Range dispatch: an If-Range that fails drops
/// the Range header (full 200); a single range is seeked for the 206; any
/// multi-range request is answered with the full file; the 416 shapes and the
/// seek-error 416 are emitted here.
#[allow(clippy::result_large_err)] // axum helpers propagate prebuilt responses, not an error type
async fn plan_range(
    file: &mut tokio::fs::File,
    headers: &HeaderMap,
    preset: &Preset,
    size: u64,
) -> Result<Option<ranges::ByteRange>, axum::response::Response> {
    let range_value = header_str(headers, axum::http::header::RANGE);
    let range_hdr = range_value.as_deref();
    let range_kept = range_hdr.is_some_and(|_| {
        preconditions::if_range_keeps_range(
            header_str(headers, axum::http::header::IF_RANGE).as_deref(),
            preset.if_range_secs,
        )
    });
    let ranges = if range_kept {
        ranges::parse_range(range_hdr, size as i64)
    } else {
        Ok(None)
    };
    let single = match ranges {
        Ok(ranges) => {
            // A single-range request is served as 206; any multi-range
            // request is answered with the full file instead.
            if ranges.as_ref().is_some_and(|r| r.len() == 1) {
                ranges.unwrap().pop()
            } else {
                None
            }
        }
        // errNoOverlap with an empty file is ignored (fs.go: some clients
        // always send Range; answer 200 rather than 416).
        Err(ranges::RangeError::NoOverlap) if size == 0 => None,
        Err(e) => {
            let cr = match e {
                ranges::RangeError::NoOverlap => Some(format!("bytes */{size}")),
                ranges::RangeError::Invalid => None,
            };
            let body = format!("{}\n", e.message());
            return Err(preset.plain_error(StatusCode::RANGE_NOT_SATISFIABLE, cr, body));
        }
    };
    if let Some(r) = single {
        use tokio::io::AsyncSeekExt;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(r.start as u64)).await {
            let body = format!("{e}\n");
            return Err(preset.plain_error(StatusCode::RANGE_NOT_SATISFIABLE, None, body));
        }
    }
    Ok(single)
}

/// Header value as text. Go's `Header.Get` is byte-oriented and feeds raw
/// bytes to the parsers, where non-ASCII is just garbage — and garbage (a
/// present value) deliberately has different outcomes from absent here
/// (scan break vs. condNone, 416 vs. 200, 406 vs. pass). hyper accepts
/// obs-text (0x80-0xFF) in header values, so `to_str()`-based extraction
/// would silently reclassify garbage as "absent"; lossy UTF-8 keeps the
/// value present and maps every invalid byte to U+FFFD, which every parser
/// below treats exactly like Go treats the raw byte (an ETag tag-char that
/// never terminates, a name/literal/digit mismatch in dates and ranges, a
/// plain token in Accept-Encoding).
fn header_str(
    headers: &HeaderMap,
    name: axum::http::HeaderName,
) -> Option<std::borrow::Cow<'_, str>> {
    headers
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()))
}

/// text/plain for valid-UTF-8, NUL-free content (first 512 bytes), else
/// application/octet-stream. Reads from the already-open handle and rewinds,
/// so the file is opened exactly once per download; a failed rewind is
/// returned as Err so the caller can reopen rather than stream from a
/// mid-file offset.
async fn sniff_content_type(f: &mut tokio::fs::File) -> std::io::Result<&'static str> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut buf = [0u8; 512];
    // A failed read must fall back to the generic binary type, not be
    // treated as "0 bytes of text".
    let n = match f.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => {
            f.rewind().await?;
            return Ok("application/octet-stream");
        }
    };
    f.rewind().await?;
    let head = &buf[..n];
    let looks_text = !head.contains(&0)
        && match std::str::from_utf8(head) {
            Ok(_) => true,
            // A multi-byte char may be cut at the 512-byte boundary.
            Err(e) => e.valid_up_to() + 4 > head.len(),
        };
    if looks_text {
        Ok("text/plain; charset=utf-8")
    } else {
        Ok("application/octet-stream")
    }
}

/// Read size for a download body.
///
/// A download is limited by per-chunk cost, not bandwidth: each chunk costs a
/// read syscall, an allocation and (in a sandbox) a wakeup, and Go's
/// `http.ServeContent` sidesteps all of it with a kernel-side `sendfile` loop
/// that cube-envd's body stream cannot reach. So this path buys the equivalent
/// the other way: as few chunks as possible, read and written concurrently,
/// over recycled buffers.
///
/// The size is a memory/syscall trade, not a knee: each doubling halves the
/// read (and channel-wakeup) syscalls and doubles the buffers in flight. On one
/// 32 MiB body the daemon's syscall count per download was 343 at 512 KiB, 226
/// at 1 MiB and 171 at 2 MiB, against 1102 before this change; 1 MiB keeps the
/// extra memory at ~4 MiB per body in flight while capturing most of the drop.
/// Only the chunking changes: total bytes, `Content-Length` and range
/// boundaries are unaffected.
const DOWNLOAD_CHUNK: usize = 1024 * 1024;

/// How far the buffered reader may run ahead of the socket. Two chunks are
/// enough to keep the read off the write's critical path; the socket, not the
/// disk, is the slower side, so a deeper window only costs memory.
const DOWNLOAD_READ_AHEAD: usize = 2;

/// Slice size for a body that could not get a *buffered* slot: it streams
/// without read-ahead, so its footprint is a slice or two instead of four 1 MiB
/// buffers. This is the tier that keeps a storm of stalled downloads from
/// growing the daemon's memory with the connection count.
const DOWNLOAD_STREAM_SLICE: usize = 256 * 1024;

/// A read buffer that recycles itself into its pool once the last `Bytes`
/// slice of it is dropped.
struct PooledBuffer {
    pool: ReadPool,
    buf: Vec<u8>,
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.pool.recycle(std::mem::take(&mut self.buf));
    }
}

/// Recycled read buffers. Allocating a fresh `DOWNLOAD_CHUNK` buffer per read
/// costs an `mmap`, a `munmap` and a page-faulting zero-fill of the whole
/// chunk — under musl that was 278 syscalls per 32 MiB download (142 `mmap` +
/// 136 `munmap`), a quarter of the whole path's budget. Recycling keeps the
/// allocation count per body constant instead of per chunk.
#[derive(Clone)]
struct ReadPool {
    free: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    len: usize,
    /// Buffers kept for reuse: `READ_AHEAD` queued, one being filled by the
    /// reader and one in flight to the socket.
    keep: usize,
}

impl ReadPool {
    fn new(len: usize) -> ReadPool {
        let len = len.max(1);
        ReadPool {
            free: Default::default(),
            len,
            keep: DOWNLOAD_READ_AHEAD + 2,
        }
    }

    /// A buffer of at least `len` bytes, reused when one is free.
    fn take(&self) -> Vec<u8> {
        let recycled = match self.free.lock() {
            Ok(mut free) => free.pop(),
            // A poisoned lock only means some *other* download's body task
            // panicked; the buffers themselves are plain bytes.
            Err(poisoned) => poisoned.into_inner().pop(),
        };
        recycled.unwrap_or_else(|| vec![0u8; self.len])
    }

    fn recycle(&self, buf: Vec<u8>) {
        if buf.len() != self.len {
            return;
        }
        // Bound both arms: a poisoned lock must not turn the pool into an
        // unbounded one (same reasoning as `take`'s poison handling).
        let mut free = match self.free.lock() {
            Ok(free) => free,
            Err(poisoned) => poisoned.into_inner(),
        };
        if free.len() < self.keep {
            free.push(buf);
        }
    }

    /// `Bytes` over the first `n` bytes of `buf`, recycled when dropped.
    fn bytes(&self, buf: Vec<u8>, n: usize) -> bytes::Bytes {
        bytes::Bytes::from_owner(PooledBuffer {
            pool: self.clone(),
            buf,
        })
        .slice(..n)
    }
}

/// The two global download budgets (see `platform/limits.rs`), held for the
/// life of a body's producer and passed in so tests can drive the tiers.
///
/// `blocking` bounds *pool threads*: a permit buys the blocking producer, the
/// fast shape, and is held until the body ends, so at most that many threads
/// can ever be pinned by downloads.
/// `buffered` bounds *memory*: a permit buys read-ahead with 1 MiB slices
/// (~4.5 MiB per stalled body). Without it a body still streams, but in 256 KiB
/// slices without read-ahead, so a storm of stalled downloads cannot grow the
/// daemon's memory with the connection count.
#[derive(Clone)]
struct Budgets {
    blocking: std::sync::Arc<tokio::sync::Semaphore>,
    buffered: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Permits held by one body's producer; dropping them returns the budgets.
struct BudgetGuard {
    _in_flight: Option<tokio::sync::OwnedSemaphorePermit>,
    _blocking: Option<tokio::sync::OwnedSemaphorePermit>,
    _buffered: Option<tokio::sync::OwnedSemaphorePermit>,
}

static BUDGETS: std::sync::OnceLock<Budgets> = std::sync::OnceLock::new();

/// Global cap on concurrent large downloads (`platform/limits.rs`). Unlike the
/// tier budgets this one is acquired by the *handler*, because a request over
/// the cap must be refused with a status code the body stream cannot produce.
static IN_FLIGHT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::OnceLock::new();

fn in_flight_budget() -> std::sync::Arc<tokio::sync::Semaphore> {
    IN_FLIGHT
        .get_or_init(|| {
            std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::platform::limits::download_max_bodies(),
            ))
        })
        .clone()
}

/// Take a global slot for a body that is *not* a single read.
///
/// `Ok(None)` means the body is small enough not to count (a body that fits in
/// one chunk costs a single read, so it is exempt), `Ok(Some(permit))` holds a
/// slot until the body ends, and `Err(())` means the request must be refused —
/// never queued, because queueing would put this download behind the stalled
/// one that is holding the slots.
#[allow(clippy::result_unit_err)] // `()` is the whole verdict; the caller owns the 503 shape
fn acquire_in_flight(
    limit: Option<u64>,
    budget: &std::sync::Arc<tokio::sync::Semaphore>,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ()> {
    if matches!(limit, Some(n) if n <= DOWNLOAD_CHUNK as u64) {
        return Ok(None);
    }
    budget.clone().try_acquire_owned().map(Some).map_err(|_| ())
}

fn budgets() -> Budgets {
    BUDGETS
        .get_or_init(|| Budgets {
            blocking: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::platform::limits::download_blocking_producers(),
            )),
            buffered: std::sync::Arc::new(tokio::sync::Semaphore::new(
                crate::platform::limits::download_buffered_bodies(),
            )),
        })
        .clone()
}

/// Chunked reader stream (`DOWNLOAD_CHUNK`) without pulling in tokio-util.
/// `limit` bounds the total bytes produced (single-range 206 bodies); `None`
/// streams to EOF.
async fn reader_stream(
    file: tokio::fs::File,
    limit: Option<u64>,
    in_flight: Option<tokio::sync::OwnedSemaphorePermit>,
) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>> {
    reader_stream_with(budgets(), file, limit, in_flight).await
}

/// The body pipeline, with the budgets passed in so tests can drive the tiers
/// without the process-wide semaphores.
///
/// A body that fits in one chunk keeps the plain single-read shape (one
/// blocking crossing, no permit and no producer task): the pipeline below only
/// pays off across several chunks, and small files are the common SDK
/// download.
///
/// A larger body runs one of three producers. All three deliver the same bytes;
/// they differ only in what a *stalled* client costs the daemon:
///
/// 1. `DOWNLOAD_CHUNK` slices with read-ahead, read by one `spawn_blocking`
///    task for the whole body — a single pool crossing, and therefore a thread
///    held until the body ends (`blocking` budget, default pool/4).
/// 2. the same shape as an async task: the read still crosses the pool, but a
///    stalled body parks on the channel instead of on a thread (`buffered`
///    budget, default pool/2).
/// 3. without either permit, `DOWNLOAD_STREAM_SLICE` slices, one at a time and
///    with no read-ahead: slower per byte, but a stalled storm of these grows
///    memory with one or two 256 KiB slices per connection instead of four
///    1 MiB buffers.
async fn reader_stream_with(
    budgets: Budgets,
    mut file: tokio::fs::File,
    limit: Option<u64>,
    in_flight: Option<tokio::sync::OwnedSemaphorePermit>,
) -> futures::stream::BoxStream<'static, Result<bytes::Bytes, std::io::Error>> {
    use futures::StreamExt;
    use tokio::io::AsyncReadExt;

    if let Some(n) = limit {
        if n <= DOWNLOAD_CHUNK as u64 {
            return futures::stream::once(async move {
                let mut buf = vec![0u8; n as usize];
                match file.read(&mut buf).await {
                    // A short read (the file shrank under us) is the whole
                    // body; an empty one is no body at all, like EOF.
                    Ok(0) => None,
                    Ok(read) => {
                        buf.truncate(read);
                        Some(Ok(bytes::Bytes::from(buf)))
                    }
                    Err(e) => Some(Err(e)),
                }
            })
            .filter_map(futures::future::ready)
            .boxed();
        }
    }

    // Never `acquire().await` on either budget: waiting for a permit would turn
    // a saturated budget into head-of-line blocking behind a stalled body.
    // Degrading to the next tier is slower but bounded.
    let buffered = match budgets.buffered.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            // Tier 3: no buffered slot, so stream 256 KiB slices without
            // read-ahead and hold nothing else.
            let pool = ReadPool::new(match limit {
                Some(n) => (n as usize).min(DOWNLOAD_STREAM_SLICE),
                None => DOWNLOAD_STREAM_SLICE,
            });
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            tokio::spawn(read_ahead(
                file,
                limit,
                pool,
                tx,
                DOWNLOAD_STREAM_SLICE,
                BudgetGuard {
                    _in_flight: in_flight,
                    _blocking: None,
                    _buffered: None,
                },
            ));
            return tokio_stream::wrappers::ReceiverStream::new(rx).boxed();
        }
    };
    let pool = ReadPool::new(match limit {
        Some(n) => (n as usize).min(DOWNLOAD_CHUNK),
        None => DOWNLOAD_CHUNK,
    });
    let (tx, rx) = tokio::sync::mpsc::channel(DOWNLOAD_READ_AHEAD);
    match budgets.blocking.try_acquire_owned() {
        Ok(blocking) => {
            // `into_std` waits for any in-flight operation on the tokio handle;
            // from here the producer owns the fd and does plain blocking reads.
            let std_file = file.into_std().await;
            let guard = BudgetGuard {
                _in_flight: in_flight,
                _blocking: Some(blocking),
                _buffered: Some(buffered),
            };
            tokio::task::spawn_blocking(move || {
                read_ahead_blocking(std_file, limit, pool, tx, DOWNLOAD_CHUNK, guard)
            });
        }
        Err(_) => {
            let guard = BudgetGuard {
                _in_flight: in_flight,
                _blocking: None,
                _buffered: Some(buffered),
            };
            tokio::spawn(read_ahead(file, limit, pool, tx, DOWNLOAD_CHUNK, guard));
        }
    }
    tokio_stream::wrappers::ReceiverStream::new(rx).boxed()
}

/// The tier-1 producer: one pool crossing for the whole body, plain blocking
/// reads. Holds `_guard` (and therefore both budgets) until the body ends,
/// which is what makes the budgets bounds on *resources in use* rather than on
/// a rate.
fn read_ahead_blocking(
    mut file: std::fs::File,
    mut limit: Option<u64>,
    pool: ReadPool,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    chunk: usize,
    _guard: BudgetGuard,
) {
    use std::io::Read;
    loop {
        let want = match limit {
            Some(0) => return,
            Some(r) => r.min(chunk as u64) as usize,
            None => chunk,
        };
        let mut buf = pool.take();
        match file.read(&mut buf[..want]) {
            Ok(0) => return,
            Ok(n) => {
                if let Some(r) = limit.as_mut() {
                    *r -= n as u64;
                }
                if tx.blocking_send(Ok(pool.bytes(buf, n))).is_err() {
                    // The body was dropped (client gone, or the response ended
                    // early) — stop reading rather than fill the channel.
                    return;
                }
            }
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
                return;
            }
        }
    }
}

/// The async producer, used by tiers 2 and 3: the same loop, but it must not
/// hold a pool thread while the client is not reading, so it awaits both the
/// read and the send. Tier 2 passes `DOWNLOAD_CHUNK` with a read-ahead channel;
/// tier 3 passes `DOWNLOAD_STREAM_SLICE` and a one-slot channel, so its
/// footprint stays at a slice or two.
async fn read_ahead(
    mut file: tokio::fs::File,
    mut limit: Option<u64>,
    pool: ReadPool,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
    chunk: usize,
    _guard: BudgetGuard,
) {
    use tokio::io::AsyncReadExt;
    loop {
        let want = match limit {
            Some(0) => return,
            Some(r) => r.min(chunk as u64) as usize,
            None => chunk,
        };
        let mut buf = pool.take();
        match file.read(&mut buf[..want]).await {
            Ok(0) => return,
            Ok(n) => {
                if let Some(r) = limit.as_mut() {
                    *r -= n as u64;
                }
                if tx.send(Ok(pool.bytes(buf, n))).await.is_err() {
                    // The body was dropped (client gone, or the response ended
                    // early) — stop reading rather than fill the channel.
                    return;
                }
            }
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    /// Deterministic, position-dependent content: a chunk sliced from the
    /// wrong offset of a pooled buffer still has the right length.
    fn write_pattern(path: &std::path::Path, size: usize) {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(path, data).unwrap();
    }

    /// Generous budgets, injected so no test depends on the process-wide ones.
    fn test_budgets() -> Budgets {
        Budgets {
            blocking: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
            buffered: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
        }
    }

    async fn collect(
        file: tokio::fs::File,
        limit: Option<u64>,
    ) -> Vec<Result<bytes::Bytes, std::io::Error>> {
        reader_stream_with(test_budgets(), file, limit, None)
            .await
            .collect()
            .await
    }

    /// The same, through the unbuffered tier: no permits, so the body streams
    /// `DOWNLOAD_STREAM_SLICE` slices and the chunk sizes say so.
    async fn collect_unbuffered(
        file: tokio::fs::File,
        limit: Option<u64>,
    ) -> Vec<Result<bytes::Bytes, std::io::Error>> {
        let budgets = Budgets {
            blocking: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
            buffered: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
        };
        reader_stream_with(budgets, file, limit, None)
            .await
            .collect()
            .await
    }

    fn total(chunks: &[Result<bytes::Bytes, std::io::Error>]) -> usize {
        chunks.iter().map(|c| c.as_ref().unwrap().len()).sum()
    }

    /// The single-chunk arm: one read, one item, exact bytes.
    #[tokio::test]
    async fn a_body_that_fits_in_one_chunk_is_one_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.bin");
        let size = 4096;
        write_pattern(&path, size);

        let file = tokio::fs::File::open(&path).await.unwrap();
        let chunks = collect(file, Some(size as u64)).await;
        assert_eq!(chunks.len(), 1);
        let chunk = chunks.into_iter().next().unwrap().unwrap();
        assert_eq!(chunk.len(), size);
        assert!(chunk.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
    }

    /// The chunking is the point of `DOWNLOAD_CHUNK` and is invisible to any
    /// content assertion, so pin it: a regression to smaller reads would still
    /// pass every correctness test and only show up as sandbox throughput.
    #[tokio::test]
    async fn a_large_body_reads_in_chunks_and_stops_at_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let size = DOWNLOAD_CHUNK + 4096;
        write_pattern(&path, size);

        // One full chunk plus the tail, in order.
        let file = tokio::fs::File::open(&path).await.unwrap();
        let chunks = collect(file, Some(size as u64)).await;
        let lens: Vec<usize> = chunks.iter().map(|c| c.as_ref().unwrap().len()).collect();
        assert_eq!(lens, vec![DOWNLOAD_CHUNK, 4096]);
        let all: Vec<u8> = chunks
            .into_iter()
            .flat_map(|c| c.unwrap().to_vec())
            .collect();
        assert_eq!(all.len(), size);
        assert!(all.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));

        // A limit inside the first chunk is a single read (206 with a short
        // range).
        let file = tokio::fs::File::open(&path).await.unwrap();
        let limited = collect(file, Some(4096)).await;
        assert_eq!(limited.len(), 1);
        assert_eq!(total(&limited), 4096);

        // A limit crossing the chunk boundary stops exactly at the limit.
        let file = tokio::fs::File::open(&path).await.unwrap();
        let crossed = collect(file, Some(DOWNLOAD_CHUNK as u64 + 10)).await;
        assert_eq!(total(&crossed), DOWNLOAD_CHUNK + 10);

        // An exhausted limit reads nothing at all.
        let file = tokio::fs::File::open(&path).await.unwrap();
        assert!(collect(file, Some(0)).await.is_empty());

        // No limit streams to EOF.
        let file = tokio::fs::File::open(&path).await.unwrap();
        assert_eq!(total(&collect(file, None).await), size);
    }

    /// A read error reaches the body instead of ending the stream silently.
    /// Reading a directory fd fails with EISDIR; the limit forces the
    /// pipelined reader.
    #[tokio::test]
    async fn read_errors_are_delivered() {
        let dir = tempfile::tempdir().unwrap();
        let file = tokio::fs::File::open(dir.path()).await.unwrap();
        let chunks = collect(file, Some(DOWNLOAD_CHUNK as u64 + 1)).await;
        assert_eq!(chunks.len(), 1);
        assert!(chunks.into_iter().next().unwrap().is_err());
    }

    /// The pool is what keeps a 1 MiB chunk from paying an allocation per
    /// read; pin both halves of it (recycle on last drop, and stay bounded).
    #[test]
    fn pooled_buffers_recycle_and_the_pool_stays_bounded() {
        let pool = ReadPool::new(64);
        let bytes = pool.bytes(pool.take(), 8);
        assert_eq!(bytes.len(), 8);
        let live = bytes.clone();
        drop(bytes);
        assert_eq!(
            pool.free.lock().unwrap().len(),
            0,
            "a live slice keeps the buffer out of the pool"
        );
        drop(live);
        assert_eq!(
            pool.free.lock().unwrap().len(),
            1,
            "the last slice recycles the buffer"
        );
        let held: Vec<bytes::Bytes> = (0..(DOWNLOAD_READ_AHEAD + 4))
            .map(|_| pool.bytes(pool.take(), 1))
            .collect();
        drop(held);
        assert_eq!(
            pool.free.lock().unwrap().len(),
            pool.keep,
            "surplus buffers are dropped instead of retained"
        );
    }

    /// The pipeline's only new failure mode: the client goes away mid-body.
    /// Dropping the body drops the receiver, the producer's `send` fails, and
    /// the task must end with every buffer back in the pool. This is also the
    /// property that keeps a stalled download off the shared blocking pool:
    /// the producer parks on the channel, never on a thread.
    #[tokio::test]
    async fn dropping_the_body_stops_the_producer_and_recycles_its_buffers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let size = DOWNLOAD_CHUNK * 4;
        write_pattern(&path, size);

        let file = tokio::fs::File::open(&path).await.unwrap();
        let pool = ReadPool::new(DOWNLOAD_CHUNK);
        let (tx, mut rx) = tokio::sync::mpsc::channel(DOWNLOAD_READ_AHEAD);
        let producer = tokio::spawn(read_ahead(
            file,
            Some(size as u64),
            pool.clone(),
            tx,
            DOWNLOAD_CHUNK,
            BudgetGuard {
                _in_flight: None,
                _blocking: None,
                _buffered: None,
            },
        ));

        // Taking `READ_AHEAD + 1` chunks proves the producer ran and had
        // `READ_AHEAD` more queued or in hand; then the client "disconnects" by
        // dropping the receiver.
        let mut taken = Vec::new();
        for _ in 0..=DOWNLOAD_READ_AHEAD {
            let chunk = rx.recv().await.expect("chunk").unwrap();
            assert_eq!(chunk.len(), DOWNLOAD_CHUNK);
            taken.push(chunk);
        }
        drop(rx);
        tokio::time::timeout(std::time::Duration::from_secs(5), producer)
            .await
            .expect("the producer must stop once the body is dropped")
            .expect("the producer task must not panic");

        drop(taken);
        let free = pool.free.lock().unwrap().len();
        assert!(
            free > DOWNLOAD_READ_AHEAD && free <= pool.keep,
            "every buffer came back and the pool did not grow (free = {free}, keep = {})",
            pool.keep
        );
    }

    /// Both budgets are what keep downloads from consuming the whole pool and
    /// from buffering without bound: a permit is held for the life of a body,
    /// the next body degrades instead of waiting, and the unbuffered tier still
    /// delivers the exact bytes — in smaller slices, which is the observable
    /// difference.
    #[tokio::test]
    async fn the_download_budgets_hold_and_degrade_instead_of_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        // Long enough that a producer fills its channel and parks in `send`,
        // which is the stalled-client shape: a short body would finish and give
        // its permits back on its own.
        let size = DOWNLOAD_CHUNK * (DOWNLOAD_READ_AHEAD + 4);
        write_pattern(&path, size);

        // One blocking slot and two buffered slots.
        let budgets = Budgets {
            blocking: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            buffered: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
        };
        // Not polled on purpose: these bodies stand in for stalled clients, so
        // they keep their permits while they are alive.
        let stalled_blocking = reader_stream_with(
            budgets.clone(),
            tokio::fs::File::open(&path).await.unwrap(),
            Some(size as u64),
            None,
        )
        .await;
        assert_eq!(budgets.blocking.available_permits(), 0);
        assert_eq!(
            budgets.buffered.available_permits(),
            1,
            "tier 1 took one buffered slot"
        );

        // Tier 2: no blocking slot left, but still buffered (1 MiB slices).
        let stalled_async = reader_stream_with(
            budgets.clone(),
            tokio::fs::File::open(&path).await.unwrap(),
            Some(size as u64),
            None,
        )
        .await;
        assert_eq!(budgets.buffered.available_permits(), 0);

        // Tier 3: nothing left, so the body must stream 256 KiB slices without
        // read-ahead and produce the exact bytes.
        let unbuffered = reader_stream_with(
            budgets.clone(),
            tokio::fs::File::open(&path).await.unwrap(),
            Some(size as u64),
            None,
        )
        .await;
        let chunks = unbuffered.collect::<Vec<_>>().await;
        assert_eq!(total(&chunks), size);
        assert!(chunks
            .iter()
            .all(|c| c.as_ref().unwrap().len() <= DOWNLOAD_STREAM_SLICE));
        assert!(chunks[0].as_ref().unwrap().len() <= DOWNLOAD_STREAM_SLICE);
        assert_eq!(
            budgets.blocking.available_permits(),
            0,
            "tier 3 takes no permit"
        );
        assert_eq!(
            budgets.buffered.available_permits(),
            0,
            "tier 3 takes no permit"
        );

        // Ending (or dropping) the stalled bodies gives their permits back, so
        // the next download gets the fast tier again.
        drop(stalled_blocking);
        drop(stalled_async);
        for _ in 0..200 {
            if budgets.blocking.available_permits() == 1
                && budgets.buffered.available_permits() == 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            budgets.blocking.available_permits(),
            1,
            "blocking permit came back"
        );
        assert_eq!(
            budgets.buffered.available_permits(),
            2,
            "buffered permits came back"
        );
    }

    /// The global cap is what keeps a storm of stalled downloads from growing
    /// the daemon's memory with the connection count: a body that is not a
    /// single read holds a slot for its whole life, a small body never takes
    /// one, and a request that misses out is refused instead of queued.
    #[tokio::test]
    async fn the_global_cap_refuses_rather_than_queues_and_small_bodies_are_exempt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let size = DOWNLOAD_CHUNK * (DOWNLOAD_READ_AHEAD + 4);
        write_pattern(&path, size);

        let cap = std::sync::Arc::new(tokio::sync::Semaphore::new(1));

        // A small body is exempt even with the cap fully taken.
        let held = cap.clone().try_acquire_owned().unwrap();
        assert!(matches!(acquire_in_flight(Some(4096), &cap), Ok(None)));
        assert!(matches!(acquire_in_flight(Some(0), &cap), Ok(None)));
        drop(held);
        assert!(matches!(
            acquire_in_flight(Some(size as u64), &cap),
            Ok(Some(_))
        ));

        // A large body gets the last slot...
        let permit = match acquire_in_flight(Some(size as u64), &cap) {
            Ok(Some(permit)) => permit,
            _ => panic!("the last slot should have been available"),
        };
        // ... and the next one is refused, not queued.
        assert!(acquire_in_flight(Some(size as u64), &cap).is_err());
        assert!(
            acquire_in_flight(None, &cap).is_err(),
            "EOF bodies count too"
        );

        // The slot is held for the body's life and comes back with it.
        let body = reader_stream_with(
            test_budgets(),
            tokio::fs::File::open(&path).await.unwrap(),
            Some(size as u64),
            Some(permit),
        )
        .await;
        assert!(
            acquire_in_flight(Some(size as u64), &cap).is_err(),
            "still held"
        );
        assert_eq!(total(&body.collect::<Vec<_>>().await), size);
        for _ in 0..200 {
            if acquire_in_flight(Some(size as u64), &cap).is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the global slot never came back");
    }

    /// The unbuffered tier is only about footprint: the bytes are the same and
    /// the limits are still honoured.
    #[tokio::test]
    async fn the_unbuffered_tier_streams_the_same_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let size = DOWNLOAD_STREAM_SLICE * 4 + 4096;
        write_pattern(&path, size);

        let file = tokio::fs::File::open(&path).await.unwrap();
        let chunks = collect_unbuffered(file, Some(size as u64)).await;
        assert!(
            chunks.len() >= 5,
            "4 slices plus a tail, got {}",
            chunks.len()
        );
        assert!(chunks
            .iter()
            .all(|c| c.as_ref().unwrap().len() <= DOWNLOAD_STREAM_SLICE));
        let all: Vec<u8> = chunks
            .into_iter()
            .flat_map(|c| c.unwrap().to_vec())
            .collect();
        assert_eq!(all.len(), size);
        assert!(all.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));

        // A limit inside the first slice is a single read.
        let file = tokio::fs::File::open(&path).await.unwrap();
        assert_eq!(total(&collect_unbuffered(file, Some(4096)).await), 4096);

        // A body that fits in one chunk never reaches the tiers at all.
        let file = tokio::fs::File::open(&path).await.unwrap();
        let small = collect_unbuffered(file, Some(DOWNLOAD_CHUNK as u64)).await;
        assert_eq!(small.len(), 1);
        assert_eq!(total(&small), DOWNLOAD_CHUNK);
    }
}
