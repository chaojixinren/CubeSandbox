// Copyright (c) 2026 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

//! GET/POST /files — download and upload.
//!
//! Baseline contract:
//! - user resolution: `username` query > Basic auth > root;
//! - relative paths anchor at the user's home;
//! - download errors: 400 (directory / missing path param), 401 (bad user),
//!   404 (missing file), body `{"code":<int>,"message":"..."}`;
//! - upload: multipart (part filename = target path) or raw octet-stream
//!   (`path` query required); parents are created; the file is chowned to
//!   the requesting user; response is `[{"name","path","type":"file"}]`;
//! - gzip response encoding is NOT implemented (declared difference —
//!   identity responses are valid HTTP for any Accept-Encoding).

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

use crate::auth::{self, User};
use crate::error::RestError;
use crate::rest::{content_disposition, encoding, httpdate, preconditions, ranges};
use crate::state::AppState;

fn resolve_request_user(
    state: &AppState,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
) -> Result<User, RestError> {
    let name = params
        .get("username")
        .cloned()
        .or_else(|| {
            auth::user_from_basic_auth(
                headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok()),
            )
        })
        // Upstream falls back to `defaults.User` (root until /init overrides it).
        .unwrap_or_else(|| state.default_user());
    auth::lookup_user(&name).map_err(|msg| RestError::new(StatusCode::UNAUTHORIZED, msg))
}

fn check_token_rest(state: &AppState, headers: &HeaderMap) -> Result<(), RestError> {
    super::check_token(state, headers)
        .map_err(|_| RestError::new(StatusCode::UNAUTHORIZED, "invalid access token".to_string()))
}

/// GET /files — stream a file back with upstream `http.ServeContent`
/// semantics: Last-Modified, conditional requests (If-Match / If-Unmodified-
/// Since / If-None-Match / If-Modified-Since / If-Range → 304/412), Range
/// (single range → 206, unsatisfiable → 416), Accept-Ranges, and the two 406
/// Accept-Encoding exits — in upstream download.go's exact order (see
/// docs/cube-envd/item-1.3-implementation-plan.md §2).
pub async fn download(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if let Err(e) = check_token_rest(&state, &headers) {
        return e.into_response();
    }
    let user = match resolve_request_user(&state, &params, &headers) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
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
        .or_else(|| state.default_workdir())
        .unwrap_or_else(|| user.home.clone());
    let path = auth::resolve_path(&raw_path, &user);

    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return RestError::new(
                StatusCode::NOT_FOUND,
                format!("path '{path}' does not exist"),
            )
            .into_response();
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': permission denied"),
            )
            .into_response();
        }
        Err(e) => {
            return RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("error opening file '{path}': {e}"),
            )
            .into_response();
        }
    };
    if meta.is_dir() {
        return RestError::new(
            StatusCode::BAD_REQUEST,
            format!("path '{path}' is a directory"),
        )
        .into_response();
    }

    // Accept-Encoding, then Vary, then the Range/conditional identity gate —
    // upstream's order (download.go): the first 406 answers BEFORE Vary is
    // set; the second one carries Vary. nginx's `add_header Vary` has no
    // `always`, so error responses must carry it themselves when upstream
    // does.
    let ae = header_str(&headers, axum::http::header::ACCEPT_ENCODING).unwrap_or("");
    if encoding::parse_accept_encoding(ae).is_err() {
        return RestError::new(
            StatusCode::NOT_ACCEPTABLE,
            "error parsing Accept-Encoding: no acceptable encoding found, supported: [gzip]",
        )
        .into_response();
    }
    // cube-envd serves identity only (declared difference D1); the parsed
    // best encoding is deliberately unused, but the rejection above must stay.
    let has_range_or_conditional = [
        axum::http::header::RANGE,
        axum::http::header::IF_MODIFIED_SINCE,
        axum::http::header::IF_NONE_MATCH,
        axum::http::header::IF_RANGE,
    ]
    .iter()
    .any(|h| {
        header_str(&headers, h.clone())
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    });
    if has_range_or_conditional && !encoding::is_identity_acceptable(ae) {
        // This 406 answers AFTER Vary was set, so it must carry Vary itself
        // (nginx's `add_header Vary` has no `always`; upstream sets the
        // header on the writer before this exit). Body shape matches
        // RestError / upstream jsonError.
        let body = serde_json::json!({
            "code": 406,
            "message": "identity encoding not acceptable for Range or conditional request",
        })
        .to_string();
        return axum::response::Response::builder()
            .status(StatusCode::NOT_ACCEPTABLE)
            .header(axum::http::header::VARY, "Accept-Encoding")
            .header(
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(axum::body::Body::from(body))
            .expect("build 406 response");
    }

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

    // Preset headers (upstream sets Content-Disposition before
    // http.ServeContent, which then adds Last-Modified from the stat mtime).
    // Vary, Content-Disposition and Last-Modified survive 304/412; 416
    // deletes Last-Modified (fs.go serveError). Content-Type / Content-Length
    // are only added on 200/206.
    let disposition = content_disposition::format_content_disposition(
        std::path::Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download"),
    );
    // Go `isZeroTime`: epoch/zero mtimes mean "no time" → no Last-Modified
    // and the date-based conditions do not apply. The mtime is already
    // second-truncated (`as_secs`), like Go's Truncate(time.Second).
    let modtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .filter(|secs| *secs != 0);
    let preset: Vec<(axum::http::HeaderName, String)> = {
        let mut v = Vec::with_capacity(4);
        v.push((axum::http::header::VARY, "Accept-Encoding".to_string()));
        v.push((axum::http::header::CONTENT_DISPOSITION, disposition));
        if let Some(mt) = modtime {
            v.push((
                axum::http::header::LAST_MODIFIED,
                httpdate::format_http_date(mt),
            ));
        }
        v
    };
    // 416 keeps Vary + Content-Disposition but drops Last-Modified.
    let preset_no_last_modified: Vec<_> = preset
        .iter()
        .filter(|(k, _)| *k != axum::http::header::LAST_MODIFIED)
        .cloned()
        .collect();
    let apply_preset = |mut b: axum::http::response::Builder,
                        headers: &[(axum::http::HeaderName, String)]|
     -> axum::http::response::Builder {
        for (k, v) in headers {
            b = b.header(k.clone(), v.clone());
        }
        b
    };
    let empty = |code: StatusCode,
                 headers: &[(axum::http::HeaderName, String)]|
     -> axum::response::Response {
        apply_preset(axum::response::Response::builder().status(code), headers)
            .body(axum::body::Body::empty())
            .expect("build error response")
    };

    // Conditional requests (fs.go checkPreconditions) run before the
    // Content-Type probe — so 304/412 carry no Content-Type, exactly like
    // upstream.
    match preconditions::check_preconditions(
        header_str(&headers, axum::http::header::IF_MATCH),
        header_str(&headers, axum::http::header::IF_UNMODIFIED_SINCE),
        header_str(&headers, axum::http::header::IF_NONE_MATCH),
        header_str(&headers, axum::http::header::IF_MODIFIED_SINCE),
        modtime,
    ) {
        preconditions::CondOutcome::NotModified => {
            // fs.go writeNotModified: strips Content-Type/Content-Length/
            // Content-Encoding (none set yet here) and keeps Last-Modified
            // (no ETag).
            return empty(StatusCode::NOT_MODIFIED, &preset);
        }
        preconditions::CondOutcome::PreconditionFailed => {
            // fs.go: bare 412, no body, no Content-Type.
            return empty(StatusCode::PRECONDITION_FAILED, &preset);
        }
        preconditions::CondOutcome::Serve => {}
    }

    // Baseline serves downloads through Go's content sniffer; approximate it
    // with a text/binary split, which covers what SDK users observe. The
    // full DetectContentType table is a declared non-goal.
    let content_type = match sniff_content_type(&mut file).await {
        Ok(ct) => ct,
        Err(_) => {
            // Rewind failed (non-seekable special file): reopen so the body
            // still starts at byte 0 instead of after the sniffed prefix.
            match tokio::fs::File::open(&path).await {
                Ok(f) => {
                    file = f;
                    "application/octet-stream"
                }
                Err(e) => {
                    return RestError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("error opening file '{path}': {e}"),
                    )
                    .into_response();
                }
            }
        }
    };

    let size = meta.len();
    // Range (fs.go parseRange, then serveContent's dispatch): an If-Range
    // that fails drops the Range header (full 200). Multi-range requests are
    // served as a plain 200 (declared difference D3 — upstream's multipart
    // path is unused by any SDK).
    let range_hdr = header_str(&headers, axum::http::header::RANGE);
    let range_kept = range_hdr.is_some_and(|_| {
        preconditions::if_range_keeps_range(
            header_str(&headers, axum::http::header::IF_RANGE),
            modtime,
        )
    });
    let ranges = if range_kept {
        ranges::parse_range(range_hdr, size as i64)
    } else {
        Ok(None)
    };
    let single = match ranges {
        Ok(ranges) => {
            // Some(vec) with >1 entries → multi-range → ignored (D3).
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
            // fs.go serveError(416): strips Cache-Control/Content-Encoding/
            // ETag/Last-Modified, then http.Error — text/plain body, nosniff.
            let cr = match e {
                ranges::RangeError::NoOverlap => Some(format!("bytes */{size}")),
                ranges::RangeError::Invalid => None,
            };
            let mut b =
                axum::response::Response::builder().status(StatusCode::RANGE_NOT_SATISFIABLE);
            b = apply_preset(b, &preset_no_last_modified);
            if let Some(cr) = cr {
                b = b.header(axum::http::header::CONTENT_RANGE, cr);
            }
            let body = format!("{}\n", e.message());
            return b
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )
                .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
                .header(axum::http::header::CONTENT_LENGTH, body.len())
                .body(axum::body::Body::from(body))
                .expect("build 416 response");
        }
    };

    // Seek for a single range, mirroring fs.go before it emits the 206.
    let (code, stream_limit) = match single {
        Some(r) => {
            use tokio::io::AsyncSeekExt;
            if let Err(e) = file.seek(std::io::SeekFrom::Start(r.start as u64)).await {
                // fs.go serveError with the seek error on a 416.
                let body = format!("{e}\n");
                return apply_preset(
                    axum::response::Response::builder().status(StatusCode::RANGE_NOT_SATISFIABLE),
                    &preset_no_last_modified,
                )
                .header(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )
                .header(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
                .header(axum::http::header::CONTENT_LENGTH, body.len())
                .body(axum::body::Body::from(body))
                .expect("build seek-error response");
            }
            (StatusCode::PARTIAL_CONTENT, Some(r.length as u64))
        }
        None => (StatusCode::OK, None),
    };

    // Common success headers: Content-Type always; Content-Range only on
    // 206; Accept-Ranges always; Content-Length for 206 and for 200 when the
    // stat size is positive.
    let mut b = axum::response::Response::builder().status(code);
    b = apply_preset(b, &preset);
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
        // stat-size-0 but readable files (/proc/*, some sysfs) would get a
        // Content-Length: 0 header that truncates the real body — stream
        // those chunked instead. Regular files keep the explicit length
        // (baseline sends one).
        None if size == 0 => None,
        None => Some(size),
    };
    if let Some(len) = body_len {
        b = b.header(axum::http::header::CONTENT_LENGTH, len);
    }
    let stream = reader_stream(file, stream_limit);
    b.body(axum::body::Body::from_stream(stream))
        .expect("build download response")
}

fn header_str(headers: &HeaderMap, name: axum::http::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
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

/// Chunked reader stream (64 KiB) without pulling in tokio-util. `limit`
/// bounds the total bytes produced (single-range 206 bodies); `None` streams
/// to EOF.
fn reader_stream(
    file: tokio::fs::File,
    limit: Option<u64>,
) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send {
    use tokio::io::AsyncReadExt;
    futures::stream::unfold((file, limit), |(mut file, mut remaining)| async move {
        let want = match remaining {
            Some(0) => return None,
            Some(r) => r.min(64 * 1024) as usize,
            None => 64 * 1024,
        };
        let mut buf = vec![0u8; want];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                if let Some(r) = remaining.as_mut() {
                    *r -= n as u64;
                }
                Some((Ok(bytes::Bytes::from(buf)), (file, remaining)))
            }
            Err(e) => Some((Err(e), (file, remaining))),
        }
    })
}

/// POST /files — multipart or raw octet-stream upload.
pub async fn upload(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> axum::response::Response {
    if let Err(e) = check_token_rest(&state, &headers) {
        return e.into_response();
    }
    let user = match resolve_request_user(&state, &params, &headers) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };

    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let result = if content_type.starts_with("multipart/form-data") {
        upload_multipart(&content_type, body, &user).await
    } else {
        upload_raw(body, &params, &user).await
    };

    match result {
        // Baseline quirk: upstream writes the JSON array without an explicit
        // content type, so Go's sniffer labels it text/plain.
        Ok(entries) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string()),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

#[derive(serde::Serialize)]
struct UploadEntry {
    name: String,
    path: String,
    #[serde(rename = "type")]
    entry_type: &'static str,
}

async fn upload_raw(
    body: axum::body::Body,
    params: &HashMap<String, String>,
    user: &User,
) -> Result<Vec<UploadEntry>, RestError> {
    let Some(raw_path) = params.get("path") else {
        return Err(RestError::new(
            StatusCode::BAD_REQUEST,
            "the 'path' query parameter is required for application/octet-stream uploads",
        ));
    };
    let path = auth::resolve_path(raw_path, user);
    let data = axum::body::to_bytes(body, crate::connect::MAX_ENVELOPE_SIZE)
        .await
        .map_err(|e| {
            // A body over the cap must report 413 like the multipart path
            // (and the documented contract), not a generic 400.
            let msg = e.to_string();
            if msg.contains("length limit") {
                RestError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "the upload exceeds the {}-byte limit",
                        crate::connect::MAX_ENVELOPE_SIZE
                    ),
                )
            } else {
                RestError::new(
                    StatusCode::BAD_REQUEST,
                    format!("error reading body: {msg}"),
                )
            }
        })?;
    let user_owned = user.clone();
    let path_owned = path.clone();
    // Disk writes (up to 64 MiB + fsync) must not block the small tokio
    // worker pool — a stalled worker would also stall /health.
    tokio::task::spawn_blocking(move || write_file(&path_owned, &data, &user_owned))
        .await
        .map_err(|e| {
            RestError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("write task: {e}"),
            )
        })??;
    Ok(vec![entry_for(&path)])
}

/// RFC 2045-style parameter extraction for the multipart boundary: handles
/// a quoted boundary (semicolons allowed inside the quotes) and trailing
/// parameters after it (`; charset=...`), not just `boundary=` at the end.
fn parse_boundary(content_type: &str) -> Option<String> {
    let after = content_type.split("boundary=").nth(1)?;
    if let Some(rest) = after.strip_prefix('"') {
        rest.split('"').next().map(|s| s.to_string())
    } else {
        Some(after.split(';').next().unwrap_or(after).trim().to_string())
    }
    .filter(|b| !b.is_empty())
}

async fn upload_multipart(
    content_type: &str,
    body: axum::body::Body,
    user: &User,
) -> Result<Vec<UploadEntry>, RestError> {
    let boundary = parse_boundary(content_type)
        .ok_or_else(|| RestError::new(StatusCode::BAD_REQUEST, "missing multipart boundary"))?;

    let stream = body.into_data_stream();
    // Bound the whole multipart payload so an unbounded upload cannot OOM the
    // daemon. Matches the cap the raw octet-stream path already enforces
    // (upload_raw uses MAX_ENVELOPE_SIZE); without this, multer defaults to
    // unlimited and bypasses axum's DefaultBodyLimit on a streamed body.
    let constraints = multer::Constraints::new().size_limit(
        multer::SizeLimit::new()
            .whole_stream(crate::connect::MAX_ENVELOPE_SIZE as u64)
            .per_field(crate::connect::MAX_ENVELOPE_SIZE as u64),
    );
    let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);

    let mut entries = Vec::new();
    while let Some(field) = multipart.next_field().await.map_err(map_multipart_error)? {
        // Only parts carrying a filename are file uploads (part filename =
        // target path, matching upstream). A plain form field must not fall
        // back to the `?path` query target — that would let a stray text
        // field overwrite the real file's bytes. The `?path` fallback
        // belongs to the raw octet-stream path only.
        let Some(target) = field.file_name().map(|s| s.to_string()) else {
            continue;
        };
        let path = auth::resolve_path(&target, user);
        let data = field.bytes().await.map_err(map_multipart_error)?;
        let user_owned = user.clone();
        let path_owned = path.clone();
        // Same reasoning as upload_raw: keep big writes off the async workers.
        tokio::task::spawn_blocking(move || write_file(&path_owned, &data, &user_owned))
            .await
            .map_err(|e| {
                RestError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("write task: {e}"),
                )
            })??;
        entries.push(entry_for(&path));
    }
    if entries.is_empty() {
        return Err(RestError::new(
            StatusCode::BAD_REQUEST,
            "multipart upload contained no file",
        ));
    }
    Ok(entries)
}

/// Map a multer error, reporting a size-limit breach as 413 (the upload was
/// refused for being too large) and any other parse failure as 400.
fn map_multipart_error(e: multer::Error) -> RestError {
    if matches!(
        e,
        multer::Error::StreamSizeExceeded { .. } | multer::Error::FieldSizeExceeded { .. }
    ) {
        RestError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "multipart upload exceeds the {}-byte limit",
                crate::connect::MAX_ENVELOPE_SIZE
            ),
        )
    } else {
        RestError::new(
            StatusCode::BAD_REQUEST,
            format!("error reading multipart: {e}"),
        )
    }
}

fn entry_for(path: &str) -> UploadEntry {
    let name = std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string());
    UploadEntry {
        name,
        path: path.to_string(),
        entry_type: "file",
    }
}

/// Create parents (owned by the user), write via temp file + rename, chown.
/// Overwriting an existing file preserves its mode bits (upstream envd writes
/// in place with O_TRUNC, which never touches the mode; the temp-file path
/// must copy it explicitly or an executable script would lose its x bits).
fn write_file(path: &str, data: &[u8], user: &User) -> Result<(), RestError> {
    let target = std::path::Path::new(path);
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            create_dirs_owned(parent, user)?;
        }
    }
    // lstat, not stat: if the target is a symlink we replace the link itself,
    // so the mode to preserve is the link entry's, never the followed target's.
    let existing_mode = std::fs::symlink_metadata(target)
        .ok()
        .filter(|m| m.is_file())
        .map(|m| m.permissions().mode());

    let dir = target.parent().unwrap_or(std::path::Path::new("/"));
    let tmp_path = dir.join(format!(
        ".cube-envd-upload-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let write_result = (|| -> std::io::Result<()> {
        // create_new (O_EXCL): never follow or reuse a pre-planted path at
        // the (predictable) temp name.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        f.write_all(data)?;
        if let Some(mode) = existing_mode {
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(map_write_error(path, &e));
    }
    chown(&tmp_path, user);
    if let Err(e) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(map_write_error(path, &e));
    }
    Ok(())
}

fn create_dirs_owned(dir: &std::path::Path, user: &User) -> Result<(), RestError> {
    // Find the deepest existing ancestor, then create and chown below it.
    let mut missing = Vec::new();
    let mut cursor = dir.to_path_buf();
    while !cursor.exists() {
        missing.push(cursor.clone());
        match cursor.parent() {
            Some(p) => cursor = p.to_path_buf(),
            None => break,
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| map_write_error(&dir.to_string_lossy(), &e))?;
    for created in missing.iter().rev() {
        chown(created, user);
    }
    Ok(())
}

fn chown(path: &std::path::Path, user: &User) {
    if let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        unsafe {
            // lchown, not chown: never follow a symlink when setting ownership,
            // so a planted symlink at `path` cannot redirect the chown onto an
            // arbitrary target the caller shouldn't be able to take over.
            libc::lchown(c_path.as_ptr(), user.uid, user.gid);
        }
    }
}

fn map_write_error(path: &str, e: &std::io::Error) -> RestError {
    if e.raw_os_error() == Some(libc::ENOSPC) {
        RestError::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "not enough disk space available",
        )
    } else if e.kind() == std::io::ErrorKind::PermissionDenied {
        RestError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("error writing file '{path}': permission denied"),
        )
    } else {
        RestError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("error writing file '{path}': {e}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user(home: &str) -> User {
        User {
            name: "test".into(),
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            home: home.into(),
            groups: vec![],
        }
    }

    #[test]
    fn write_file_creates_parents_and_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user(dir.path().to_str().unwrap());
        let target = dir.path().join("a/b/c.txt");
        write_file(target.to_str().unwrap(), b"hello", &user).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        // Overwrite works and leaves no temp files behind.
        write_file(target.to_str().unwrap(), b"world", &user).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"world");
        let leftovers: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".cube-envd-upload")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn overwrite_preserves_mode_bits() {
        let dir = tempfile::tempdir().unwrap();
        let user = test_user(dir.path().to_str().unwrap());
        let target = dir.path().join("script.sh");
        write_file(target.to_str().unwrap(), b"#!/bin/sh\n", &user).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Overwriting through the temp-file+rename path must keep 0755.
        write_file(target.to_str().unwrap(), b"#!/bin/sh\necho v2\n", &user).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o755);
        // A fresh file still gets default create permissions.
        let fresh = dir.path().join("plain.txt");
        write_file(fresh.to_str().unwrap(), b"x", &user).unwrap();
        assert!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o111 == 0);
    }

    #[test]
    fn boundary_parsing_variants() {
        assert_eq!(
            parse_boundary("multipart/form-data; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            parse_boundary("multipart/form-data; boundary=abc; charset=utf-8").as_deref(),
            Some("abc")
        );
        assert_eq!(
            parse_boundary(r#"multipart/form-data; boundary="quo;ted"; charset=utf-8"#).as_deref(),
            Some("quo;ted")
        );
        assert_eq!(parse_boundary("multipart/form-data"), None);
        assert_eq!(parse_boundary("multipart/form-data; boundary="), None);
    }

    #[test]
    fn upload_entry_shape() {
        let e = entry_for("/home/user/hello.txt");
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"name":"hello.txt","path":"/home/user/hello.txt","type":"file"})
        );
    }
}

#[cfg(test)]
mod download_tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::extract::Query;
    use axum::http::header;
    use std::collections::HashMap;

    /// Drive the real GET /files handler against a tempdir file. The default
    /// user is root (present in /etc/passwd everywhere this suite runs); an
    /// absolute `path` query bypasses home anchoring. AppState has no access
    /// token set, so the token gate passes.
    async fn get(path: &str, extra: &[(&str, &str)]) -> axum::response::Response {
        let state = State(std::sync::Arc::new(AppState::new()));
        let mut params = HashMap::new();
        params.insert("path".to_string(), path.to_string());
        let mut headers = HeaderMap::new();
        for (k, v) in extra {
            headers.insert(k.parse::<header::HeaderName>().unwrap(), v.parse().unwrap());
        }
        download(state, Query(params), headers).await
    }

    async fn body(
        resp: axum::response::Response,
    ) -> (axum::http::StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let (parts, b) = resp.into_parts();
        let bytes = to_bytes(b, 1 << 20).await.unwrap();
        (parts.status, parts.headers, bytes.to_vec())
    }

    /// 406 responses use the REST error shape (JSON code+message, like
    /// upstream jsonError) — the human message rides inside `message`.
    fn json_message(body: &[u8]) -> String {
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        v["message"].as_str().unwrap().to_string()
    }

    fn tmp_file(name: &str, content: &[u8]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        std::fs::write(&p, content).unwrap();
        (dir, p.to_str().unwrap().to_string())
    }

    #[tokio::test]
    async fn plain_get_has_negotiation_headers() {
        let (_d, p) = tmp_file("base_a.txt", b"hello-octet\n");
        let resp = get(&p, &[]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert_eq!(&b[..], b"hello-octet\n");
        assert_eq!(h[header::VARY], "Accept-Encoding");
        assert_eq!(h[header::ACCEPT_RANGES], "bytes");
        assert_eq!(h[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(h[header::CONTENT_LENGTH], "12");
        assert!(h.contains_key(header::LAST_MODIFIED)); // mtime is present
        assert_eq!(
            h[header::CONTENT_DISPOSITION],
            "inline; filename=base_a.txt"
        );
    }

    #[tokio::test]
    async fn range_returns_206_slice() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        let resp = get(&p, &[("Range", "bytes=2-5")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 206);
        assert_eq!(&b[..], b"2345");
        assert_eq!(h[header::CONTENT_RANGE], "bytes 2-5/10");
        assert_eq!(h[header::CONTENT_LENGTH], "4");
        assert_eq!(h[header::ACCEPT_RANGES], "bytes");
    }

    #[tokio::test]
    async fn range_open_ended_and_suffix() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        let resp = get(&p, &[("Range", "bytes=7-")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 206);
        assert_eq!(&b[..], b"789");
        assert_eq!(h[header::CONTENT_RANGE], "bytes 7-9/10");

        let resp = get(&p, &[("Range", "bytes=-3")]).await;
        let (_s, h, b) = body(resp).await;
        assert_eq!(&b[..], b"789");
        assert_eq!(h[header::CONTENT_RANGE], "bytes 7-9/10");
    }

    #[tokio::test]
    async fn if_modified_since_roundtrip_304() {
        let (_d, p) = tmp_file("c.txt", b"cache-me");
        let resp = get(&p, &[]).await;
        let (_s, h, _b) = body(resp).await;
        let lm = h[header::LAST_MODIFIED].to_str().unwrap().to_string();

        // Same Last-Modified → not modified.
        let resp = get(&p, &[("If-Modified-Since", &lm)]).await;
        let (status, h304, b) = body(resp).await;
        assert_eq!(status, 304);
        assert!(b.is_empty());
        assert_eq!(h304[header::LAST_MODIFIED], lm); // kept on 304
        assert_eq!(h304[header::VARY], "Accept-Encoding"); // preset survives
        assert!(!h304.contains_key(header::CONTENT_TYPE)); // none on 304
        assert!(!h304.contains_key(header::CONTENT_LENGTH));

        // Stale IMS (before the file's mtime) → full 200.
        let resp = get(
            &p,
            &[("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")],
        )
        .await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert_eq!(&b[..], b"cache-me");
    }

    #[tokio::test]
    async fn if_none_match_concrete_etag_serves_full_200() {
        // No ETag on the representation: a concrete If-None-Match never
        // matches → 200 full body, and If-Modified-Since is skipped (the
        // client's "changed" signal wins) — fs.go condTrue semantics.
        let (_d, p) = tmp_file("c.txt", b"etag-test");
        let resp = get(
            &p,
            &[
                ("If-None-Match", "\"deadbeef\""),
                ("If-Modified-Since", "Thu, 01 Jan 2099 00:00:00 GMT"),
            ],
        )
        .await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert_eq!(&b[..], b"etag-test");
    }

    #[tokio::test]
    async fn if_none_match_star_is_304() {
        let (_d, p) = tmp_file("c.txt", b"etag-test");
        let resp = get(&p, &[("If-None-Match", "*")]).await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 304);
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn empty_conditional_headers_are_absent_like_go() {
        // Go reads conditional headers with Header.Get, so a present-but-
        // empty header is the same as a missing one. Empty If-Match must not
        // 412 (a concrete etag would); empty If-None-Match must not
        // short-circuit If-Modified-Since.
        let (_d, p) = tmp_file("e.txt", b"0123456789");
        let (status, _h, _b) = body(get(&p, &[("If-Match", "")]).await).await;
        assert_eq!(status, 200);
        let lm = body(get(&p, &[]).await).await;
        let last_modified = lm.1[header::LAST_MODIFIED].to_str().unwrap().to_string();
        let resp = get(
            &p,
            &[("If-None-Match", ""), ("If-Modified-Since", &last_modified)],
        )
        .await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 304);
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn range_no_overlap_416_shape() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        let resp = get(&p, &[("Range", "bytes=100-")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 416);
        assert_eq!(&b[..], b"invalid range: failed to overlap\n");
        assert_eq!(h[header::CONTENT_RANGE], "bytes */10");
        assert_eq!(h[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        // fs.go serveError strips Last-Modified from the 416 header set.
        assert!(!h.contains_key(header::LAST_MODIFIED));
        // Vary + Content-Disposition survive.
        assert_eq!(h[header::VARY], "Accept-Encoding");
        assert!(h.contains_key(header::CONTENT_DISPOSITION));
    }

    #[tokio::test]
    async fn range_bad_syntax_416_without_content_range() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        let resp = get(&p, &[("Range", "bytes=abc")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 416);
        assert_eq!(&b[..], b"invalid range\n");
        assert!(!h.contains_key(header::CONTENT_RANGE));
    }

    #[tokio::test]
    async fn range_on_empty_file_ignored_200() {
        let (_d, p) = tmp_file("empty.bin", b"");
        // errNoOverlap + size == 0 → ignore Range, answer 200 (fs.go).
        let resp = get(&p, &[("Range", "bytes=0-")]).await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert!(b.is_empty());
    }

    #[tokio::test]
    async fn if_match_concrete_fails_412() {
        let (_d, p) = tmp_file("c.txt", b"412-body");
        let resp = get(&p, &[("If-Match", "\"etag\"")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 412);
        assert!(b.is_empty());
        assert!(!h.contains_key(header::CONTENT_TYPE));
        assert_eq!(h[header::VARY], "Accept-Encoding");
        // 412 keeps Last-Modified (bare WriteHeader, no serveError).
        assert!(h.contains_key(header::LAST_MODIFIED));
    }

    #[tokio::test]
    async fn range_with_identity_rejected_is_406_with_vary() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        // `identity;q=0, gzip` parses fine (gzip acceptable) but rejects
        // identity → the Range/conditional gate's 406b, which carries Vary
        // (it answers after Vary was set).
        let resp = get(
            &p,
            &[
                ("Range", "bytes=0-1"),
                ("Accept-Encoding", "identity;q=0, gzip"),
            ],
        )
        .await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 406);
        assert_eq!(
            json_message(&b),
            "identity encoding not acceptable for Range or conditional request"
        );
        assert_eq!(h[header::VARY], "Accept-Encoding");
    }

    #[tokio::test]
    async fn multi_range_served_as_full_200() {
        // Declared difference D3: no multipart; a multi-range request gets
        // the whole file.
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        let resp = get(&p, &[("Range", "bytes=0-1, 5-6")]).await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert_eq!(&b[..], b"0123456789");
    }

    #[tokio::test]
    async fn if_range_mismatched_etag_drops_range() {
        let (_d, p) = tmp_file("r.bin", b"0123456789");
        // If-Range with an etag never matches (no current etag) → Range is
        // dropped and the whole file is served.
        let resp = get(&p, &[("Range", "bytes=0-1"), ("If-Range", "\"old-etag\"")]).await;
        let (status, _h, b) = body(resp).await;
        assert_eq!(status, 200);
        assert_eq!(&b[..], b"0123456789");
    }

    #[tokio::test]
    async fn gzip_rejected_406_before_vary() {
        let (_d, p) = tmp_file("g.txt", b"x");
        // *;q=0 without an identity entry rejects everything → 406 answers
        // BEFORE Vary is set (upstream order).
        let resp = get(&p, &[("Accept-Encoding", "*;q=0")]).await;
        let (status, h, b) = body(resp).await;
        assert_eq!(status, 406);
        assert_eq!(
            json_message(&b),
            "error parsing Accept-Encoding: no acceptable encoding found, supported: [gzip]"
        );
        assert!(!h.contains_key(header::VARY));
    }
}
