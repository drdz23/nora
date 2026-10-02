// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

//! Lean toolchain proxy + Lake build-cache registry format.
//!
//! Implements two independent pieces behind one mount point:
//!
//!   1. An elan-compatible toolchain proxy — caches `leanprover/lean4`
//!      release archives (e.g. `v4.28.0`) on first fetch, the same
//!      proxy-fetch-and-cache pattern `conan.rs`/`cargo_registry.rs` use for
//!      immutable, revision-scoped files.
//!   2. A Lake build-cache endpoint compatible with `LAKE_CACHE_ARTIFACT_ENDPOINT`
//!      (Lake 5.0, ships with Lean 4.28): `GET`/`PUT` of content-addressed
//!      `.ltar` artifacts. This side is hosted-only (no upstream) — artifacts
//!      arrive via `lake cache put`, they are never fetched from a third party.
//!
//! ## Endpoints
//!   GET /lean/toolchains/{version}/{filename} — proxy+cache a Lean toolchain archive
//!   GET /lean/cache/{hash}                    — download a cached Lake build artifact
//!   PUT /lean/cache/{hash}                    — publish a Lake build artifact
//!
//! ## Client config
//!   Point elan's toolchain origin at this server (see README for the exact
//!   elan env var NORA expects to be configured with), then:
//!     elan toolchain install leanprover/lean4:v4.28.0
//!   And for the Lake cache:
//!     LAKE_CACHE_ARTIFACT_ENDPOINT=http://nora:4000/lean/cache lake cache get
//!
//! ## Design
//! - Toolchain archives are immutable per (version, filename) — proxied once,
//!   cached forever, mirroring `conan.rs`'s recipe-file download.
//! - Lake cache artifacts are immutable by content hash — hosted only, same
//!   trust model as `raw.rs` uploads but content-addressed like Cargo's
//!   `.crate` tarball (an existing hash short-circuits a re-publish as a no-op
//!   success rather than a conflict, since `lake cache put` legitimately
//!   retries after a partial network failure).
//!
//! ## NOTE on Lake's cache HTTP API
//! `LAKE_CACHE_ARTIFACT_ENDPOINT` is a real Lake 5.0 feature but its exact wire
//! contract is not published as a versioned spec at the time of writing. This
//! implementation follows the same content-addressed GET/PUT-by-hash
//! convention Cargo/Conan use for immutable, revision-scoped files, with a
//! `.ltar` suffix (the extension used informally in community discussion of
//! the feature). If Lake's real format differs — a manifest step, a different
//! hash algorithm, additional headers — only `is_valid_cache_name` and the
//! route pattern below need to change; the caching/curation/audit scaffolding
//! underneath is unaffected.

use crate::activity_log::{ActionType, ActivityEntry};
use crate::audit::AuditEntry;
use crate::auth::{enforce_namespace_scope, NamespaceAuthority};
use crate::registry::{circuit_open_response, proxy_fetch, ProxyError};
use crate::registry_type::RegistryType;
use crate::secrets::expose_opt;
use crate::validation::validate_storage_key;
use crate::AppState;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Router,
};
use std::time::Duration;

const UPSTREAM_DEFAULT: &str = "https://github.com/leanprover/lean4/releases/download";

/// (prefix, suffix) used by `repo_index::build_generic_index` to list cached
/// toolchain archives in the UI. Lake cache blobs are content-addressed, not
/// user-browsable "packages", and are intentionally excluded from the index.
pub const INDEX_PATTERN: (&str, &str) = ("lean/toolchains/", "");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/lean/toolchains/{version}/{filename}",
            get(toolchain_download),
        )
        .route("/lean/cache/{hash}", get(cache_download).put(cache_upload))
}

// ── Toolchain proxy (elan) ────────────────────────────────────────────────

async fn toolchain_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((version, filename)): Path<(String, String)>,
) -> Response {
    if !state.config.lean.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !is_valid_version(&version) || !is_valid_filename(&filename) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let storage_key = format!("lean/toolchains/{}/{}", version, filename);
    let artifact = format!("{}/{}", version, filename);

    // Toolchain releases carry no per-file publish date from the proxy
    // response itself, so fall back to NORA's own cache mtime — same
    // precedent as Raw/Cargo for hosted-or-proxied immutable files.
    let publish_date =
        crate::curation::extract_mtime_as_publish_date(&state.storage, &storage_key).await;

    // #68 namespace isolation: an internal-namespace "version" must never be
    // fetched upstream. There is no real dependency-confusion vector for Lean
    // toolchains (no third party can publish a colliding version string to a
    // public index), but the check is kept for defence-in-depth consistency
    // with every other proxy format.
    let internal = crate::curation::is_internal_namespace(
        &state.curation().curation_engine,
        crate::curation::RegistryType::Lean,
        &version,
    );
    if !internal {
        if let Some(response) = crate::curation::check_download(
            &state.curation().curation_engine,
            state.bypass_token().as_deref(),
            &headers,
            crate::curation::RegistryType::Lean,
            &version,
            None,
            publish_date,
        ) {
            return response;
        }
    }

    // Immutable cache. get_verified discharges the integrity witness at serve
    // (compile-time guarantee — see crate::verified).
    if let Ok(outcome) = state.storage.get_verified(&storage_key).await {
        use nora_registry::verified::{verified_body, GateOutcome};
        let data = match outcome {
            GateOutcome::Verified(blob) => verified_body(blob),
            GateOutcome::Unpinned(blob) => blob.into_inner(),
        };
        if let Some(response) = crate::curation::verify_integrity(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Lean,
            &version,
            None,
            &data,
        ) {
            return response;
        }

        let (q_mode, q_secs) = resolve_lean_quarantine(&state);
        if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
            &state.digest_store,
            "lean",
            &data,
            &q_mode,
            q_secs,
            "cache",
            publish_date,
        ) {
            return resp;
        }

        // Range request: 206 Partial Content, or 416 when the client asks
        // past the end — toolchain archives can be large.
        if let Some(response) = crate::registry::range::range_response(
            &state.storage,
            &[&storage_key],
            &headers,
            data.len() as u64,
            "application/octet-stream",
            &[],
        )
        .await
        {
            if response.status() == StatusCode::PARTIAL_CONTENT {
                state.metrics.record_download("lean");
                state.metrics.record_cache_hit("lean");
            }
            return response;
        }

        state.metrics.record_download("lean");
        state.metrics.record_cache_hit("lean");
        state.activity.push(ActivityEntry::new(
            ActionType::CacheHit,
            artifact,
            RegistryType::Lean,
            "CACHE",
        ));
        return with_binary(data.to_vec());
    }

    // An internal-namespace version with no local copy is never proxied upstream.
    if internal {
        return crate::curation::check_namespace_isolation(
            &state.curation().curation_engine,
            crate::curation::RegistryType::Lean,
            &version,
        )
        .unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
    }

    let proxy_url = upstream_url(&state);
    let url = format!(
        "{}/{}/{}",
        proxy_url.trim_end_matches('/'),
        version,
        filename
    );

    match proxy_fetch(
        &state.http_client,
        &url,
        Duration::from_secs(state.config.lean.proxy_timeout_dl),
        expose_opt(&state.config.lean.proxy_auth),
        &state.circuit_breaker,
        RegistryType::Lean,
    )
    .await
    {
        Ok(bytes) => {
            state.metrics.record_download("lean");
            state.metrics.record_cache_miss("lean");
            state.activity.push(ActivityEntry::new(
                ActionType::ProxyFetch,
                artifact,
                RegistryType::Lean,
                "PROXY",
            ));
            state
                .audit
                .log(AuditEntry::new("proxy_fetch", "proxy", "", "lean", ""));

            // Immutable cache: put_if_absent
            state.spawn_cache_immutable("lean", storage_key, Bytes::from(bytes.clone()));
            let (q_mode, q_secs) = resolve_lean_quarantine(&state);
            if let Some(resp) = crate::digest_quarantine::proxy_gate_dated(
                &state.digest_store,
                "lean",
                &bytes,
                &q_mode,
                q_secs,
                &url,
                publish_date,
            ) {
                return resp;
            }
            with_binary(bytes)
        }
        Err(ProxyError::CircuitOpen(reg)) => circuit_open_response(&reg),
        Err(ProxyError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::debug!(error = ?e, "Lean toolchain download error");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Resolve the effective quarantine mode and TTL for Lean, falling back to
/// the global curation settings when no lean-specific override is configured.
fn resolve_lean_quarantine(state: &AppState) -> (crate::digest_quarantine::QuarantineMode, i64) {
    crate::digest_quarantine::resolve_global(
        state
            .config
            .curation
            .lean
            .quarantine
            .as_ref()
            .or(state.config.curation.quarantine.as_ref()),
        state
            .config
            .curation
            .lean
            .quarantine_ttl
            .as_deref()
            .or(state.config.curation.quarantine_ttl.as_deref()),
    )
}

fn upstream_url(state: &AppState) -> String {
    state
        .config
        .lean
        .toolchain_proxy
        .clone()
        .unwrap_or_else(|| UPSTREAM_DEFAULT.to_string())
}

// ── Lake cache (hosted, content-addressed) ──────────────────────────────

async fn cache_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Response {
    if !state.config.lean.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(hash_only) = is_valid_cache_name(&hash) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let storage_key = format!("lean/cache/{}", hash);
    if validate_storage_key(&storage_key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match state.storage.get_verified(&storage_key).await {
        Ok(outcome) => {
            use nora_registry::verified::{verified_body, GateOutcome};
            let data = match outcome {
                GateOutcome::Verified(blob) => verified_body(blob),
                GateOutcome::Unpinned(blob) => blob.into_inner(),
            };

            if let Some(response) = crate::registry::range::range_response(
                &state.storage,
                &[&storage_key],
                &headers,
                data.len() as u64,
                "application/octet-stream",
                &[],
            )
            .await
            {
                if response.status() == StatusCode::PARTIAL_CONTENT {
                    state.metrics.record_download("lean");
                }
                return response;
            }

            state.metrics.record_download("lean");
            state.activity.push(ActivityEntry::new(
                ActionType::Pull,
                hash_only.to_string(),
                RegistryType::Lean,
                "LOCAL",
            ));
            state
                .audit
                .log(AuditEntry::new("pull", "proxy", "", "lean", ""));
            with_binary(data.to_vec())
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn cache_upload(
    State(state): State<AppState>,
    Extension(authority): Extension<NamespaceAuthority>,
    Path(hash): Path<String>,
    body: Bytes,
) -> Response {
    if !state.config.lean.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(hash_only) = is_valid_cache_name(&hash) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    // Lake cache artifacts have no namespace of their own (keyed by content
    // hash) — scope the check to a fixed coordinate, same pattern as Raw
    // would use for a non-path-shaped upload.
    if enforce_namespace_scope(&authority, "lean/cache").is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }

    if (body.len() as u64) > state.config.lean.cache_max_size {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Lake cache artifact too large. Max size: {} bytes",
                state.config.lean.cache_max_size
            ),
        )
            .into_response();
    }

    let storage_key = format!("lean/cache/{}", hash);
    if validate_storage_key(&storage_key).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Content-addressed immutability: the same hash was already accepted, so
    // treat a re-PUT as an idempotent no-op success rather than a conflict —
    // `lake cache put` legitimately retries after a partial network failure,
    // unlike Cargo where re-publishing a version is a real policy violation.
    let lock = state.publish_lock(&storage_key);
    let _guard = lock.lock().await;
    if state.storage.stat(&storage_key).await.is_some() {
        return StatusCode::OK.into_response();
    }

    if state.storage.put(&storage_key, &body).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state.metrics.record_upload("lean");
    state.activity.push(ActivityEntry::new(
        ActionType::Push,
        hash_only.to_string(),
        RegistryType::Lean,
        "LOCAL",
    ));
    state
        .audit
        .log(AuditEntry::new("push", "local", "", "lean", ""));

    StatusCode::CREATED.into_response()
}

// ── Response helpers ────────────────────────────────────────────────────

fn with_binary(data: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
        ],
        data,
    )
        .into_response()
}

// ── Validation ────────────────────────────────────────────────────────────

/// Validate an elan toolchain version string (e.g. `v4.28.0`, `nightly-2024-09-01`).
fn is_valid_version(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.contains('/')
        && !s.contains('\0')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validate a toolchain archive filename.
fn is_valid_filename(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.contains('/')
        && !name.contains('\0')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '+')
}

/// Validate a Lake cache artifact name, which must be a hex content hash,
/// optionally suffixed `.ltar` (see the module-level NOTE on Lake's cache wire
/// format). Returns the bare hash (without extension) for logging.
fn is_valid_cache_name(name: &str) -> Option<&str> {
    let hash = name.strip_suffix(".ltar").unwrap_or(name);
    if hash.is_empty() || hash.len() < 8 || hash.len() > 128 {
        return None;
    }
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hash)
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_versions() {
        assert!(is_valid_version("v4.28.0"));
        assert!(is_valid_version("nightly-2024-09-01"));
        assert!(is_valid_version("4.28.0-rc2"));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!is_valid_version(""));
        assert!(!is_valid_version("../evil"));
        assert!(!is_valid_version("v4/28"));
        assert!(!is_valid_version("v4\x0028"));
        assert!(!is_valid_version("v4 28"));
    }

    #[test]
    fn test_valid_filenames() {
        assert!(is_valid_filename("lean-4.28.0-linux.tar.zst"));
        assert!(is_valid_filename("lean-4.28.0-darwin-x86_64.tar.gz"));
    }

    #[test]
    fn test_invalid_filenames() {
        assert!(!is_valid_filename(""));
        assert!(!is_valid_filename("../evil.tar.gz"));
        assert!(!is_valid_filename("path/to/file"));
        assert!(!is_valid_filename("file\0name"));
    }

    #[test]
    fn test_valid_cache_names() {
        let hex40 = "a".repeat(40);
        assert_eq!(
            is_valid_cache_name(&format!("{hex40}.ltar")),
            Some(hex40.as_str())
        );
        let hex64 = "f".repeat(64);
        assert_eq!(is_valid_cache_name(&hex64), Some(hex64.as_str()));
    }

    #[test]
    fn test_invalid_cache_names() {
        assert_eq!(is_valid_cache_name(""), None);
        assert_eq!(is_valid_cache_name("short"), None); // < 8 hex chars
        assert_eq!(is_valid_cache_name("not-hex-at-all!!"), None);
        assert_eq!(is_valid_cache_name("../evil.ltar"), None);
        assert_eq!(is_valid_cache_name(&"a".repeat(200)), None);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod integration_tests {
    use crate::test_helpers::{body_bytes, create_test_context_with_config, send};
    use axum::http::{Method, StatusCode};

    #[tokio::test]
    async fn test_lean_disabled_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = false;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/lean/toolchains/v4.28.0/lean-4.28.0-linux.tar.zst",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_lean_cached_toolchain_download() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });

        ctx.state
            .storage
            .put(
                "lean/toolchains/v4.28.0/lean-4.28.0-linux.tar.zst",
                b"fake-toolchain-archive",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/lean/toolchains/v4.28.0/lean-4.28.0-linux.tar.zst",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        assert_eq!(&body[..], b"fake-toolchain-archive");
    }

    #[tokio::test]
    async fn test_lean_toolchain_invalid_version_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/lean/toolchains/../evil/file.tar.gz",
            "",
        )
        .await;
        assert!(resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_lean_toolchain_unreachable_proxy() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
            cfg.lean.toolchain_proxy = Some("http://127.0.0.1:1".to_string());
            cfg.lean.proxy_timeout_dl = 1;
        });
        let resp = send(
            &ctx.app,
            Method::GET,
            "/lean/toolchains/v4.28.0/lean-4.28.0-linux.tar.zst",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_lake_cache_put_then_get() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });

        let hash = "b".repeat(40) + ".ltar";
        let url = format!("/lean/cache/{hash}");

        let put_resp = send(
            &ctx.app,
            Method::PUT,
            &url,
            b"fake-olean-artifact".to_vec(),
        )
        .await;
        assert_eq!(put_resp.status(), StatusCode::CREATED);

        let get_resp = send(&ctx.app, Method::GET, &url, "").await;
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = body_bytes(get_resp).await;
        assert_eq!(&body[..], b"fake-olean-artifact");
    }

    #[tokio::test]
    async fn test_lake_cache_put_idempotent_on_same_hash() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });
        let hash = "c".repeat(40);
        let url = format!("/lean/cache/{hash}");

        for _ in 0..2 {
            let resp = send(&ctx.app, Method::PUT, &url, b"same-bytes".to_vec()).await;
            assert!(resp.status() == StatusCode::CREATED || resp.status() == StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_lake_cache_get_missing_returns_404() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });
        let hash = "d".repeat(40);
        let resp = send(&ctx.app, Method::GET, &format!("/lean/cache/{hash}"), "").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_lake_cache_invalid_hash_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
        });
        let resp = send(&ctx.app, Method::GET, "/lean/cache/not-a-hash!!", "").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_lake_cache_oversized_put_rejected() {
        let ctx = create_test_context_with_config(|cfg| {
            cfg.lean.enabled = true;
            cfg.lean.cache_max_size = 4;
        });
        let hash = "e".repeat(40);
        let resp = send(
            &ctx.app,
            Method::PUT,
            &format!("/lean/cache/{hash}"),
            b"too-big-for-the-limit".to_vec(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_lean_curation_enforce_blocks_toolchain() {
        let blocklist_dir = tempfile::TempDir::new().unwrap();
        let blocklist_path = blocklist_dir.path().join("blocklist.json");
        let blocklist = serde_json::json!({
            "version": 1,
            "rules": [{"registry": "lean", "name": "v4.0.0-broken", "version": "*", "reason": "known-bad toolchain"}]
        });
        std::fs::write(&blocklist_path, serde_json::to_string(&blocklist).unwrap()).unwrap();

        let bl_path = blocklist_path.to_str().unwrap().to_string();
        let ctx = create_test_context_with_config(move |cfg| {
            cfg.lean.enabled = true;
            cfg.curation.mode = crate::config::CurationMode::Enforce;
            cfg.curation.blocklist_path = Some(bl_path);
        });

        ctx.state
            .storage
            .put(
                "lean/toolchains/v4.0.0-broken/lean-linux.tar.zst",
                b"evil",
            )
            .await
            .unwrap();

        let resp = send(
            &ctx.app,
            Method::GET,
            "/lean/toolchains/v4.0.0-broken/lean-linux.tar.zst",
            "",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
