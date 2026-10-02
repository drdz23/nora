// Copyright (c) 2026 The NORA Authors
// SPDX-License-Identifier: MIT

use crate::secrets::ProtectedString;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeanConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream for the elan toolchain proxy (GitHub release archives for
    /// `leanprover/lean4`). `None` disables toolchain proxying — the Lake
    /// cache endpoints (hosted, no upstream) still work.
    #[serde(default = "default_lean_toolchain_proxy")]
    pub toolchain_proxy: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxy_auth: Option<ProtectedString>,
    #[serde(default = "super::super::default_timeout")]
    pub proxy_timeout: u64,
    #[serde(default = "super::go::default_go_zip_timeout")]
    pub proxy_timeout_dl: u64,
    /// Max accepted size (bytes) for a single `lake cache put` artifact.
    #[serde(default = "default_cache_max_size")]
    pub cache_max_size: u64,
}

fn default_lean_toolchain_proxy() -> Option<String> {
    Some("https://github.com/leanprover/lean4/releases/download".to_string())
}

fn default_cache_max_size() -> u64 {
    536_870_912 // 512MB — prebuilt .olean/.ilean archives for a whole package can be large
}

impl Default for LeanConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            toolchain_proxy: default_lean_toolchain_proxy(),
            proxy_auth: None,
            proxy_timeout: 30,
            proxy_timeout_dl: 120,
            cache_max_size: default_cache_max_size(),
        }
    }
}

impl LeanConfig {
    pub(in crate::config) fn apply_env_overrides(&mut self) {
        if let Ok(val) = env::var("NORA_LEAN_ENABLED") {
            self.enabled = val.to_lowercase() == "true" || val == "1";
        }
        if let Ok(val) = env::var("NORA_LEAN_TOOLCHAIN_PROXY") {
            self.toolchain_proxy = if val.is_empty() { None } else { Some(val) };
        }
        if let Ok(val) = env::var("NORA_LEAN_PROXY_AUTH") {
            self.proxy_auth = if val.is_empty() {
                None
            } else {
                Some(ProtectedString::new(val))
            };
        }
        if let Ok(val) = env::var("NORA_LEAN_PROXY_TIMEOUT") {
            super::super::parse_env_warn("NORA_LEAN_PROXY_TIMEOUT", &val, &mut self.proxy_timeout);
        }
        if let Ok(val) = env::var("NORA_LEAN_PROXY_TIMEOUT_DL") {
            super::super::parse_env_warn(
                "NORA_LEAN_PROXY_TIMEOUT_DL",
                &val,
                &mut self.proxy_timeout_dl,
            );
        }
        if let Ok(val) = env::var("NORA_LEAN_CACHE_MAX_SIZE") {
            super::super::parse_env_warn("NORA_LEAN_CACHE_MAX_SIZE", &val, &mut self.cache_max_size);
        }
    }
}
