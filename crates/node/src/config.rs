//! Node configuration file (`/etc/tunnix-node/config.json`).
//!
//! Field names follow v2node's `config.json` so an existing v2node install can be
//! migrated by copying the file and adding `PanelType`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/tunnix-node/config.json";
pub const DEFAULT_DATA_DIR: &str = "/var/lib/tunnix-node";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub nodes: Vec<NodeConfig>,
    /// Where generated core configs and certificates are written.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Contact e-mail for ACME (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_email: Option<String>,
    /// Remnawave node mode (panel pushes config over mTLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remnawave: Option<crate::rw::RemnawaveConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct LogConfig {
    #[serde(default = "default_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PanelType {
    /// wyx2685/v2board (the panel v2node targets).
    #[default]
    #[serde(alias = "v2node", alias = "wyx2685")]
    Xiaoboard,
    /// cedar2025/Xboard.
    Xboard,
    /// Original v2board/v2board 1.7.x (vmess, trojan, shadowsocks only).
    V2board,
}

impl std::fmt::Display for PanelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Xiaoboard => "xiaoboard",
            Self::Xboard => "xboard",
            Self::V2board => "v2board",
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    #[serde(rename = "PanelType", default)]
    pub panel_type: PanelType,
    #[serde(rename = "ApiHost")]
    pub api_host: String,
    #[serde(rename = "NodeID", alias = "NodeId")]
    pub node_id: i64,
    #[serde(rename = "ApiKey")]
    pub api_key: String,
    /// Only for the original V2Board: vmess | trojan | shadowsocks.
    #[serde(rename = "NodeType", default, skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,
    /// HTTP timeout in seconds.
    #[serde(rename = "Timeout", default = "default_timeout")]
    pub timeout: u64,
    /// Node-wide speed limit in Mbps (0 = none), applied on top of per-user limits.
    #[serde(rename = "SpeedLimit", default)]
    pub speed_limit: u32,
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

fn default_level() -> String {
    "info".into()
}

fn default_timeout() -> u64 {
    15
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        // Remnawave compose files pass NODE_PORT / SECRET_KEY as env vars.
        let env_rw = std::env::var("SECRET_KEY")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|secret_key| crate::rw::RemnawaveConfig {
                node_port: std::env::var("NODE_PORT")
                    .ok()
                    .and_then(|p| p.trim().parse().ok())
                    .unwrap_or(2222),
                secret_key,
            });
        let mut config: Config = if !path.exists() && env_rw.is_some() {
            Config {
                log: LogConfig::default(),
                nodes: Vec::new(),
                data_dir: default_data_dir(),
                acme_email: None,
                remnawave: None,
            }
        } else {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("read config {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("parse config {}", path.display()))?
        };
        if env_rw.is_some() {
            config.remnawave = env_rw;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.nodes.is_empty() && self.remnawave.is_none() {
            bail!("config has no Nodes and no Remnawave section");
        }
        let mut seen = std::collections::HashSet::new();
        for node in &self.nodes {
            if node.api_host.trim().is_empty() || node.api_key.trim().is_empty() {
                bail!("node {}: ApiHost and ApiKey are required", node.node_id);
            }
            if !seen.insert((
                node.api_host.trim_end_matches('/').to_string(),
                node.node_id,
            )) {
                bail!("node {} of {} is listed twice", node.node_id, node.api_host);
            }
            if node.panel_type == PanelType::V2board && node.node_type.is_none() {
                bail!(
                    "node {}: PanelType v2board needs NodeType (vmess | trojan | shadowsocks)",
                    node.node_id
                );
            }
        }
        Ok(())
    }
}

/// Adds/updates (`add`) or removes a node in the config file, creating it if needed.
pub fn edit_nodes(
    path: &Path,
    add: bool,
    opts: &std::collections::HashMap<String, String>,
) -> Result<String> {
    let get = |k: &str| {
        opts.get(k)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let api_host = get("api-host").context("--api-host is required")?;
    let api_host = api_host.trim_end_matches('/').to_string();
    let node_id: i64 = get("node-id")
        .context("--node-id is required")?
        .parse()
        .context("--node-id must be a number")?;
    let mut config = if path.exists() {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str::<Config>(&text)
            .with_context(|| format!("parse {}", path.display()))?
    } else {
        Config {
            log: LogConfig::default(),
            nodes: Vec::new(),
            data_dir: default_data_dir(),
            acme_email: None,
            remnawave: None,
        }
    };
    let same =
        |n: &NodeConfig| n.api_host.trim_end_matches('/') == api_host && n.node_id == node_id;
    let before = config.nodes.len();
    config.nodes.retain(|n| !same(n));
    let msg = if add {
        let panel_type: PanelType = match get("panel").as_deref().unwrap_or("xiaoboard") {
            "xboard" => PanelType::Xboard,
            "v2board" => PanelType::V2board,
            "xiaoboard" | "v2node" | "wyx2685" => PanelType::Xiaoboard,
            other => bail!("unknown --panel {other:?} (xiaoboard | xboard | v2board)"),
        };
        config.nodes.push(NodeConfig {
            panel_type,
            api_host: api_host.clone(),
            node_id,
            api_key: get("api-key").context("--api-key is required")?,
            node_type: get("node-type"),
            timeout: get("timeout")
                .and_then(|t| t.parse().ok())
                .unwrap_or_else(default_timeout),
            speed_limit: get("speed-limit").and_then(|t| t.parse().ok()).unwrap_or(0),
        });
        config.validate()?;
        if config.nodes.len() == before {
            format!("updated node {node_id} ({panel_type}) of {api_host}")
        } else {
            format!("added node {node_id} ({panel_type}) of {api_host}")
        }
    } else {
        if config.nodes.len() == before {
            bail!("node {node_id} of {api_host} is not in {}", path.display());
        }
        format!("removed node {node_id} of {api_host}")
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(&config)? + "\n")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2node_style_config() {
        let c: Config = serde_json::from_str(
            r#"{"Log":{"Level":"warning"},"Nodes":[
                {"ApiHost":"https://p.example","NodeID":3,"ApiKey":"k","Timeout":30},
                {"PanelType":"xboard","ApiHost":"https://x.example","NodeID":4,"ApiKey":"k"}]}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.nodes[0].panel_type, PanelType::Xiaoboard);
        assert_eq!(c.nodes[1].panel_type, PanelType::Xboard);
        assert_eq!(c.nodes[1].timeout, 15);
        assert_eq!(c.log.level, "warning");
    }

    #[test]
    fn add_update_remove_node() {
        let dir = std::env::temp_dir().join(format!("tn-cfg-{}", std::process::id()));
        let path = dir.join("config.json");
        let opts = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        let a = opts(&[
            ("panel", "xboard"),
            ("api-host", "https://p.x/"),
            ("node-id", "5"),
            ("api-key", "k"),
        ]);
        assert!(edit_nodes(&path, true, &a).unwrap().starts_with("added"));
        assert!(edit_nodes(&path, true, &a).unwrap().starts_with("updated"));
        let b = opts(&[
            ("api-host", "https://p.x"),
            ("node-id", "6"),
            ("api-key", "k"),
        ]);
        edit_nodes(&path, true, &b).unwrap();
        let c = Config::load(&path).unwrap();
        assert_eq!(c.nodes.len(), 2);
        assert_eq!(c.nodes[0].api_host, "https://p.x");
        edit_nodes(
            &path,
            false,
            &opts(&[("api-host", "https://p.x"), ("node-id", "5")]),
        )
        .unwrap();
        assert_eq!(Config::load(&path).unwrap().nodes.len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
