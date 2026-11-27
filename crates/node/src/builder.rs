//! Translates a normalised panel [`NodeInfo`] into shoes server config entries.
//!
//! Users are not written into the config. The inbound gets a random placeholder
//! credential under which the node registers its live `UserStore`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use log::warn;
use serde_json::{Value, json};

use crate::panel::{NodeInfo, Protocol, Security};

/// Private and special-purpose ranges a client must never reach through the node.
const BLOCKED_RANGES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

pub struct BuildContext<'a> {
    /// Unique per node, e.g. `node-3`.
    pub tag: &'a str,
    pub placeholder: &'a str,
    pub cert_dir: &'a Path,
    /// Certificate obtained by ACME for cert_mode http/dns: (cert, key).
    pub acme: Option<(String, String)>,
}

/// Returns the server entries for one panel node.
pub fn build_servers(info: &NodeInfo, ctx: &BuildContext<'_>) -> Result<Vec<Value>> {
    let inner = inner_protocol(info, ctx)?;
    let vision = info.flow.as_deref() == Some("xtls-rprx-vision");
    if info.protocol == Protocol::AnyTls && info.security == Security::None {
        bail!("AnyTLS needs TLS");
    }
    if vision && info.protocol != Protocol::Vless {
        bail!("flow xtls-rprx-vision requires VLESS");
    }
    let rules = rules(info);
    let address = bind_address(&info.listen_ip, info.port);

    let server = match info.protocol {
        Protocol::Hysteria2 | Protocol::Tuic => {
            let (cert, key) = certificate(info, ctx)?;
            json!({
                "name": ctx.tag,
                "address": address,
                "transport": "quic",
                "quic_settings": {"cert": cert, "key": key, "alpn_protocols": ["h3"]},
                "protocol": inner,
                "rules": rules,
            })
        }
        _ => {
            let transported = wrap_transport(info, inner)?;
            let protocol = match info.security {
                Security::None => transported,
                Security::Reality => reality(info, transported, vision)?,
                Security::Tls => {
                    let (cert, key) = certificate(info, ctx)?;
                    let target = json!({
                        "cert": cert,
                        "key": key,
                        "vision": vision && info.network == "tcp",
                        "protocol": transported,
                    });
                    if info.tls.reject_unknown_sni && !info.tls.server_names.is_empty() {
                        let targets: serde_json::Map<String, Value> = info
                            .tls
                            .server_names
                            .iter()
                            .map(|n| (n.clone(), target.clone()))
                            .collect();
                        json!({"type": "tls", "tls_targets": targets})
                    } else {
                        json!({"type": "tls", "default_tls_target": target})
                    }
                }
            };
            json!({
                "name": ctx.tag,
                "address": address,
                "transport": "tcp",
                "protocol": protocol,
                "rules": rules,
            })
        }
    };
    let mut servers = vec![server];
    // Shadowsocks clients send UDP natively on the same port.
    if info.protocol == Protocol::Shadowsocks {
        let mut udp = servers[0].clone();
        udp["name"] = json!(format!("{}-udp", ctx.tag));
        udp["transport"] = json!("udp");
        servers.push(udp);
    }
    Ok(servers)
}

fn bind_address(listen_ip: &str, port: u16) -> String {
    let ip = listen_ip
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip = if ip.is_empty() { "0.0.0.0" } else { ip };
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn inner_protocol(info: &NodeInfo, ctx: &BuildContext<'_>) -> Result<Value> {
    let p = ctx.placeholder;
    Ok(match info.protocol {
        Protocol::Vless => {
            let mut v = json!({"type": "vless", "user_id": p, "udp_enabled": true});
            if let Some(decryption) = &info.decryption {
                v["decryption"] = json!(decryption);
                // With native encryption, Vision lives on the VLESS layer itself.
                if info.flow.as_deref() == Some("xtls-rprx-vision")
                    && info.security == Security::None
                {
                    v["vision"] = json!(true);
                }
            }
            v
        }
        Protocol::Vmess => {
            json!({"type": "vmess", "cipher": "any", "user_id": p, "udp_enabled": true})
        }
        Protocol::Trojan => json!({"type": "trojan", "password": p}),
        Protocol::Shadowsocks => {
            let cipher = ss_cipher(info.cipher.as_deref().unwrap_or("aes-128-gcm"))?;
            let password = if cipher.starts_with("2022-") {
                if cipher.contains("chacha20") {
                    bail!(
                        "multi-user {cipher} is not supported by Shadowsocks 2022 (use an AES cipher)"
                    );
                }
                info.server_key
                    .clone()
                    .context("Shadowsocks 2022 node without server_key")?
            } else {
                p.to_string()
            };
            json!({"type": "shadowsocks", "cipher": cipher, "password": password, "udp_enabled": true})
        }
        Protocol::Hysteria2 => {
            if let Some(obfs) = info
                .obfs
                .as_deref()
                .filter(|o| !o.is_empty() && *o != "none")
            {
                if obfs != "salamander" {
                    bail!("Hysteria2 obfs {obfs:?} is not supported (only salamander)");
                }
                if info.obfs_password.as_deref().unwrap_or("").is_empty() {
                    bail!("Hysteria2 salamander obfs without a password");
                }
            }
            json!({"type": "hysteria2", "password": p, "udp_enabled": true})
        }
        Protocol::Tuic => json!({
            "type": "tuic",
            "uuid": p,
            "password": p,
            "zero_rtt_handshake": info.zero_rtt_handshake,
        }),
        Protocol::AnyTls => {
            let mut v = json!({
                "type": "anytls",
                "users": [{"name": "panel", "password": p}],
                "udp_enabled": true,
            });
            if !info.padding_scheme.is_empty() {
                v["padding_scheme"] = json!(info.padding_scheme);
            }
            v
        }
    })
}

fn ss_cipher(name: &str) -> Result<&'static str> {
    Ok(match name.trim().to_ascii_lowercase().as_str() {
        "aes-128-gcm" | "aead_aes_128_gcm" => "aes-128-gcm",
        "aes-256-gcm" | "aead_aes_256_gcm" => "aes-256-gcm",
        "chacha20-poly1305" | "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" => {
            "chacha20-ietf-poly1305"
        }
        "2022-blake3-aes-128-gcm" => "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm" => "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305" => "2022-blake3-chacha20-poly1305",
        other => bail!("Shadowsocks cipher {other:?} is not supported"),
    })
}

/// Hysteria2 Salamander obfuscation: (listen address, password).
pub fn salamander(info: &NodeInfo) -> Option<(std::net::SocketAddr, String)> {
    if info.protocol != Protocol::Hysteria2 || info.obfs.as_deref() != Some("salamander") {
        return None;
    }
    let addr = bind_address(&info.listen_ip, info.port).parse().ok()?;
    Some((addr, info.obfs_password.clone()?))
}

/// Extra credentials the node must register its user store under.
pub fn extra_store_keys(info: &NodeInfo) -> Vec<String> {
    match (info.protocol, info.cipher.as_deref(), &info.server_key) {
        (Protocol::Shadowsocks, Some(c), Some(key)) if c.starts_with("2022-") => vec![key.clone()],
        _ => Vec::new(),
    }
}

fn setting_str<'a>(info: &'a NodeInfo, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .filter_map(|k| info.network_settings.get(*k))
        .find_map(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn wrap_transport(info: &NodeInfo, inner: Value) -> Result<Value> {
    Ok(match info.network.as_str() {
        "tcp" | "raw" | "" => {
            if let Some(header) = info.network_settings.get("header")
                && header
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t != "none")
            {
                bail!("TCP header obfuscation is not supported");
            }
            inner
        }
        "ws" | "websocket" | "httpupgrade" => {
            let (path, early) = split_early_data(setting_str(info, &["path"]).unwrap_or("/"));
            let mut target = json!({"matching_path": path, "protocol": inner});
            if info.network == "httpupgrade" {
                target["mode"] = json!("httpupgrade");
            }
            if let Some(max) = early {
                target["max_early_data"] = json!(max);
                target["early_data_header_name"] = json!("sec-websocket-protocol");
            }
            json!({"type": "websocket", "targets": [target]})
        }
        "grpc" | "gun" => {
            let service = setting_str(info, &["serviceName", "service_name"]).unwrap_or("");
            json!({
                "type": "websocket",
                "targets": [{"matching_path": service, "mode": "grpc", "protocol": inner}],
            })
        }
        "xhttp" | "splithttp" => {
            let path = setting_str(info, &["path"]).unwrap_or("/");
            let mut v = json!({"type": "xhttp", "path": path, "protocol": inner});
            if let Some(mode) = setting_str(info, &["mode"]) {
                v["mode"] = json!(mode);
            }
            v
        }
        other => bail!("transport {other:?} is not supported by this build yet"),
    })
}

/// Splits Xray's `/path?ed=2048` into the path and the early-data size.
fn split_early_data(path: &str) -> (String, Option<usize>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    let ed = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("ed="))
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0);
    let base = if base.is_empty() { "/" } else { base };
    (base.to_string(), ed)
}

fn reality(info: &NodeInfo, protocol: Value, vision: bool) -> Result<Value> {
    let tls = &info.tls;
    let private_key = tls
        .private_key
        .as_deref()
        .context("REALITY node without private_key")?;
    if tls.xver != 0 {
        warn!("REALITY xver (PROXY protocol to dest) is not supported; ignored");
    }
    let dest_host = tls
        .dest
        .as_deref()
        .or(tls.server_names.first().map(String::as_str))
        .context("REALITY node without dest/server_name")?;
    let dest = if dest_host
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
        && !dest_host.ends_with(']')
    {
        dest_host.to_string()
    } else {
        format!("{dest_host}:{}", tls.dest_port.unwrap_or(443))
    };
    let mut short_ids = tls.short_ids.clone();
    if short_ids.is_empty() {
        short_ids.push(String::new());
    }
    let mut target = json!({
        "private_key": private_key,
        "short_ids": short_ids,
        "dest": dest,
        "vision": vision && info.network == "tcp",
        "protocol": protocol,
    });
    if let Some(seed) = &tls.mldsa65_seed {
        target["mldsa65_seed"] = json!(seed);
    }
    let names = if tls.server_names.is_empty() {
        vec![dest_host.to_string()]
    } else {
        tls.server_names.clone()
    };
    let targets: serde_json::Map<String, Value> =
        names.into_iter().map(|n| (n, target.clone())).collect();
    Ok(json!({"type": "tls", "reality_targets": targets}))
}

/// Resolves the certificate files for a TLS/QUIC inbound.
fn certificate(info: &NodeInfo, ctx: &BuildContext<'_>) -> Result<(String, String)> {
    let tls = &info.tls;
    let name = tls
        .server_names
        .first()
        .cloned()
        .unwrap_or_else(|| "localhost".into());
    let default_paths = || -> (PathBuf, PathBuf) {
        (
            ctx.cert_dir.join(format!("{}.crt", ctx.tag)),
            ctx.cert_dir.join(format!("{}.key", ctx.tag)),
        )
    };
    match tls.cert_mode.as_str() {
        "file" => {
            let (c, k) = default_paths();
            let cert = tls
                .cert_file
                .clone()
                .unwrap_or_else(|| c.display().to_string());
            let key = tls
                .key_file
                .clone()
                .unwrap_or_else(|| k.display().to_string());
            if !Path::new(&cert).exists() || !Path::new(&key).exists() {
                bail!("cert_mode=file but {cert} / {key} not found on this server");
            }
            Ok((cert, key))
        }
        "remote" => {
            let (c, k) = default_paths();
            let (Some(cert), Some(key)) = (&tls.cert_pem, &tls.key_pem) else {
                bail!("cert_mode=remote but the panel sent no tls_cert/tls_key");
            };
            write_if_changed(&c, cert)?;
            write_private(&k, key)?;
            Ok((c.display().to_string(), k.display().to_string()))
        }
        "self" | "none" | "" => {
            let (c, k) = default_paths();
            self_signed(&name, &c, &k)?;
            Ok((c.display().to_string(), k.display().to_string()))
        }
        "http" | "dns" | "tls" if ctx.acme.is_some() => Ok(ctx.acme.clone().unwrap()),
        other => {
            // ACME failed or the mode is unknown: keep the node up with a self-signed
            // certificate until the next attempt.
            warn!(
                "{}: no certificate for cert_mode={other} yet, using a self-signed one for {name}",
                ctx.tag
            );
            let (c, k) = default_paths();
            self_signed(&name, &c, &k)?;
            Ok((c.display().to_string(), k.display().to_string()))
        }
    }
}

fn self_signed(name: &str, cert_path: &Path, key_path: &Path) -> Result<()> {
    let marker = cert_path.with_extension("name");
    if cert_path.exists()
        && key_path.exists()
        && std::fs::read_to_string(&marker).is_ok_and(|n| n == name)
    {
        return Ok(());
    }
    let generated = rcgen::generate_simple_self_signed(vec![name.to_string()])
        .context("generate self-signed certificate")?;
    write_if_changed(cert_path, &generated.cert.pem())?;
    write_private(key_path, &generated.signing_key.serialize_pem())?;
    std::fs::write(&marker, name)?;
    Ok(())
}

fn write_if_changed(path: &Path, content: &str) -> Result<()> {
    if std::fs::read_to_string(path).is_ok_and(|c| c == content) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, content).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn write_private(path: &Path, content: &str) -> Result<()> {
    write_if_changed(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn rules(info: &NodeInfo) -> Value {
    // TUNNIX_ALLOW_PRIVATE=1 lifts the private-range block (local testing only).
    let allow_private = std::env::var("TUNNIX_ALLOW_PRIVATE").is_ok_and(|v| v == "1");
    let mut rules = if allow_private {
        Vec::new()
    } else {
        vec![json!({"masks": BLOCKED_RANGES, "action": "block"})]
    };
    let block = block_conditions(&info.routes);
    if !block.is_empty() {
        rules.push(json!({"conditions": {"any": block}, "action": "block"}));
    }
    rules.push(json!({
        "conditions": {"any_destination": true},
        "action": "allow",
        "client_chain": {"protocol": {"type": "direct"}},
    }));
    Value::Array(rules)
}

/// Translates panel block routes into core rule conditions, following Xray semantics as v2node
/// does: `block` matches domains, `block_ip` addresses, `block_port` ports and `protocol`
/// sniffed protocols. Entries the core cannot express are skipped with a warning, so an
/// unsupported rule never prevents the node from starting.
fn block_conditions(routes: &[crate::panel::Route]) -> Vec<Value> {
    let mut lists: std::collections::BTreeMap<&'static str, Vec<Value>> = Default::default();
    let skip = |action: &str, m: &str| {
        warn!("route {action} match {m:?} is not supported; skipped");
    };
    for route in routes {
        let action = route.action.as_str();
        for m in route
            .matches
            .iter()
            .map(|m| m.trim())
            .filter(|m| !m.is_empty())
        {
            let entry: Option<(&'static str, Value)> = match action {
                "block" => {
                    if let Some(v) = m.strip_prefix("domain:") {
                        Some(("domain_suffix", json!(v)))
                    } else if let Some(v) = m.strip_prefix("full:") {
                        Some(("domain", json!(v)))
                    } else if let Some(v) = m.strip_prefix("keyword:") {
                        Some(("domain_keyword", json!(v)))
                    } else if let Some(v) = m.strip_prefix("regexp:") {
                        Some(("domain_regex", json!(v)))
                    } else if m.contains(':') {
                        None // geosite:, ext:, ...
                    } else {
                        // Xray treats a bare string as a substring match.
                        Some(("domain_keyword", json!(m)))
                    }
                }
                "block_ip" => {
                    if m.contains(':')
                        && m.parse::<std::net::Ipv6Addr>().is_err()
                        && !m.contains('/')
                    {
                        None // geoip:, ext:, ...
                    } else if let Ok(ip) = m.parse::<std::net::IpAddr>() {
                        let bits = if ip.is_ipv4() { 32 } else { 128 };
                        Some(("ip_cidr", json!(format!("{ip}/{bits}"))))
                    } else {
                        Some(("ip_cidr", json!(m)))
                    }
                }
                "block_port" => {
                    for part in m.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                        match part.parse::<u16>() {
                            Ok(port) => lists
                                .entry("destination_port")
                                .or_default()
                                .push(json!(port)),
                            Err(_) => push_checked(
                                &mut lists,
                                "destination_port_range",
                                json!(part.replace('-', ":")),
                                action,
                                part,
                            ),
                        }
                    }
                    continue;
                }
                // QUIC is UDP to port 443; other sniffed protocols are not available.
                "protocol" if m.eq_ignore_ascii_case("quic") => {
                    lists.entry("quic").or_default().push(json!(true));
                    continue;
                }
                "protocol" => None,
                "dns" => continue,
                _ => {
                    skip(action, m);
                    continue;
                }
            };
            match entry {
                Some((key, value)) => push_checked(&mut lists, key, value, action, m),
                None => skip(action, m),
            }
        }
        if !matches!(
            action,
            "block" | "block_ip" | "block_port" | "protocol" | "dns" | ""
        ) && route.matches.is_empty()
        {
            warn!("route action {action:?} is not supported; skipped");
        }
    }

    let mut conditions = Vec::new();
    for (key, values) in lists {
        if key == "quic" {
            conditions.push(json!({"all": [{"network": "udp"}, {"destination_port": [443]}]}));
        } else {
            conditions.push(json!({ key: values }));
        }
    }
    conditions
}

/// Adds `value` to the `key` list only if the core accepts it on its own.
fn push_checked(
    lists: &mut std::collections::BTreeMap<&'static str, Vec<Value>>,
    key: &'static str,
    value: Value,
    action: &str,
    m: &str,
) {
    if shoes::tunnix::is_valid_condition(&json!({ key: [value.clone()] })) {
        lists.entry(key).or_default().push(value);
    } else {
        warn!("route {action} match {m:?} is not valid; skipped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PanelType;

    fn node(v: Value) -> NodeInfo {
        NodeInfo::parse(&v, PanelType::Xiaoboard, "v2node").unwrap()
    }

    #[test]
    fn vless_reality_vision() {
        let info = node(json!({"protocol": "vless", "server_port": 443, "tls": 2,
            "flow": "xtls-rprx-vision", "network": "tcp",
            "tls_settings": {"server_name": "www.apple.com", "private_key": "PK", "short_id": "ab"}}));
        let dir = std::env::temp_dir();
        let ctx = BuildContext {
            tag: "node-1",
            placeholder: "11111111-1111-1111-1111-111111111111",
            cert_dir: &dir,
            acme: None,
        };
        let s = &build_servers(&info, &ctx).unwrap()[0];
        assert_eq!(s["address"], "0.0.0.0:443");
        let t = &s["protocol"]["reality_targets"]["www.apple.com"];
        assert_eq!(t["dest"], "www.apple.com:443");
        assert_eq!(t["vision"], true);
        assert_eq!(t["protocol"]["type"], "vless");
        assert_eq!(t["protocol"]["user_id"], ctx.placeholder);
    }

    #[tokio::test]
    async fn routes_follow_xray_semantics_and_skip_unsupported() {
        let info = node(json!({"protocol": "vless", "server_port": 8443, "tls": 0,
        "network": "tcp",
        "routes": [
            {"id": 1, "action": "protocol", "match": ["quic", "bittorrent"]},
            {"id": 2, "action": "route", "match": ["geosite:google", "domain:gemini.google.com"],
             "action_value": "{\"tag\":\"ai\",\"protocol\":\"socks\"}"},
            {"id": 3, "action": "block", "match": ["domain:ads.example.com", "full:x.example",
             "keyword:tracker", "regexp:^bad\\.", "regexp:(", "geosite:category-ads",
             "*.wild.example", "doubleclick", " "]},
            {"id": 4, "action": "block_ip", "match": ["10.1.0.0/16", "1.2.3.4", "2001:db8::1",
             "geoip:cn", "1.2.3.0/abc"]},
            {"id": 5, "action": "block_port", "match": ["25,465", "6881-6889", "x"]},
            {"id": 6, "action": "default_out", "match": []},
            {"id": 7, "action": "dns", "match": ["example.com"], "action_value": "1.1.1.1"},
        ]}));
        let r = rules(&info);
        let block = r
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| {
                rule.get("conditions")
                    .is_some_and(|c| c.get("any").is_some())
            })
            .unwrap();
        assert_eq!(
            block["conditions"]["any"],
            json!([
                {"destination_port": [25, 465]},
                {"destination_port_range": ["6881:6889"]},
                {"domain": ["x.example"]},
                {"domain_keyword": ["tracker", "*.wild.example", "doubleclick"]},
                {"domain_regex": ["^bad\\."]},
                {"domain_suffix": ["ads.example.com"]},
                {"ip_cidr": ["10.1.0.0/16", "1.2.3.4/32", "2001:db8::1/128"]},
                {"all": [{"network": "udp"}, {"destination_port": [443]}]},
            ])
        );

        let dir = std::env::temp_dir().join(format!("tunnix-routes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = BuildContext {
            placeholder: "11111111-1111-4111-8111-111111111111",
            ..ctx(&dir)
        };
        let servers = build_servers(&info, &ctx).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, serde_json::to_string(&servers).unwrap()).unwrap();
        let checked = shoes::tunnix::check_config(vec![path.display().to_string()]).await;
        std::fs::remove_dir_all(&dir).ok();
        checked.unwrap();
    }

    #[test]
    fn no_routes_adds_no_block_rule() {
        let info =
            node(json!({"protocol": "vless", "server_port": 8443, "tls": 0, "network": "tcp"}));
        assert!(block_conditions(&info.routes).is_empty());
    }

    fn ctx(dir: &Path) -> BuildContext<'_> {
        BuildContext {
            tag: "node-t",
            placeholder: "11111111-1111-1111-1111-111111111111",
            cert_dir: dir,
            acme: None,
        }
    }

    #[test]
    fn grpc_httpupgrade_and_early_data() {
        let dir = std::env::temp_dir();
        let g = node(
            json!({"protocol": "vless", "server_port": 1, "tls": 0, "network": "grpc", "network_settings": {"serviceName": "svc"}}),
        );
        let s = &build_servers(&g, &ctx(&dir)).unwrap()[0];
        assert_eq!(s["protocol"]["targets"][0]["mode"], "grpc");
        assert_eq!(s["protocol"]["targets"][0]["matching_path"], "svc");
        let h = node(
            json!({"protocol": "vmess", "server_port": 2, "tls": 0, "network": "httpupgrade", "network_settings": {"path": "/up?ed=2048"}}),
        );
        let s = &build_servers(&h, &ctx(&dir)).unwrap()[0];
        let t = &s["protocol"]["targets"][0];
        assert_eq!(t["mode"], "httpupgrade");
        assert_eq!(t["matching_path"], "/up");
        assert_eq!(t["max_early_data"], 2048);
    }

    #[test]
    fn every_protocol_builds() {
        let dir = std::env::temp_dir().join(format!("tn-all-{}", std::process::id()));
        let cases = [
            json!({"protocol": "vmess", "server_port": 1, "tls": 0, "network": "ws", "network_settings": {"path": "/v"}}),
            json!({"protocol": "trojan", "server_port": 2, "tls_settings": {"server_name": "t.example.com"}}),
            json!({"protocol": "shadowsocks", "server_port": 3, "cipher": "aes-256-gcm"}),
            json!({"protocol": "shadowsocks", "server_port": 4, "cipher": "2022-blake3-aes-128-gcm", "server_key": "AAAAAAAAAAAAAAAAAAAAAA=="}),
            json!({"protocol": "hysteria2", "server_port": 5, "tls_settings": {"server_name": "h.example.com"}}),
            json!({"protocol": "tuic", "server_port": 6, "tls_settings": {"server_name": "u.example.com"}}),
            json!({"protocol": "anytls", "server_port": 7, "padding_scheme": ["stop=8"], "tls_settings": {"server_name": "a.example.com"}}),
        ];
        for case in cases {
            let info = node(case.clone());
            let servers =
                build_servers(&info, &ctx(&dir)).unwrap_or_else(|e| panic!("{case}: {e}"));
            let expected = if info.protocol == Protocol::Shadowsocks {
                2
            } else {
                1
            };
            assert_eq!(servers.len(), expected);
        }
        let ss = node(
            json!({"protocol": "shadowsocks", "server_port": 4, "cipher": "2022-blake3-aes-128-gcm", "server_key": "K"}),
        );
        assert_eq!(extra_store_keys(&ss), vec!["K".to_string()]);
        let hy = node(
            json!({"protocol": "hysteria2", "server_port": 5, "obfs": "salamander", "obfs_password": "x"}),
        );
        assert!(build_servers(&hy, &ctx(&dir)).is_ok());
        assert_eq!(salamander(&hy).unwrap().1, "x");
        let bad = node(
            json!({"protocol": "hysteria2", "server_port": 5, "obfs": "gecko", "obfs_password": "x"}),
        );
        assert!(build_servers(&bad, &ctx(&dir)).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn vless_ws_tls_self_signed() {
        let info = node(
            json!({"protocol": "vless", "server_port": 8443, "tls": 1, "network": "ws",
            "network_settings": {"path": "/ws"}, "listen_ip": "::",
            "tls_settings": {"server_name": "a.example.com", "cert_mode": "self"}}),
        );
        let dir = std::env::temp_dir().join(format!("tn-test-{}", std::process::id()));
        let ctx = BuildContext {
            tag: "node-2",
            placeholder: "11111111-1111-1111-1111-111111111111",
            cert_dir: &dir,
            acme: None,
        };
        let s = &build_servers(&info, &ctx).unwrap()[0];
        assert_eq!(s["address"], "[::]:8443");
        let t = &s["protocol"]["default_tls_target"];
        assert_eq!(t["protocol"]["type"], "websocket");
        assert!(Path::new(t["cert"].as_str().unwrap()).exists());
        std::fs::remove_dir_all(dir).ok();
    }
}
