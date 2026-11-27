//! Translates the Xray JSON config sent by Remnawave into TunnixNode inbounds.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use log::warn;
use serde_json::{Map, Value};
use shoes::tunnix::UserSpec;

use crate::panel::{NodeInfo, Protocol, Route, Security, TlsInfo};

/// One managed inbound of the Remnawave profile.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub tag: String,
    pub info: NodeInfo,
    pub users: Vec<UserSpec>,
}

#[derive(Debug, Clone, Default)]
pub struct Translated {
    pub inbounds: Vec<Inbound>,
    /// Tag reported as the outbound carrying all traffic (first freedom outbound).
    pub direct_outbound: String,
    pub skipped: Vec<String>,
}

fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|x| !x.is_empty())
}

fn pem_value(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(x) if !x.trim().is_empty() => Some(x.clone()),
        Value::Array(lines) => {
            let joined: Vec<&str> = lines.iter().filter_map(Value::as_str).collect();
            (!joined.is_empty()).then(|| joined.join("\n") + "\n")
        }
        _ => None,
    }
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(|x| x.trim().to_string())
            .collect(),
        Some(Value::String(x)) if !x.trim().is_empty() => vec![x.trim().to_string()],
        _ => Vec::new(),
    }
}

/// Collects `block` routes from rules that send traffic to a blackhole outbound.
fn block_routes(config: &Value) -> Vec<Route> {
    let blackholes: Vec<&str> = config
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|o| matches!(s(o, "protocol"), Some("blackhole") | Some("block")))
        .filter_map(|o| s(o, "tag"))
        .collect();
    let mut matches = Vec::new();
    for rule in config
        .pointer("/routing/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(out) = s(rule, "outboundTag") else {
            continue;
        };
        if !blackholes.contains(&out) {
            continue;
        }
        for item in str_list(rule.get("domain"))
            .into_iter()
            .chain(str_list(rule.get("ip")))
        {
            if item == "geoip:private" {
                continue; // always blocked
            }
            matches.push(item);
        }
    }
    if matches.is_empty() {
        Vec::new()
    } else {
        vec![Route {
            action: "block".into(),
            matches,
            action_value: None,
        }]
    }
}

pub fn translate(config: &Value) -> Result<Translated> {
    let routes = block_routes(config);
    let direct_outbound = config
        .get("outbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|o| matches!(s(o, "protocol"), Some("freedom") | Some("direct")))
        .and_then(|o| s(o, "tag"))
        .unwrap_or("DIRECT")
        .to_string();
    let mut out = Translated {
        direct_outbound,
        ..Default::default()
    };
    let inbounds = config
        .get("inbounds")
        .and_then(Value::as_array)
        .context("config has no inbounds")?;
    for inbound in inbounds {
        let tag = s(inbound, "tag").unwrap_or("").to_string();
        if tag.starts_with("REMNAWAVE_") {
            continue;
        }
        let protocol = s(inbound, "protocol").unwrap_or("");
        let protocol = match protocol {
            "vless" => Protocol::Vless,
            "vmess" => Protocol::Vmess,
            "trojan" => Protocol::Trojan,
            "shadowsocks" => Protocol::Shadowsocks,
            "hysteria" | "hysteria2" => Protocol::Hysteria2,
            other => {
                warn!("Remnawave: inbound {tag:?} ({other}) is not managed by TunnixNode; skipped");
                out.skipped.push(tag);
                continue;
            }
        };
        let inbound_result = translate_inbound(&tag, protocol, inbound, &routes)
            .with_context(|| format!("inbound {tag:?}"))?;
        out.inbounds.push(inbound_result);
    }
    Ok(out)
}

fn translate_inbound(
    tag: &str,
    protocol: Protocol,
    inbound: &Value,
    routes: &[Route],
) -> Result<Inbound> {
    let port = match inbound.get("port") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(p)) => p.trim().parse().map_err(|_| {
            anyhow::anyhow!("port {p:?} is not supported (port ranges are not supported)")
        })?,
        _ => 0,
    };
    if !(1..=65535).contains(&port) {
        bail!("missing or invalid port");
    }
    let listen = s(inbound, "listen").unwrap_or("0.0.0.0");
    if listen.starts_with('@') || listen.starts_with('/') {
        bail!("unix socket listeners are not supported");
    }
    let empty = Value::Object(Map::new());
    let settings = inbound.get("settings").unwrap_or(&empty);
    let stream = inbound.get("streamSettings").unwrap_or(&empty);
    let mut network = s(stream, "network").unwrap_or("tcp").to_ascii_lowercase();
    if network == "raw" {
        network = "tcp".into();
    }
    if protocol == Protocol::Hysteria2 {
        network = "tcp".into();
    }
    let settings_key = match network.as_str() {
        "ws" => "wsSettings",
        "grpc" => "grpcSettings",
        "httpupgrade" => "httpupgradeSettings",
        "xhttp" | "splithttp" => {
            if stream.get("xhttpSettings").is_some() {
                "xhttpSettings"
            } else {
                "splithttpSettings"
            }
        }
        "tcp" => {
            if stream.get("rawSettings").is_some() {
                "rawSettings"
            } else {
                "tcpSettings"
            }
        }
        "kcp" | "mkcp" => bail!("mKCP transport is not supported"),
        other => bail!("transport {other:?} is not supported"),
    };
    let network_settings = stream
        .get(settings_key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    let security = match (protocol, s(stream, "security").unwrap_or("none")) {
        (Protocol::Hysteria2, _) => Security::Tls,
        (_, "tls") => Security::Tls,
        (_, "reality") => Security::Reality,
        (Protocol::Trojan, _) => Security::Tls,
        _ => Security::None,
    };
    let mut tls = TlsInfo {
        cert_mode: "self".into(),
        ..Default::default()
    };
    if let Some(t) = stream.get("tlsSettings") {
        if let Some(name) = s(t, "serverName") {
            tls.server_names.push(name.to_string());
        }
        if let Some(cert) = t
            .get("certificates")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        {
            let pem = pem_value(cert.get("certificate"));
            let key = pem_value(cert.get("key"));
            if pem.is_some() && key.is_some() {
                tls.cert_mode = "remote".into();
                tls.cert_pem = pem;
                tls.key_pem = key;
            } else if let (Some(c), Some(k)) = (s(cert, "certificateFile"), s(cert, "keyFile")) {
                tls.cert_mode = "file".into();
                tls.cert_file = Some(c.to_string());
                tls.key_file = Some(k.to_string());
            }
        }
    }
    if let Some(r) = stream.get("realitySettings") {
        tls.server_names = str_list(r.get("serverNames"));
        tls.private_key = s(r, "privateKey").map(str::to_string);
        tls.short_ids = str_list(r.get("shortIds"));
        tls.dest = s(r, "target").or_else(|| s(r, "dest")).map(str::to_string);
        if let Some(Value::Number(n)) = r.get("dest").or_else(|| r.get("target")) {
            tls.dest = Some(format!("127.0.0.1:{n}"));
        }
        tls.xver = r.get("xver").and_then(Value::as_u64).unwrap_or(0);
        tls.mldsa65_seed = s(r, "mldsa65Seed").map(str::to_string);
    }

    let method = s(settings, "method").map(str::to_string);
    let is_2022 = method.as_deref().is_some_and(|m| m.starts_with("2022-"));
    let flow = s(settings, "flow").map(str::to_string);
    let decryption = s(settings, "decryption")
        .filter(|d| *d != "none")
        .map(str::to_string);

    let mut users = Vec::new();
    for client in settings
        .get("clients")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(email) = s(client, "email") else {
            continue;
        };
        let Ok(uid) = email.parse::<i64>() else {
            warn!("Remnawave: client email {email:?} is not a numeric user id; skipped");
            continue;
        };
        let credential = match protocol {
            Protocol::Vless | Protocol::Vmess => s(client, "id").map(str::to_string),
            Protocol::Trojan => s(client, "password").map(str::to_string),
            Protocol::Hysteria2 => s(client, "auth")
                .or_else(|| s(client, "id"))
                .map(str::to_string),
            Protocol::Shadowsocks if is_2022 => s(client, "password").and_then(ss2022_user_key),
            Protocol::Shadowsocks => s(client, "password").map(str::to_string),
            _ => None,
        };
        if let Some(uuid) = credential {
            users.push(UserSpec {
                uid,
                uuid,
                speed_limit: 0,
                device_limit: 0,
            });
        }
    }

    let info = NodeInfo {
        protocol,
        listen_ip: listen.to_string(),
        port: port as u16,
        network,
        network_settings,
        security,
        tls,
        flow,
        decryption,
        cipher: method,
        server_key: if is_2022 {
            s(settings, "password").map(str::to_string)
        } else {
            None
        },
        congestion_control: None,
        zero_rtt_handshake: false,
        up_mbps: 0,
        down_mbps: 0,
        obfs: None,
        obfs_password: None,
        padding_scheme: Vec::new(),
        push_interval: Duration::from_secs(60),
        pull_interval: Duration::from_secs(60),
        report_min_traffic: 0,
        device_online_min_traffic: 0,
        routes: routes.to_vec(),
    };
    Ok(Inbound {
        tag: tag.to_string(),
        info,
        users,
    })
}

/// Remnawave SS-2022 user keys are base64(utf8(ssPassword)); TunnixNode keys users
/// by the raw password string (its bytes are the user PSK).
pub fn ss2022_user_key(b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn translates_reality_vless_and_ss2022() {
        let cfg = json!({
            "inbounds": [
                {"tag": "REMNAWAVE_API_INBOUND", "protocol": "tunnel", "listen": "@x"},
                {"tag": "VLESS_REALITY", "port": 443, "protocol": "vless",
                 "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "12"}],
                              "decryption": "none", "flow": "xtls-rprx-vision"},
                 "streamSettings": {"network": "raw", "security": "reality",
                    "realitySettings": {"target": "www.apple.com:443", "serverNames": ["www.apple.com"],
                                        "privateKey": "PK", "shortIds": ["", "ab"]}}},
                {"tag": "SS", "port": "8388", "protocol": "shadowsocks",
                 "settings": {"method": "2022-blake3-aes-256-gcm", "password": "SERVERKEY",
                              "clients": [{"password": base64::engine::general_purpose::STANDARD.encode("abcdefghijklmnopqrstuvwxyz012345"), "email": "7"}]}},
                {"tag": "SOCKS", "port": 1080, "protocol": "socks"}
            ],
            "outbounds": [{"tag": "DIRECT", "protocol": "freedom"}, {"tag": "BLOCK", "protocol": "blackhole"}],
            "routing": {"rules": [{"ip": ["geoip:private"], "outboundTag": "BLOCK"},
                                  {"domain": ["domain:bad.example"], "outboundTag": "BLOCK"}]}
        });
        let t = translate(&cfg).unwrap();
        assert_eq!(t.inbounds.len(), 2);
        assert_eq!(t.skipped, vec!["SOCKS"]);
        let v = &t.inbounds[0];
        assert_eq!(v.info.security, Security::Reality);
        assert_eq!(v.info.tls.dest.as_deref(), Some("www.apple.com:443"));
        assert_eq!(v.info.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(v.users[0].uid, 12);
        assert_eq!(v.info.routes[0].matches, vec!["domain:bad.example"]);
        let ss = &t.inbounds[1];
        assert_eq!(ss.info.port, 8388);
        assert_eq!(ss.info.server_key.as_deref(), Some("SERVERKEY"));
        assert_eq!(ss.users[0].uuid, "abcdefghijklmnopqrstuvwxyz012345");
        assert_eq!(t.direct_outbound, "DIRECT");
    }

    #[test]
    fn rejects_port_ranges_and_kcp() {
        let cfg = json!({"inbounds": [{"tag": "x", "port": "1000-2000", "protocol": "vless", "settings": {}}]});
        assert!(translate(&cfg).is_err());
        let cfg = json!({"inbounds": [{"tag": "x", "port": 1, "protocol": "vless", "settings": {},
            "streamSettings": {"network": "kcp"}}]});
        let err = format!("{:#}", translate(&cfg).unwrap_err());
        assert!(err.contains("mKCP"), "{err}");
    }
}
