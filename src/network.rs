use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    pub metric: String,
}

pub fn valid_ipv4_cidr(value: &str) -> bool {
    if value == "default" {
        return true;
    }
    let Some((addr, prefix)) = value.split_once('/') else {
        return false;
    };
    addr.parse::<Ipv4Addr>().is_ok() && prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
}

pub fn valid_ipv4_gateway(value: &str) -> bool {
    value.is_empty() || value.parse::<Ipv4Addr>().is_ok()
}

pub fn valid_ipv4_addresses(value: &str, required: bool) -> bool {
    let addresses: Vec<_> = value
        .split(',')
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .collect();
    if required && addresses.is_empty() {
        return false;
    }
    addresses.iter().all(|address| {
        let Some((ip, prefix)) = address.split_once('/') else {
            return false;
        };
        ip.parse::<Ipv4Addr>().is_ok()
            && prefix
                .parse::<u8>()
                .map(|value| value <= 32)
                .unwrap_or(false)
    })
}

pub fn valid_ipv4_method(value: &str) -> bool {
    matches!(
        value,
        "auto" | "manual" | "shared" | "link-local" | "disabled"
    )
}

pub fn valid_autoconnect(value: &str) -> bool {
    matches!(value, "yes" | "no")
}

pub fn valid_dns_servers(value: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .filter(|server| !server.is_empty())
        .all(|server| server.parse::<IpAddr>().is_ok())
}

pub fn valid_metric(value: &str) -> bool {
    value.is_empty() || value.parse::<u32>().is_ok()
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub name: String,
    pub kind: String,
    pub device: String,
    pub state: String,
    pub autoconnect: String,
    pub ipv4_method: String,
    pub addresses: Vec<String>,
    pub gateway: String,
    pub metric: String,
    pub dns: Vec<String>,
    pub search: Vec<String>,
    pub routes: Vec<Route>,
    pub runtime_addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct IpAddress {
    addr_info: Vec<AddrInfo>,
}

#[derive(Debug, Deserialize)]
struct AddrInfo {
    family: String,
    local: String,
    prefixlen: u8,
}

fn split_nmcli(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for c in line.chars() {
        if escaped {
            current.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ':' {
            fields.push(current);
            current = String::new();
        } else {
            current.push(c);
        }
    }
    if escaped {
        current.push('\\');
    }
    fields.push(current);
    fields
}

async fn run(args: &[&str]) -> Result<String> {
    let out = Command::new("nmcli")
        .args(args)
        .output()
        .await
        .with_context(|| format!("failed to execute nmcli {}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(if err.is_empty() {
            "nmcli command failed".to_string()
        } else {
            err
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn list_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn load_profiles() -> Result<Vec<Profile>> {
    let listing = run(&[
        "-t",
        "-f",
        "NAME,TYPE,DEVICE,STATE,AUTOCONNECT",
        "connection",
        "show",
    ])
    .await?;
    let mut profiles = Vec::new();
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        let fields = split_nmcli(line);
        if fields.len() < 5 {
            continue;
        }
        let name = fields[0].clone();
        let details = run(&["-t", "-g", "ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.route-metric,ipv4.dns,ipv4.dns-search,ipv4.routes", "connection", "show", &name]).await.with_context(|| format!("failed to load NetworkManager profile {name}"))?;
        let values: Vec<String> = details.lines().map(str::trim).map(str::to_string).collect();
        let routes = values.get(6).map(|v| parse_routes(v)).unwrap_or_default();
        let runtime_addresses = runtime_addresses(&fields[2]).await.unwrap_or_default();
        profiles.push(Profile {
            name,
            kind: fields[1].clone(),
            device: fields[2].clone(),
            state: fields[3].clone(),
            autoconnect: fields[4].clone(),
            ipv4_method: values.first().cloned().unwrap_or_default(),
            addresses: values.get(1).map(|v| list_values(v)).unwrap_or_default(),
            gateway: values.get(2).cloned().unwrap_or_default(),
            metric: values.get(3).cloned().unwrap_or_default(),
            dns: values.get(4).map(|v| list_values(v)).unwrap_or_default(),
            search: values.get(5).map(|v| list_values(v)).unwrap_or_default(),
            routes,
            runtime_addresses,
        });
    }
    Ok(profiles)
}

fn parse_routes(value: &str) -> Vec<Route> {
    value
        .split(',')
        .filter_map(|raw| {
            let parts: Vec<_> = raw.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            Some(Route {
                destination: parts[0].to_string(),
                gateway: parts.get(1).unwrap_or(&"").to_string(),
                metric: parts.get(2).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

async fn runtime_addresses(device: &str) -> Result<Vec<String>> {
    if device.is_empty() || device == "--" {
        return Ok(Vec::new());
    }
    let out = Command::new("ip")
        .args(["-j", "addr", "show", "dev", device])
        .output()
        .await?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    let items: Vec<IpAddress> = serde_json::from_slice(&out.stdout)?;
    Ok(items
        .into_iter()
        .flat_map(|i| i.addr_info.into_iter())
        .filter(|a| a.family == "inet")
        .map(|a| format!("{}/{}", a.local, a.prefixlen))
        .collect())
}

pub async fn save_ipv4(
    profile: &Profile,
    method: &str,
    addresses: &str,
    gateway: &str,
    metric: &str,
) -> Result<()> {
    let mut args = vec![
        "connection",
        "modify",
        profile.name.as_str(),
        "ipv4.method",
        method,
        "ipv4.addresses",
        addresses,
        "ipv4.gateway",
        gateway,
        "ipv4.route-metric",
        metric,
    ];
    if method == "auto" {
        args = vec![
            "connection",
            "modify",
            profile.name.as_str(),
            "ipv4.method",
            "auto",
            "ipv4.addresses",
            "",
            "ipv4.gateway",
            "",
            "ipv4.route-metric",
            metric,
        ];
    }
    run(&args).await.map(|_| ())
}

pub async fn save_dns(profile: &Profile, dns: &str, search: &str) -> Result<()> {
    run(&[
        "connection",
        "modify",
        profile.name.as_str(),
        "ipv4.dns",
        dns,
        "ipv4.dns-search",
        search,
    ])
    .await
    .map(|_| ())
}

pub async fn save_autoconnect(profile: &Profile, autoconnect: &str) -> Result<()> {
    run(&[
        "connection",
        "modify",
        profile.name.as_str(),
        "connection.autoconnect",
        autoconnect,
    ])
    .await
    .map(|_| ())
}

pub async fn save_route(profile: &Profile, old: Option<&Route>, route: &Route) -> Result<()> {
    let mut routes = profile.routes.clone();
    if let Some(old) = old {
        if let Some(i) = routes.iter().position(|r| {
            r.destination == old.destination && r.gateway == old.gateway && r.metric == old.metric
        }) {
            routes.remove(i);
        }
    }
    routes.push(route.clone());
    let value = routes
        .iter()
        .map(|r| format!("{} {} {}", r.destination, r.gateway, r.metric))
        .collect::<Vec<_>>()
        .join(",");
    run(&[
        "connection",
        "modify",
        profile.name.as_str(),
        "ipv4.routes",
        &value,
    ])
    .await
    .map(|_| ())
}

pub async fn remove_route(profile: &Profile, route: &Route) -> Result<()> {
    let routes: Vec<_> = profile
        .routes
        .iter()
        .filter(|r| {
            !(r.destination == route.destination
                && r.gateway == route.gateway
                && r.metric == route.metric)
        })
        .collect();
    let value = routes
        .iter()
        .map(|r| format!("{} {} {}", r.destination, r.gateway, r.metric))
        .collect::<Vec<_>>()
        .join(",");
    run(&[
        "connection",
        "modify",
        profile.name.as_str(),
        "ipv4.routes",
        &value,
    ])
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_escaped_nmcli_fields() {
        assert_eq!(
            split_nmcli(r"Office\: wired:ethernet:enp3s0:activated:yes"),
            vec!["Office: wired", "ethernet", "enp3s0", "activated", "yes"]
        );
    }

    #[test]
    fn parses_persistent_routes() {
        let routes = parse_routes("10.20.0.0/16 192.168.10.1 50, 172.16.0.0/12 192.168.10.1 100");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, "10.20.0.0/16");
        assert_eq!(routes[0].metric, "50");
    }

    #[test]
    fn route_validation() {
        assert!(valid_ipv4_cidr("10.20.0.0/16"));
        assert!(valid_ipv4_cidr("default"));
        assert!(!valid_ipv4_cidr("10.20.0.0/33"));
        assert!(valid_ipv4_gateway("192.168.10.1"));
        assert!(valid_ipv4_gateway(""));
        assert!(!valid_ipv4_gateway("not-an-ip"));
        assert!(valid_metric("100"));
        assert!(!valid_metric("fast"));
    }

    #[test]
    fn ipv4_profile_validation() {
        assert!(valid_ipv4_method("auto"));
        assert!(valid_ipv4_method("manual"));
        assert!(!valid_ipv4_method("dhcp"));
        assert!(valid_ipv4_addresses("192.168.10.2/24, 10.0.0.2/8", true));
        assert!(valid_ipv4_addresses("", false));
        assert!(!valid_ipv4_addresses("", true));
        assert!(!valid_ipv4_addresses("192.168.10.2", true));
        assert!(valid_autoconnect("yes"));
        assert!(valid_autoconnect("no"));
        assert!(!valid_autoconnect("sometimes"));
    }

    #[test]
    fn dns_validation_accepts_ipv4_and_ipv6() {
        assert!(valid_dns_servers("1.1.1.1, 2606:4700:4700::1111"));
        assert!(valid_dns_servers(""));
        assert!(!valid_dns_servers("not-a-resolver"));
    }
}
