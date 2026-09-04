use super::model::{Endpoint, ProcessOwner, SocketEntry};

fn endpoint(raw: &str) -> Endpoint {
    let value = raw.trim();
    if let Some(close) = value.rfind(']') {
        let address = value.get(1..close).unwrap_or("").to_string();
        return Endpoint {
            address,
            port: value
                .get(close + 1..)
                .unwrap_or("")
                .trim_start_matches(':')
                .to_string(),
            family: "IPv6".into(),
        };
    }
    if let Some((address, port)) = value.rsplit_once(':') {
        return Endpoint {
            address: address.to_string(),
            port: port.to_string(),
            family: if address.contains(':') {
                "IPv6"
            } else {
                "IPv4"
            }
            .into(),
        };
    }
    Endpoint {
        address: value.to_string(),
        port: "*".into(),
        family: if value.contains(':') { "IPv6" } else { "IPv4" }.into(),
    }
}

fn owner_fields(raw: &str) -> Vec<ProcessOwner> {
    let mut owners = Vec::new();
    let mut cursor = 0;
    while let Some(relative) = raw[cursor..].find("pid=") {
        let pid_start = cursor + relative + 4;
        let pid_end = raw[pid_start..]
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| pid_start + i)
            .unwrap_or(raw.len());
        let pid = raw[pid_start..pid_end].parse().ok();
        let name_end = raw[..pid_start].rfind(",pid=").unwrap_or(pid_start);
        let prefix = &raw[..name_end];
        let name_start = prefix.rfind("(\"").map(|i| i + 2).unwrap_or(prefix.len());
        let name = prefix[name_start..].trim_end_matches('"').to_string();
        let fd = raw[pid_end..]
            .find("fd=")
            .and_then(|i| {
                raw[pid_end + i + 3..]
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
            })
            .and_then(|s| s.parse().ok());
        owners.push(ProcessOwner {
            name,
            pid,
            fd,
            ..Default::default()
        });
        cursor = pid_end;
    }
    owners
}

pub fn parse_line(line: &str, listening: bool) -> Option<SocketEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let protocol = parts[0].to_string();
    let state = parts[1].to_string();
    let local = endpoint(parts[4]);
    let remote = if parts.len() > 5 {
        Some(endpoint(parts[5]))
    } else {
        None
    };
    let metadata = if parts.len() > 6 {
        parts[6..].join(" ")
    } else {
        String::new()
    };
    Some(SocketEntry {
        protocol,
        state,
        local,
        remote,
        owners: owner_fields(&metadata),
        listening,
        ..Default::default()
    })
}

pub fn parse_ss(output: &str, listening: bool) -> Vec<SocketEntry> {
    output
        .lines()
        .filter_map(|line| parse_line(line, listening))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_tcp_listen_with_process() {
        let s = parse_line(
            "tcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=921,fd=6))",
            true,
        )
        .unwrap();
        assert_eq!(s.local.port, "443");
        assert_eq!(s.owners[0].name, "nginx");
        assert_eq!(s.owners[0].pid, Some(921));
    }
    #[test]
    fn ipv6_tcp_listen() {
        let s = parse_line(
            "tcp LISTEN 0 128 [::]:22 [::]:* users:((\"sshd\",pid=812,fd=3))",
            true,
        )
        .unwrap();
        assert_eq!(s.local.family, "IPv6");
        assert_eq!(s.local.address, "::");
    }
    #[test]
    fn udp_socket() {
        let s = parse_line("udp UNCONN 0 0 0.0.0.0:1812 0.0.0.0:*", true).unwrap();
        assert_eq!(s.protocol, "udp");
        assert!(s.owners.is_empty());
    }
    #[test]
    fn established_connection() {
        let s = parse_line(
            "tcp ESTAB 0 0 192.168.1.10:443 203.0.113.20:52901 users:((\"nginx\",pid=921,fd=6))",
            false,
        )
        .unwrap();
        assert_eq!(s.remote.unwrap().port, "52901");
        assert_eq!(s.state, "ESTAB");
    }
    #[test]
    fn socket_without_process() {
        let s = parse_line("tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*", true).unwrap();
        assert_eq!(s.process_name(), "(unknown)");
        assert_eq!(s.pid(), "-");
    }
    #[test]
    fn wildcard_bind() {
        let s = parse_line("tcp LISTEN 0 128 *:3000 *:*", true).unwrap();
        assert_eq!(s.local.address, "*");
        assert_eq!(s.local.port, "3000");
    }
    #[test]
    fn multiple_process_owners() {
        let s = parse_line("tcp ESTAB 0 0 127.0.0.1:1 127.0.0.1:2 users:((\"one\",pid=1,fd=3),(\"two\",pid=2,fd=4))", false).unwrap();
        assert_eq!(s.owners.len(), 2);
        assert_eq!(s.owners[1].pid, Some(2));
    }
}
