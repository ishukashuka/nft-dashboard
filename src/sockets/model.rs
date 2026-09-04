#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoint {
    pub address: String,
    pub port: String,
    pub family: String,
}

impl Endpoint {
    pub fn display(&self) -> String {
        if self.address.contains(':') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessOwner {
    pub name: String,
    pub pid: Option<u32>,
    pub fd: Option<u32>,
    pub uid: Option<u32>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketEntry {
    pub protocol: String,
    pub state: String,
    pub local: Endpoint,
    pub remote: Option<Endpoint>,
    pub owners: Vec<ProcessOwner>,
    pub inode: Option<String>,
    pub listening: bool,
}

impl SocketEntry {
    pub fn process_name(&self) -> String {
        self.owners
            .first()
            .map(|o| o.name.clone())
            .unwrap_or_else(|| "(unknown)".into())
    }
    pub fn pid(&self) -> String {
        self.owners
            .first()
            .and_then(|o| o.pid)
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".into())
    }
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.protocol,
            self.local.display(),
            self.remote
                .as_ref()
                .map(|e| e.display())
                .unwrap_or_default(),
            self.pid()
        )
    }
    pub fn matches_filter(&self, query: &str) -> bool {
        let haystack = [
            self.protocol.clone(),
            self.state.clone(),
            self.local.address.clone(),
            self.local.port.clone(),
            self.local.display(),
            self.remote
                .as_ref()
                .map(|e| e.address.clone())
                .unwrap_or_default(),
            self.remote
                .as_ref()
                .map(|e| e.port.clone())
                .unwrap_or_default(),
            self.process_name(),
            self.pid(),
        ]
        .join(" ")
        .to_lowercase();
        haystack.contains(&query.to_lowercase())
    }
}
