use crate::{FirewallChain, TextField, VimMode};
use anyhow::{bail, Context, Result};
use std::process::Stdio;
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainOperation {
    Add,
    Edit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainDestructiveAction {
    Flush,
    Delete,
}

pub(crate) struct ChainForm {
    pub(crate) operation: ChainOperation,
    pub(crate) field_idx: usize,
    pub(crate) vim_mode: VimMode,
    pub(crate) family: String,
    pub(crate) table: String,
    pub(crate) original_name: String,
    pub(crate) original_policy: String,
    pub(crate) name: TextField,
    pub(crate) base_chain: bool,
    pub(crate) chain_type: TextField,
    pub(crate) hook: TextField,
    pub(crate) priority: TextField,
    pub(crate) policy: TextField,
    pub(crate) device: TextField,
}

impl ChainForm {
    pub(crate) fn new(family: &str, table: &str) -> Self {
        Self {
            operation: ChainOperation::Add,
            field_idx: 0,
            vim_mode: VimMode::Normal,
            family: family.into(),
            table: table.into(),
            original_name: String::new(),
            original_policy: String::new(),
            name: TextField::default(),
            base_chain: false,
            chain_type: TextField::from("filter"),
            hook: TextField::from("input"),
            priority: TextField::from("filter"),
            policy: TextField::from("accept"),
            device: TextField::default(),
        }
    }

    pub(crate) fn edit(chain: &FirewallChain) -> Self {
        let policy = if chain.hook.is_empty() || !chain.policy.is_empty() {
            chain.policy.as_str()
        } else {
            "accept"
        };
        Self {
            operation: ChainOperation::Edit,
            field_idx: 0,
            vim_mode: VimMode::Normal,
            family: chain.family.clone(),
            table: chain.table.clone(),
            original_name: chain.name.clone(),
            original_policy: policy.into(),
            name: TextField::from(&chain.name),
            base_chain: !chain.hook.is_empty(),
            chain_type: TextField::from(&chain.chain_type),
            hook: TextField::from(&chain.hook),
            priority: TextField::from(&chain.priority),
            policy: TextField::from(policy),
            device: TextField::default(),
        }
    }

    pub(crate) fn field_count(&self) -> usize {
        if self.operation == ChainOperation::Edit {
            if self.base_chain {
                2
            } else {
                1
            }
        } else if self.base_chain {
            7
        } else {
            2
        }
    }

    pub(crate) fn next_field(&mut self) {
        self.field_idx = (self.field_idx + 1) % self.field_count();
    }

    pub(crate) fn previous_field(&mut self) {
        self.field_idx = if self.field_idx == 0 {
            self.field_count() - 1
        } else {
            self.field_idx - 1
        };
    }

    pub(crate) fn active_field_mut(&mut self) -> Option<&mut TextField> {
        let actual = self.actual_field_index();
        match actual {
            0 => Some(&mut self.name),
            2 => Some(&mut self.chain_type),
            3 => Some(&mut self.hook),
            4 => Some(&mut self.priority),
            5 => Some(&mut self.policy),
            6 => Some(&mut self.device),
            _ => None,
        }
    }

    pub(crate) fn actual_field_index(&self) -> usize {
        if self.operation == ChainOperation::Edit && self.base_chain && self.field_idx == 1 {
            5
        } else {
            self.field_idx
        }
    }

    pub(crate) fn cycle_selector(&mut self, direction: isize) {
        match self.actual_field_index() {
            1 if self.operation == ChainOperation::Add => {
                self.base_chain = !self.base_chain;
                self.field_idx = self.field_idx.min(self.field_count() - 1);
            }
            5 => {
                let next = if self.policy.value == "drop" {
                    "accept"
                } else {
                    "drop"
                };
                self.policy = TextField::from(next);
            }
            _ => {
                let _ = direction;
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_family(&self.family)?;
        validate_identifier(&self.table, "table")?;
        validate_identifier(self.name.value.trim(), "chain")?;

        if self.operation == ChainOperation::Add && self.base_chain {
            validate_word(self.chain_type.value.trim(), "chain type")?;
            validate_word(self.hook.value.trim(), "hook")?;
            validate_priority(self.priority.value.trim())?;
            validate_policy(self.policy.value.trim())?;
            if self.family == "netdev"
                && matches!(self.hook.value.trim(), "ingress" | "egress")
                && self.device.value.trim().is_empty()
            {
                bail!("netdev ingress and egress chains require a device");
            }
            if !self.device.value.trim().is_empty() {
                validate_identifier(self.device.value.trim(), "device")?;
            }
        } else if self.operation == ChainOperation::Edit && self.base_chain {
            validate_policy(self.policy.value.trim())?;
        }
        Ok(())
    }

    pub(crate) fn review(&self) -> String {
        if self.operation == ChainOperation::Add {
            if self.base_chain {
                format!(
                    "Create base chain {}/{} > {}\n\nType: {}\nHook: {}\nPriority: {}\nPolicy: {}\nDevice: {}{}",
                    self.family,
                    self.table,
                    self.name.value.trim(),
                    self.chain_type.value.trim(),
                    self.hook.value.trim(),
                    self.priority.value.trim(),
                    self.policy.value.trim(),
                    if self.device.value.trim().is_empty() { "-" } else { self.device.value.trim() },
                    if self.policy.value.trim() == "drop" {
                        "\n\nWARNING: unmatched traffic will be dropped."
                    } else {
                        ""
                    },
                )
            } else {
                format!(
                    "Create regular chain {}/{} > {}",
                    self.family,
                    self.table,
                    self.name.value.trim()
                )
            }
        } else if self.base_chain {
            format!(
                "Edit base chain {}/{} > {}\n\nName: {} -> {}\nPolicy: {} -> {}\n{}\nType, hook and priority remain unchanged.",
                self.family,
                self.table,
                self.original_name,
                self.original_name,
                self.name.value.trim(),
                display_optional(&self.original_policy),
                display_optional(self.policy.value.trim()),
                if self.policy.value.trim() == "drop" {
                    "\nWARNING: unmatched traffic will be dropped."
                } else {
                    ""
                },
            )
        } else {
            format!(
                "Rename regular chain {}/{}\n\n{} -> {}",
                self.family,
                self.table,
                self.original_name,
                self.name.value.trim()
            )
        }
    }

    fn script(&self) -> String {
        let family = &self.family;
        let table = quote(self.table.trim());
        let name = quote(self.name.value.trim());
        if self.operation == ChainOperation::Add {
            if !self.base_chain {
                return format!("add chain {family} {table} {name}\n");
            }
            let device = if self.device.value.trim().is_empty() {
                String::new()
            } else {
                format!(" device {}", quote(self.device.value.trim()))
            };
            return format!(
                "add chain {family} {table} {name} {{ type {} hook {}{} priority {}; policy {}; }}\n",
                self.chain_type.value.trim(),
                self.hook.value.trim(),
                device,
                self.priority.value.trim(),
                self.policy.value.trim(),
            );
        }

        let mut script = String::new();
        if self.original_name != self.name.value.trim() {
            script.push_str(&format!(
                "rename chain {family} {table} {} {name}\n",
                quote(&self.original_name)
            ));
        }
        if self.base_chain && self.original_policy != self.policy.value.trim() {
            script.push_str(&format!(
                "add chain {family} {table} {name} {{ policy {}; }}\n",
                self.policy.value.trim()
            ));
        }
        script
    }
}

pub(crate) async fn apply(form: &ChainForm) -> Result<()> {
    form.validate()?;
    let script = form.script();
    if script.is_empty() {
        return Ok(());
    }
    run_script(&script).await
}

pub(crate) async fn flush(chain: &FirewallChain) -> Result<()> {
    run_script(&format!(
        "flush chain {} {} {}\n",
        chain.family,
        quote(&chain.table),
        quote(&chain.name)
    ))
    .await
}

pub(crate) async fn delete(chain: &FirewallChain, flush_first: bool) -> Result<()> {
    let target = format!(
        "{} {} {}",
        chain.family,
        quote(&chain.table),
        quote(&chain.name)
    );
    let script = if flush_first {
        format!("flush chain {target}\ndelete chain {target}\n")
    } else {
        format!("delete chain {target}\n")
    };
    run_script(&script).await
}

async fn run_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start nft")?;
    child
        .stdin
        .as_mut()
        .context("failed to open nft input")?
        .write_all(script.as_bytes())
        .await
        .context("failed to send chain transaction to nft")?;
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(if error.is_empty() {
            "nft rejected the chain transaction".into()
        } else {
            error
        });
    }
    Ok(())
}

fn validate_family(value: &str) -> Result<()> {
    if matches!(value, "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev") {
        Ok(())
    } else {
        bail!("unsupported nftables family '{value}'")
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        bail!("{label} name is required");
    }
    if value.chars().any(char::is_control) {
        bail!("{label} name contains a control character");
    }
    Ok(())
}

fn validate_word(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        bail!("{label} must contain only letters, numbers, or underscores");
    }
    Ok(())
}

fn validate_priority(value: &str) -> Result<()> {
    if value.is_empty()
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '+' | ' ')
        })
    {
        bail!("priority must be a number, name, or name +/- offset");
    }
    Ok(())
}

fn validate_policy(value: &str) -> Result<()> {
    if matches!(value, "accept" | "drop") {
        Ok(())
    } else {
        bail!("policy must be accept or drop")
    }
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn display_optional(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_and_base_chain_scripts_are_complete() {
        let mut form = ChainForm::new("inet", "pintech");
        form.name = TextField::from("services");
        assert_eq!(form.script(), "add chain inet \"pintech\" \"services\"\n");

        form.base_chain = true;
        form.hook = TextField::from("input");
        form.priority = TextField::from("filter - 5");
        assert!(form
            .script()
            .contains("{ type filter hook input priority filter - 5; policy accept; }"));
    }

    #[test]
    fn netdev_ingress_requires_a_device() {
        let mut form = ChainForm::new("netdev", "filter");
        form.name = TextField::from("ingress_filter");
        form.base_chain = true;
        form.hook = TextField::from("ingress");
        assert!(form.validate().is_err());
        form.device = TextField::from("eth0");
        assert!(form.validate().is_ok());
    }

    #[test]
    fn edit_transaction_renames_then_updates_policy() {
        let chain = FirewallChain {
            family: "inet".into(),
            table: "pintech".into(),
            name: "input".into(),
            chain_type: "filter".into(),
            hook: "input".into(),
            priority: "filter".into(),
            policy: "accept".into(),
        };
        let mut form = ChainForm::edit(&chain);
        form.name = TextField::from("host_input");
        form.policy = TextField::from("drop");
        let script = form.script();
        assert!(script.starts_with("rename chain inet \"pintech\" \"input\" \"host_input\""));
        assert!(script.contains("add chain inet \"pintech\" \"host_input\" { policy drop; }"));
    }
}
