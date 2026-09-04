use crate::Rule;
use anyhow::{bail, Context, Result};
use std::process::Stdio;
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleMoveDirection {
    Up,
    Down,
}

impl RuleMoveDirection {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuleMovePlan {
    pub(crate) direction: RuleMoveDirection,
    pub(crate) family: String,
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) selected_handle: u64,
    pub(crate) anchor_handle: u64,
    pub(crate) selected_statement: String,
    pub(crate) anchor_statement: String,
    pub(crate) destination_index: usize,
}

impl RuleMovePlan {
    pub(crate) fn build(
        rules: &[Rule],
        selected: &Rule,
        direction: RuleMoveDirection,
    ) -> Result<Self> {
        let chain_rules = rules
            .iter()
            .filter(|rule| {
                rule.family == selected.family
                    && rule.table == selected.table
                    && rule.chain == selected.chain
            })
            .collect::<Vec<_>>();
        let index = chain_rules
            .iter()
            .position(|rule| rule.handle == selected.handle)
            .context("selected rule is no longer present in its chain")?;
        let destination_index = match direction {
            RuleMoveDirection::Up => index
                .checked_sub(1)
                .context("selected rule is already first in the chain")?,
            RuleMoveDirection::Down if index + 1 < chain_rules.len() => index + 1,
            RuleMoveDirection::Down => bail!("selected rule is already last in the chain"),
        };
        let anchor = chain_rules[destination_index];
        let selected_statement = selected
            .exact_expression
            .clone()
            .context("the exact nft statement is unavailable; refresh before moving this rule")?;
        if selected_statement.contains('\n') {
            bail!("multi-line nft statements cannot be moved safely");
        }

        Ok(Self {
            direction,
            family: selected.family.clone(),
            table: selected.table.clone(),
            chain: selected.chain.clone(),
            selected_handle: selected.handle,
            anchor_handle: anchor.handle,
            selected_statement,
            anchor_statement: anchor.expression.clone(),
            destination_index,
        })
    }

    pub(crate) fn preview(&self) -> String {
        format!(
            "Move handle {} {} in {}/{} > {}\n\nSelected:\n{}\n\n{} handle {}:\n{}\n\nThe rule receives a new handle. Visible counter values are restored from the snapshot, but hidden runtime state in stateful expressions may reset.",
            self.selected_handle,
            self.direction.label(),
            self.family,
            self.table,
            self.chain,
            self.selected_statement,
            if self.direction == RuleMoveDirection::Up {
                "Before"
            } else {
                "After"
            },
            self.anchor_handle,
            self.anchor_statement,
        )
    }

    fn script(&self) -> String {
        let command = if self.direction == RuleMoveDirection::Up {
            "insert"
        } else {
            "add"
        };
        format!(
            "{command} rule {} {} {} handle {} {}\ndelete rule {} {} {} handle {}\n",
            self.family,
            self.table,
            self.chain,
            self.anchor_handle,
            self.selected_statement,
            self.family,
            self.table,
            self.chain,
            self.selected_handle,
        )
    }

    pub(crate) async fn apply(&self) -> Result<()> {
        let script = self.script();
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
            .context("failed to send rule move transaction to nft")?;
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_string();
            bail!(if error.is_empty() {
                "nft rejected the rule move transaction".into()
            } else {
                error
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParsedRuleExpr, Verdict};
    use serde_json::Value;

    fn rule(handle: u64, statement: &str) -> Rule {
        Rule {
            family: "inet".into(),
            table: "pintech".into(),
            chain: "input".into(),
            handle,
            parsed: ParsedRuleExpr::default(),
            expression: statement.into(),
            exact_expression: Some(statement.into()),
            verdict: Verdict::Other,
            raw: Value::Array(Vec::new()),
            comment: None,
        }
    }

    #[test]
    fn up_move_inserts_before_neighbor_then_deletes_old_handle() {
        let rules = vec![rule(10, "accept"), rule(20, "drop")];
        let plan = RuleMovePlan::build(&rules, &rules[1], RuleMoveDirection::Up).unwrap();
        assert_eq!(plan.destination_index, 0);
        assert!(plan
            .script()
            .starts_with("insert rule inet pintech input handle 10 drop"));
        assert!(plan.script().ends_with("handle 20\n"));
    }

    #[test]
    fn down_move_adds_after_neighbor_and_guards_boundaries() {
        let rules = vec![rule(10, "accept"), rule(20, "drop")];
        let plan = RuleMovePlan::build(&rules, &rules[0], RuleMoveDirection::Down).unwrap();
        assert_eq!(plan.destination_index, 1);
        assert!(plan
            .script()
            .starts_with("add rule inet pintech input handle 20 accept"));
        assert!(RuleMovePlan::build(&rules, &rules[0], RuleMoveDirection::Up).is_err());
        assert!(RuleMovePlan::build(&rules, &rules[1], RuleMoveDirection::Down).is_err());
    }

    #[test]
    fn exact_statement_is_required() {
        let mut rules = vec![rule(10, "accept"), rule(20, "drop")];
        rules[0].exact_expression = None;
        assert!(RuleMovePlan::build(&rules, &rules[0], RuleMoveDirection::Down).is_err());
    }
}
