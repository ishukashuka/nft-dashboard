use super::{model::SocketEntry, parser::parse_ss};
use anyhow::{bail, Context, Result};
use tokio::process::Command;

async fn run(args: &[&str]) -> Result<String> {
    let out = Command::new("ss")
        .args(args)
        .output()
        .await
        .context("failed to execute ss")?;
    if !out.status.success() || (out.stdout.is_empty() && !out.stderr.is_empty()) {
        let error = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!(if error.is_empty() {
            "ss command failed".into()
        } else {
            error
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub async fn load(listening: bool) -> Result<Vec<SocketEntry>> {
    let output = if listening {
        run(&["-H", "-lntup"]).await?
    } else {
        run(&["-H", "-ntup"]).await?
    };
    Ok(parse_ss(&output, listening))
}
