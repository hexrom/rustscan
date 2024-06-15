use super::{ScanResult, Scanner};
use std::error::Error;
use std::process::Command;

pub struct ClippyScanner;

impl Scanner for ClippyScanner {
    fn run_scan(&self) -> Result<ScanResult, Box<dyn Error>> {
        // Run `cargo clippy` with `suspicious` lints
        let output = Command::new("cargo")
            .arg("clippy")
            .arg("--")
            .arg("-D")
            .arg("clippy::suspicious")
            .output()
            .expect("Failed to execute cargo clippy");

        let vulnerabilities = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).to_string()
        } else {
            String::from_utf8_lossy(&output.stderr).to_string()
        };

        Ok(ScanResult { vulnerabilities })
    }
}

