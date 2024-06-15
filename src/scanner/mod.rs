pub mod cargo_audit_scanner;

use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct ScanResult {
    pub vulnerabilities: String,
}

pub trait Scanner {
    fn run_scan(&self) -> Result<ScanResult, Box<dyn Error>>;
}


