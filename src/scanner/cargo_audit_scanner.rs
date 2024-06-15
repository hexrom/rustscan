use super::{ScanResult, Scanner};
use rustsec::{Database, Report};
use rustsec::report::Settings;
use std::error::Error;
use std::path::PathBuf;

pub struct CargoAuditScanner;

impl Scanner for CargoAuditScanner {
    fn run_scan(&self) -> Result<ScanResult, Box<dyn Error>> {
        // Load the advisory database
        let db = Database::fetch()?;

        // Load the Cargo.lock file
        let lockfile_path = PathBuf::from("Cargo.lock");
        let lockfile = rustsec::lockfile::Lockfile::load(&lockfile_path)?;

        // Set up the audit settings
        let settings = Settings::default();

        // Perform the audit
        let report = Report::generate(&db, &lockfile, &settings);

        // Convert the report to JSON
        let vulnerabilities = serde_json::to_string_pretty(&report)?;

        Ok(ScanResult { vulnerabilities })
    }
}