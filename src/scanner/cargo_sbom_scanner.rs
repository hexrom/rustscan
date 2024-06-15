use super::{ScanResult, Scanner};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::process::Command;

pub struct CargoSbomScanner;

#[derive(Serialize, Deserialize, Debug)]
struct OSVRequest {
    version: String,
    package: Package,
}

#[derive(Serialize, Deserialize, Debug)]
struct Package {
    ecosystem: String,
    name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct OSVResponse {
    vulnerabilities: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Vulnerability {
    id: String,
    summary: String,
    details: String,
    severity: Option<String>,
    affected: Vec<Affected>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Affected {
    versions: Vec<String>,
}

impl Scanner for CargoSbomScanner {
    fn run_scan(&self) -> Result<ScanResult, Box<dyn Error>> {
        // Run `cargo sbom` to generate SBOM
        let output = Command::new("cargo")
            .arg("sbom")
            .arg("--output-format")
            .arg("spdx")
            .arg("--output")
            .arg("sbom.spdx")
            .output()
            .expect("Failed to execute cargo sbom");

        if !output.status.success() {
            return Err(format!(
                "Failed to generate SBOM: {}",
                String::from_utf8_lossy(&output.stderr)
            ).into());
        }

        // Read the generated SBOM
        let mut sbom_file = File::open("sbom.spdx")?;
        let mut sbom_contents = String::new();
        sbom_file.read_to_string(&mut sbom_contents)?;

        // Parse SBOM and create OSV requests
        let osv_requests = parse_sbom_to_osv_requests(&sbom_contents)?;

        // Send requests to OSV and collect vulnerabilities
        let vulnerabilities = query_osv(&osv_requests)?;

        // Convert vulnerabilities to JSON
        let vulnerabilities_json = serde_json::to_string_pretty(&vulnerabilities)?;

        Ok(ScanResult {
            vulnerabilities: vulnerabilities_json,
        })
    }
}

fn parse_sbom_to_osv_requests(sbom: &str) -> Result<Vec<OSVRequest>, Box<dyn Error>> {
    // For simplicity, this function assumes SBOM format and parsing logic
    // Implement parsing logic as per the actual SBOM format
    let mut osv_requests = Vec::new();

    // Example parsing logic (to be replaced with actual logic)
    osv_requests.push(OSVRequest {
        version: "1.0.0".to_string(),
        package: Package {
            ecosystem: "Cargo".to_string(),
            name: "example-crate".to_string(),
        },
    });

    Ok(osv_requests)
}

fn query_osv(requests: &[OSVRequest]) -> Result<OSVResponse, Box<dyn Error>> {
    let client = Client::new();
    let mut vulnerabilities = Vec::new();

    for request in requests {
        let response: OSVResponse = client
            .post("https://api.osv.dev/v1/query")
            .json(request)
            .send()?
            .json()?;

        vulnerabilities.extend(response.vulnerabilities);
    }

    Ok(OSVResponse { vulnerabilities })
}

