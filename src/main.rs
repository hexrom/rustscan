mod scanner;

use clap::{Arg, Command};
use scanner::{cargo_audit_scanner::CargoAuditScanner, clippy_scanner::ClippyScanner, Scanner};
use serde_json::Value;

fn main() {
    let matches = Command::new("RustScan")
        .version("1.0")
        .author("Your Name <your.email@example.com>")
        .about("Scans a Rust project for vulnerabilities")
        .arg(
            Arg::new("scan")
                .short('s')
                .long("scan")
                .value_parser(["cargo-audit", "clippy"])
                .default_value("cargo-audit")
                .help("Run a security scan using the specified tool"),
        )
        .get_matches();

    let scan_tool = matches.get_one::<String>("scan").map(String::as_str).unwrap_or("cargo-audit");
    let scanner: Box<dyn Scanner> = match scan_tool {
        "clippy" => Box::new(ClippyScanner),
        _ => Box::new(CargoAuditScanner),
    };

    match scanner.run_scan() {
        Ok(result) => {
            if scan_tool == "cargo-audit" {
                let parsed: Value = serde_json::from_str(&result.vulnerabilities).unwrap();
                println!("Scan Results:\n");
                print_vulnerabilities(&parsed);
            } else {
                println!("Scan Results:\n{}", result.vulnerabilities);
            }
        }
        Err(e) => eprintln!("Error running scan: {}", e),
    }
}

fn print_vulnerabilities(v: &Value) {
    if let Some(vulns) = v["vulnerabilities"]["list"].as_array() {
        for vuln in vulns {
            println!("ID: {}", vuln["advisory"]["id"]);
            println!("Package: {}", vuln["advisory"]["package"]);
            println!("Title: {}", vuln["advisory"]["title"]);
            println!("Description: {}", vuln["advisory"]["description"].as_str().unwrap_or("").replace("\\n", "\n"));
            println!("Date: {}", vuln["advisory"]["date"]);
            if let Some(url) = vuln["advisory"]["url"].as_str() {
                println!("More Info: {}", url);
            }
            if let Some(patched) = vuln["versions"]["patched"].as_array() {
                let patched_versions: Vec<String> = patched.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                println!("Patched Versions: {}", patched_versions.join(", "));
            }
            if let Some(unaffected) = vuln["versions"]["unaffected"].as_array() {
                let unaffected_versions: Vec<String> = unaffected.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
                println!("Unaffected Versions: {}", unaffected_versions.join(", "));
            }
            println!("==============================\n");
        }
    } else {
        println!("No vulnerabilities found.");
    }
}


