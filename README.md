# RustScan
Rust security ccanner aggregator. Use RustScan to scan your Rust project for security vulnerabilities using a number of tools, think of it as a Rust security scan swiss army knife. 

// Build tool  
`cargo build --release`

// Scan Rust project (while in project directory)
`rustscan --scan cargo-audit`  
`rustscan --scan clippy`  
`rustscan --scan cargo-sbom`  

More features and tool support coming soon.
