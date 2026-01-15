# SimpleVulnScan

SimpleVulnScan is a vulnerability scanner developed in Python.  
It identifies known vulnerabilities (CVEs) by comparing installed software versions against public vulnerability databases.

⚠️ **Work in progress**: some features are partial, experimental, instable or subject to change.

---

## Project Goals

- Audit installed software and dependencies
- Identify known vulnerabilities (CVEs)
- Assess severity using CVSS scores
- Classify vulnerabilities by risk level
- Provide remediation recommendations

This project has an **educational and experimental purpose**, focused on security and cybersecurity learning.

---

## Current Features

- Retrieval of installed package versions (Python environments and/or system packages)
- Querying vulnerability databases (CVE / NVD)
- Version comparison against known vulnerable ranges
- Identification of affected packages
- Vulnerability classification by severity (low, medium, high, critical)

---

## Planned Features

- Local CVE database (JSON)
- Extended support for package managers (apt, yum, pacman)
- Report generation (text, JSON, CSV)
- Automated update and remediation suggestions
- Improved version comparison accuracy

---

## Requirements

- Python 3.9 or higher
- Python environment with required dependencies

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ismagoat/Simple-VulnScan.git
cd Simple-VulnScan

# Install dependencies
pip install -r requirements.txt
```

---

## Usage Manual

```bash
python main.py
```

Depending on the current configuration:

- The script analyzes installed packages
- Compares their versions against vulnerability databases
- Displays detected vulnerabilities with their severity levels

Results are displayed directly in the terminal.

---

## Current Limitations

- Partial software coverage
- Dependency on external CVE sources
- Possible false positives
- Not intended for production use

---

## License

This project is **free and open source**.

You are allowed to:
- Use the project
- Modify it
- Redistribute it
- Integrate it into other projects

No warranty is provided. The author cannot be held responsible for improper use.

---

## Disclaimer

SimpleVulnScan is an educational tool. It does not replace a professional security audit or enterprise-grade vulnerability scanners.

