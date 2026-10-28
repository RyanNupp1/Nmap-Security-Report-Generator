
# Nmap Security Report Generator

A Python-based security lab project that parses Nmap XML scan results and generates structured security assessment reports in TXT, JSON, and HTML formats.

## Features

- Parses Nmap XML scan output.
- Inventories hosts and open ports.
- Applies configurable rules to identify services for security review.
- Assigns review severity levels: High, Medium, Low, and Informational.
- Generates TXT, JSON, and HTML reports.
- Flags unclassified open services for further investigation.
- Includes automated tests for report consistency.

## Project Files

| File | Purpose |
|---|---|
| `nmap_reporter.py` | Main report generator |
| `test_reports.py` | Automated report validation tests |
| `headers.py` | Local HTTP assessment exercise |
| `.gitignore` | Excludes generated reports, scan XML, and Python cache files |

## Requirements

- Python 3
- Nmap, for producing scan data
- Termux or another Python-compatible environment

The report generator itself processes existing Nmap XML files; it does not need to run Nmap for every report.

## Usage

Generate an XML scan of a system you own or are explicitly authorized to test:

```bash
nmap -sV -oX scan.xml 127.0.0.1
```

Generate reports from the XML:

```bash
python nmap_reporter.py scan.xml
```

Run the report validation tests:

```bash
python test_reports.py
```

The test script currently references specific timestamped sample reports. Generate the matching reports first, or update the test configuration when report filenames change.

## Output

The report generator produces:

- A plain-text report for quick review
- A JSON report for structured processing
- An HTML report for browser-based review

## Limitations

This is a learning and portfolio project, not a replacement for a professional vulnerability scanner.

- Findings are preliminary indicators, not confirmed vulnerabilities.
- Service identification can be incomplete or inaccurate.
- An open port does not by itself establish that a vulnerability exists.
- Results depend on the supplied Nmap XML data and configured rules.
- Findings should be manually verified before making security decisions.

## Authorized Use

Use Nmap only on systems you own or have explicit permission to assess. Keep sensitive scan data and generated reports private unless you have verified that they are safe to publish.

## Project Status

Educational security automation project under active development.
