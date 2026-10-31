# Nmap Security Report Generator

A Python-based cybersecurity lab project that parses existing Nmap XML scan results and generates structured security assessment reports in plain text, JSON, and HTML.

The project demonstrates XML parsing, security-oriented rule evaluation, report generation, input validation, HTML output handling, and automated regression testing.

## Features

- Parses existing Nmap XML scan output.
- Inventories discovered hosts and open ports.
- Applies configurable rules to identify services that warrant security review.
- Assigns preliminary review severity levels: High, Medium, Low, and Informational.
- Generates TXT, JSON, and HTML reports.
- Flags unclassified open services for further investigation.
- Validates report counts, host inventory, severity totals, and expected findings.
- Handles malformed XML and invalid Nmap XML input.
- Includes an HTML-escaping regression test for untrusted hostname data.
- Supports a custom report output directory.

## Project Structure

- `nmap_reporter.py` — Main XML parser and report generator
- `test_reports.py` — Report generation and HTML-escaping tests
- `test_errors.py` — Invalid-input and error-handling tests
- `tests/fixtures/` — Static XML test inputs
- `headers.py` — Separate HTTP assessment exercise
- `.gitignore` — Excludes generated reports, local scan data, and Python cache files

## Requirements

- Python 3
- Nmap, to generate scan data
- Termux or another Python-compatible environment

The report generator processes existing XML files. Nmap does not need to run every time a report is generated.

## Usage

1. Generate scan data

Run Nmap against a system you own or have explicit permission to assess.

Example using localhost:

nmap -sV -oX scan.xml 127.0.0.1

The "-sV" option enables service/version detection, and "-oX" writes the results in XML format.

2. Generate reports

From the project directory:

python nmap_reporter.py scan.xml

The tool generates timestamped TXT, JSON, and HTML reports in the XML file's directory by default.

To choose a different output directory:

python nmap_reporter.py scan.xml --out-dir reports

3. Run automated tests

Run the report-generation tests:

python test_reports.py

These tests cover:

- A scan with no open ports and no findings.
- A recognized development-server service that produces a Medium-severity finding.
- An unclassified open service that produces an Informational finding.
- HTML escaping of hostile hostname input.

The report tests also check consistency between report summaries, host inventories, finding records, and severity totals.

Run the error-handling tests:

python test_errors.py

These tests cover:

- Malformed XML input.
- XML input with an invalid Nmap document root.

The current test suite contains six tests across the two test scripts.

## Output Formats

- TXT: Human-readable assessment summaries.
- JSON: Structured data suitable for further processing.
- HTML: Browser-readable reports for convenient review.

## Limitations

This is a cybersecurity learning and portfolio project, not a replacement for a professional vulnerability scanner.

- Findings are preliminary indicators for investigation, not confirmed vulnerabilities.
- Service identification may be incomplete or inaccurate.
- An open port alone does not establish that a vulnerability exists.
- Results depend on the supplied Nmap XML data and configured rules.
- HTML escaping is tested with a hostile hostname input; this test does not establish that every possible HTML context is secure.
- Findings should be independently verified before making security decisions.

## Authorized Use

Only scan systems you own or have explicit permission to assess.

Keep sensitive scan data and generated reports private unless you have reviewed them and confirmed that they are safe to publish.

## Project Status

An actively developed cybersecurity learning and portfolio project. The current regression suite covers report generation, HTML escaping, malformed XML, and invalid Nmap document roots.
