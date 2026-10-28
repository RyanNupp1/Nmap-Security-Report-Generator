# Nmap Security Report Generator

A Python-based cybersecurity lab project that parses Nmap XML scan results and generates structured security assessment reports in plain text, JSON, and HTML.

The project demonstrates XML parsing, security-oriented rule evaluation, report generation, and automated regression testing.

Features

- Parses existing Nmap XML scan output.
- Inventories discovered hosts and open ports.
- Applies configurable rules to identify services that warrant security review.
- Assigns review severity levels: High, Medium, Low, and Informational.
- Generates TXT, JSON, and HTML reports.
- Flags unclassified open services for further investigation.
- Validates report counts, host inventory, severity totals, and expected findings through automated tests.

## Project Structure

| File or directory | Purpose |
|---|---|
| `nmap_reporter.py` | Main report generator |
| `test_reports.py` | Automated regression tests |
| `tests/fixtures/` | Static XML test inputs |
| `headers.py` | HTTP assessment exercise |
| `.gitignore` | Excludes generated reports, local scan data, and Python cache files |

## Requirements

- Python 3
- Nmap, to generate scan data
- Termux or another Python-compatible environment

The report generator processes existing XML files. Nmap does not need to run every time a report is generated.

## Usage

1. Generate scan data

Run Nmap against a system you own or are explicitly authorized to test.

Example using localhost:

nmap -sV -oX scan.xml 127.0.0.1

The "-sV" option enables service/version detection, and "-oX" writes the results in XML format.

2. Generate reports

From the project directory, run:

python nmap_reporter.py scan.xml

The tool processes the supplied XML and generates timestamped TXT, JSON, and HTML reports. Generated report filenames include the input scan's base name and a timestamp.

3. Run the regression tests

Run:

python -m py_compile test_reports.py
python test_reports.py

The tests use the XML fixtures included in "tests/fixtures/" and validate three scenarios:

- A scan with no open ports and no findings.
- A recognized development-server service that produces a Medium-severity finding.
- An unclassified open service that produces an Informational finding.

The tests also check consistency between report summaries, host inventories, finding records, and severity totals.

A successful run should report:

Results: 3 passed, 0 failed

## Output Formats

The report generator produces three formats:

- TXT: Human-readable assessment summaries.
- JSON: Structured data suitable for further processing.
- HTML: Browser-readable reports for convenient review.

## Limitations

This is a cybersecurity learning and portfolio project, not a replacement for a professional vulnerability scanner.

- Findings are preliminary indicators for investigation, not confirmed vulnerabilities.
- Service identification may be incomplete or inaccurate.
- An open port alone does not establish that a vulnerability exists.
- Results depend on the supplied Nmap XML data and the configured rules.
- Findings should be independently verified before making security decisions.

## Authorized Use

Only scan systems you own or have explicit permission to assess. Keep sensitive scan data and generated reports private unless you have reviewed them and confirmed that they are safe to publish.

## Project Status

An actively developed learning and portfolio project. The current regression suite covers three XML input scenarios. Additional test cases, documentation, and rule validation can be added as the project evolves.
