
import json
import sys
from pathlib import Path

TESTS = [
    {
        "file": "no_open_ports_report_20261027_211003.json",
        "expected_ports": 0,
        "expected_findings": 0,
        "expected_severity": None,
        "expected_id": None,
    },
    {
        "file": "scan_report_20261027_211003.json",
        "expected_ports": 1,
        "expected_findings": 1,
        "expected_severity": "Medium",
        "expected_id": "NMAP-DEV_SERVER",
    },
    {
        "file": "unknown_service_test_report_20261027_211003.json",
        "expected_ports": 1,
        "expected_findings": 1,
        "expected_severity": "Informational",
        "expected_id": (
            "NMAP-UNKNOWN-SERVICE-127-0-0-1-TCP-45678"
        ),
    },
]


def validate_report(test):
    path = Path(test["file"])
    errors = []

    if not path.exists():
        return [f"Missing file: {path}"]

    try:
        with path.open(encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot read valid JSON from {path}: {exc}"]

    findings = report.get("findings", [])
    hosts = report.get("hosts", [])

    actual_ports = report.get("open_port_count")
    actual_findings = report.get("finding_count")

    if actual_ports != test["expected_ports"]:
        errors.append(
            f"Expected {test['expected_ports']} open ports; "
            f"got {actual_ports}"
        )

    if actual_findings != test["expected_findings"]:
        errors.append(
            f"Expected {test['expected_findings']} findings; "
            f"got {actual_findings}"
        )

    # Confirm the summary agrees with the actual findings.
    if actual_findings != len(findings):
        errors.append(
            "finding_count does not match findings list length"
        )

    if sum(
        len(host.get("open_ports", [])) for host in hosts
    ) != actual_ports:
        errors.append(
            "open_port_count does not match host inventory"
        )

    # Confirm the severity totals match the finding records.
    severity_counts = report.get("severity_counts", {})
    for severity in ("High", "Medium", "Low", "Informational"):
        actual = sum(
            finding.get("severity") == severity
            for finding in findings
        )
        if severity_counts.get(severity) != actual:
            errors.append(
                f"{severity} severity count is inconsistent"
            )

    expected_severity = test["expected_severity"]
    expected_id = test["expected_id"]

    if expected_severity is not None:
        if not any(
            finding.get("severity") == expected_severity
            and finding.get("id") == expected_id
            for finding in findings
        ):
            errors.append(
                f"Expected finding not found: "
                f"{expected_severity} / {expected_id}"
            )

    return errors


def main():
    failures = 0

    for test in TESTS:
        errors = validate_report(test)

        if errors:
            failures += 1
            print(f"\nFAIL: {test['file']}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS: {test['file']}")

    print(f"\nResults: {len(TESTS) - failures} passed, "
          f"{failures} failed")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
