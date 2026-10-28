import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTER = ROOT / "nmap_reporter.py"

TESTS = [
    {
        "input": "tests/fixtures/no_open_ports.xml",
        "expected_ports": 0,
        "expected_findings": 0,
        "expected_severity": None,
        "expected_id": None,
    },
    {
        "input": "tests/fixtures/scan.xml",
        "expected_ports": 1,
        "expected_findings": 1,
        "expected_severity": "Medium",
        "expected_id": "NMAP-DEV_SERVER",
    },
    {
        "input": "tests/fixtures/unknown_service_test.xml",
        "expected_ports": 1,
        "expected_findings": 1,
        "expected_severity": "Informational",
        "expected_id": (
            "NMAP-UNKNOWN-SERVICE-127-0-0-1-TCP-45678"
        ),
    },
]


def generate_report(test):
    source = ROOT / test["input"]

    if not source.is_file():
        raise FileNotFoundError(
            f"Missing test input: {test['input']}"
        )

    result = subprocess.run(
        [sys.executable, str(REPORTER), str(source)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Reporter failed.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    pattern = f"{source.stem}_report_*.json"
    reports = sorted(ROOT.glob(pattern))

    if not reports:
        raise FileNotFoundError(
            f"No JSON report found matching {pattern}"
        )

    return reports[-1]


def validate_report(test, path):
    errors = []

    try:
        with path.open(encoding="utf-8") as file:
            report = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"Cannot read valid JSON: {exc}"]

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

    if actual_findings != len(findings):
        errors.append(
            "finding_count does not match findings list length"
        )

    inventory_ports = sum(
        len(host.get("open_ports", [])) for host in hosts
    )
    if inventory_ports != actual_ports:
        errors.append(
            "open_port_count does not match host inventory"
        )

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
        found = any(
            finding.get("severity") == expected_severity
            and finding.get("id") == expected_id
            for finding in findings
        )
        if not found:
            errors.append(
                f"Expected finding not found: "
                f"{expected_severity} / {expected_id}"
            )

    return errors


def main():
    if not REPORTER.is_file():
        print(f"FAIL: Reporter not found: {REPORTER.name}")
        return 1

    failures = 0

    for test in TESTS:
        try:
            report_path = generate_report(test)
            errors = validate_report(test, report_path)
        except (OSError, RuntimeError) as exc:
            errors = [str(exc)]
            report_path = None

        if errors:
            failures += 1
            print(f"\nFAIL: {test['input']}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS: {test['input']}")

    passed = len(TESTS) - failures
    print(f"\nResults: {passed} passed, {failures} failed")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
