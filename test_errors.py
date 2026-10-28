
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTER = ROOT / "nmap_reporter.py"


def run_error_test(name, xml_content, expected_error):
    with tempfile.TemporaryDirectory() as temp_dir:
        xml_file = Path(temp_dir) / "input.xml"
        xml_file.write_text(xml_content, encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(REPORTER),
                str(xml_file),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print(f"FAIL: {name} — expected an error")
            return False

        if expected_error not in result.stderr:
            print(f"FAIL: {name} — expected error not found")
            print(result.stderr)
            return False

        print(f"PASS: {name}")
        return True


def main():
    tests = [
        (
            "Malformed XML",
            "<nmaprun><host>",
            "Invalid XML:",
        ),
        (
            "Wrong XML root",
            "<not_nmap></not_nmap>",
            "Invalid scan file:",
        ),
    ]

    passed = 0

    for name, xml_content, expected_error in tests:
        if run_error_test(name, xml_content, expected_error):
            passed += 1

    print(f"\nResults: {passed} passed, {len(tests) - passed} failed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(main())
