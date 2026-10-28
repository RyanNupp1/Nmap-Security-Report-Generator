
import argparse
import html
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path


SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]

UNKNOWN_RULE = {
    "severity": "Informational",
    "title": "Review unclassified open service",
    "reason": (
        "The open port did not match a configured security review rule. "
        "This does not establish that the service is vulnerable or safe."
    ),
    "recommendation": (
        "Identify the service and confirm that it is required. Verify its "
        "access controls, intended network exposure, and patch status."
    ),
}

# These are screening rules, not vulnerability proofs.
RULES = {
    "telnet": {
        "severity": "High",
        "title": "Review Telnet exposure",
        "reason": (
            "Telnet commonly transmits credentials and session data "
            "without encryption."
        ),
        "recommendation": (
            "Confirm whether Telnet is required. Prefer SSH, restrict "
            "management access, and disable Telnet where unnecessary."
        ),
    },
    "ftp": {
        "severity": "Medium",
        "title": "Review FTP security",
        "reason": (
            "Traditional FTP may transmit credentials and data without "
            "encryption."
        ),
        "recommendation": (
            "Check whether encrypted transfer is required, disable "
            "anonymous access if unnecessary, and restrict network access."
        ),
    },
    "smb": {
        "severity": "Medium",
        "title": "Review SMB exposure",
        "reason": (
            "SMB can expose file shares and administrative functions "
            "if improperly configured."
        ),
        "recommendation": (
            "Review share permissions, patch status, protocol versions, "
            "signing requirements, and network restrictions."
        ),
    },
    "rdp": {
        "severity": "Medium",
        "title": "Review remote desktop exposure",
        "reason": (
            "Remote Desktop is a sensitive management service that "
            "requires strong access controls."
        ),
        "recommendation": (
            "Restrict access to trusted networks or a VPN, enforce "
            "multifactor authentication where available, and keep systems patched."
        ),
    },
    "ssh": {
        "severity": "Low",
        "title": "Review SSH hardening",
        "reason": (
            "SSH is a remote administration service and should be "
            "configured and restricted appropriately."
        ),
        "recommendation": (
            "Review authentication policy, patch level, permitted users, "
            "and network access. Disable unused accounts and methods."
        ),
    },
    "http": {
        "severity": "Low",
        "title": "Review HTTP service exposure",
        "reason": (
            "The scan identifies an HTTP service, but does not establish "
            "whether its content or configuration is secure."
        ),
        "recommendation": (
            "Confirm the service is intended to be reachable. Review "
            "authentication, sensitive content, server configuration, "
            "and whether HTTPS is appropriate."
        ),
    },
    "database": {
        "severity": "Medium",
        "title": "Review database service exposure",
        "reason": (
            "A database listener may expose sensitive data or administrative "
            "functions if accessible to untrusted clients."
        ),
        "recommendation": (
            "Restrict access to authorized application hosts, review "
            "authentication and privileges, and verify patch status."
        ),
    },
    "redis": {
        "severity": "Medium",
        "title": "Review Redis access controls",
        "reason": (
            "An accessible Redis service may expose data or administrative "
            "operations depending on its configuration."
        ),
        "recommendation": (
            "Restrict network access, verify authentication and ACLs, "
            "and ensure the service is not unintentionally exposed."
        ),
    },
    "elasticsearch": {
        "severity": "Medium",
        "title": "Review search service access",
        "reason": (
            "An accessible search or indexing service may expose stored "
            "records or management functions."
        ),
        "recommendation": (
            "Verify authentication, authorization, network restrictions, "
            "and whether the service should be reachable by this host."
        ),
    },
    "dev_server": {
        "severity": "Medium",
        "title": "Review development HTTP server",
        "reason": (
            "The detected service signature suggests a lightweight "
            "development server, which may not be hardened for production."
        ),
        "recommendation": (
            "Confirm the server's purpose and bind address. Stop it when "
            "unused, avoid serving sensitive directories, and use a "
            "hardened deployment configuration where appropriate."
        ),
    },
}


def parse_scan(xml_file):
    """Extract host and open-port information from Nmap XML."""
    root = ET.parse(xml_file).getroot()

    if root.tag != "nmaprun":
        raise ValueError(
            "The XML root element is not 'nmaprun'. "
            "Supply an Nmap-generated XML file."
        )

    hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        address = host.find("address")
        hostname = host.find("./hostnames/hostname")

        ip = (
            address.get("addr", "Unknown")
            if address is not None else "Unknown"
        )
        name = (
            hostname.get("name", "None")
            if hostname is not None else "None"
        )
        state = (
            status.get("state", "Unknown")
            if status is not None else "Unknown"
        )

        ports = []

        for port in host.findall("./ports/port"):
            state_element = port.find("state")
            service_element = port.find("service")

            port_state = (
                state_element.get("state", "unknown")
                if state_element is not None else "unknown"
            )

            if port_state != "open":
                continue

            service = service_element
            ports.append({
                "port": port.get("portid", "unknown"),
                "protocol": port.get("protocol", "unknown"),
                "state": port_state,
                "service": (
                    service.get("name", "unknown")
                    if service is not None else "unknown"
                ),
                "product": (
                    service.get("product", "")
                    if service is not None else ""
                ),
                "version": (
                    service.get("version", "")
                    if service is not None else ""
                ),
                "extra_info": (
                    service.get("extrainfo", "")
                    if service is not None else ""
                ),
            })

        hosts.append({
            "ip": ip,
            "hostname": name,
            "state": state,
            "open_ports": ports,
        })

    return hosts


def identify_rule(port):
    """Return a screening rule for a detected service, if applicable."""
    number = str(port["port"])
    service = port["service"].lower()
    product = port["product"].lower()
    extra = port["extra_info"].lower()
    combined = f"{service} {product} {extra}"

    # More specific rules must come before generic HTTP rules.
    if "simplehttpserver" in combined or "simple http server" in combined:
        return "dev_server"

    if number == "23" or "telnet" in service:
        return "telnet"

    if number == "21" or service == "ftp":
        return "ftp"

    if number in {"139", "445"} or service in {
        "microsoft-ds", "netbios-ssn", "smb"
    }:
        return "smb"

    if number == "3389" or service in {"ms-wbt-server", "rdp"}:
        return "rdp"

    if number == "22" or service == "ssh":
        return "ssh"

    if number in {"3306", "5432", "1433", "1521"} or service in {
        "mysql", "postgresql", "ms-sql-s", "oracle"
    }:
        return "database"

    if number == "6379" or service == "redis":
        return "redis"

    if number == "9200" or "elasticsearch" in combined:
        return "elasticsearch"

    if number in {"80", "443", "8000", "8080", "8443", "8888"} or service in {
        "http", "https", "http-proxy"
    }:
        return "http"

    return None


def make_finding_id(rule_id, host, port):
    """Create a stable, asset-specific ID for a finding."""
    if rule_id != "unknown_service":
        return f"NMAP-{rule_id.upper()}"

    asset = re.sub(r"[^A-Za-z0-9]+", "-", host["ip"]).strip("-")
    protocol = re.sub(
        r"[^A-Za-z0-9]+", "-", port["protocol"]
    ).strip("-")

    return (
        f"NMAP-UNKNOWN-SERVICE-{asset}-"
        f"{protocol}-{port['port']}"
    ).upper()


def build_findings(hosts):
    """Create review findings, including a fallback for unmatched ports."""
    findings = []
    seen = set()

    for host in hosts:
        for port in host["open_ports"]:
            rule_id = identify_rule(port)

            if rule_id is None:
                rule_id = "unknown_service"
                rule = UNKNOWN_RULE
            else:
                rule = RULES[rule_id]

            finding_id = make_finding_id(rule_id, host, port)

            # Prevent duplicate findings for the same asset and rule.
            dedup_key = (
                host["ip"],
                port["protocol"],
                port["port"],
                rule_id,
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            software = " ".join(
                value for value in (
                    port["product"],
                    port["version"],
                    port["extra_info"],
                ) if value
            ) or "Not identified"

            findings.append({
                "id": finding_id,
                "severity": rule["severity"],
                "title": rule["title"],
                "host": host["ip"],
                "hostname": host["hostname"],
                "port": port["port"],
                "protocol": port["protocol"],
                "service": port["service"],
                "software": software,
                "evidence": (
                    f"Open port {port['port']}/{port['protocol']}; "
                    f"service identified as {port['service']}; "
                    f"software: {software}."
                ),
                "reason": rule["reason"],
                "recommendation": rule["recommendation"],
                "status": "Needs verification",
            })

    return findings


def esc(value):
    """Escape untrusted data before adding it to HTML."""
    return html.escape(str(value), quote=True)


def build_html_report(hosts, findings, source_file, generated):
    total_open = sum(len(host["open_ports"]) for host in hosts)
    active_hosts = sum(host["state"] == "up" for host in hosts)
    counts = Counter(item["severity"] for item in findings)

    finding_rows = []

    for finding in findings:
        finding_rows.append(f"""
        <tr>
            <td><span class="severity {esc(finding['severity'].lower())}">
                {esc(finding['severity'])}</span></td>
            <td>
                <strong>{esc(finding['title'])}</strong>
                <p class="muted">{esc(finding['id'])}</p>
            </td>
            <td>{esc(finding['host'])}<br>
                {esc(finding['port'])}/{esc(finding['protocol'])}
                <br>{esc(finding['service'])}
            </td>
            <td>
                <p>{esc(finding['evidence'])}</p>
                <p>{esc(finding['reason'])}</p>
                <strong>Recommended next step</strong>
                <p>{esc(finding['recommendation'])}</p>
            </td>
        </tr>
        """)

    if not finding_rows:
        finding_rows.append("""
        <tr><td colspan="4">
            No open ports were reported in the supplied scan data.
            This does not establish that the system is secure.
        </td></tr>
        """)

    host_sections = []

    for host in hosts:
        rows = []

        for port in host["open_ports"]:
            software = " ".join(
                value for value in (
                    port["product"], port["version"], port["extra_info"]
                ) if value
            ) or "Not identified"

            rows.append(f"""
            <tr>
                <td>{esc(port['port'])}/{esc(port['protocol'])}</td>
                <td>{esc(port['service'])}</td>
                <td>{esc(software)}</td>
            </tr>
            """)

        port_table = (
            "<table><thead><tr><th>Port</th><th>Service</th>"
            "<th>Detected software</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>"
            if rows else
            '<p class="muted">No open ports were reported in the supplied data.</p>'
        )

        host_sections.append(f"""
        <section class="card">
            <h3>{esc(host['hostname'])} ({esc(host['ip'])})</h3>
            <p>Host status: <strong>{esc(host['state'])}</strong></p>
            {port_table}
        </section>
        """)

    if not host_sections:
        host_sections.append('<section class="card">No hosts found.</section>')

    severity_cards = "".join(
        f'<div class="metric"><span>{esc(level)}</span>'
        f'<strong>{counts.get(level, 0)}</strong></div>'
        for level in SEVERITY_ORDER
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nmap Security Assessment</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0; background: #f3f6fb; color: #182230;
    font-family: system-ui, sans-serif; line-height: 1.55;
}}
header {{ background: #14213d; color: white; padding: 28px 18px; }}
main {{ max-width: 1100px; margin: auto; padding: 20px 16px 40px; }}
h1 {{ margin: 0; font-size: clamp(1.5rem, 4vw, 2.2rem); }}
h2 {{ margin-top: 30px; }}
h3 {{ overflow-wrap: anywhere; }}
.card, .metric {{
    background: white; border: 1px solid #dfe5ee;
    border-radius: 12px; padding: 16px; margin: 12px 0;
}}
.summary {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    gap: 10px;
}}
.metric span {{ display: block; color: #667085; }}
.metric strong {{ display: block; font-size: 1.8rem; }}
table {{ width: 100%; border-collapse: collapse; text-align: left; }}
th, td {{ padding: 10px; border-bottom: 1px solid #e2e7ef; vertical-align: top; }}
th {{ background: #f7f9fc; }}
.table-wrap {{ overflow-x: auto; }}
.muted {{ color: #667085; font-size: .9rem; }}
.severity {{
    display: inline-block; padding: 3px 9px; border-radius: 999px;
    font-weight: 700; font-size: .85rem;
}}
.high {{ background: #ffe1e1; color: #9e2020; }}
.medium {{ background: #fff0ce; color: #825000; }}
.low {{ background: #e0edff; color: #204f9b; }}
.informational {{ background: #e9eaf0; color: #414657; }}
.notice {{
    background: #fff8e6; border: 1px solid #f0d99b;
    border-radius: 10px; padding: 15px;
}}
p {{ overflow-wrap: anywhere; }}
@media print {{
    body {{ background: white; }}
    header {{ background: white; color: black; border-bottom: 2px solid #333; }}
    .card, .metric {{ break-inside: avoid; }}
}}
</style>
</head>
<body>
<header>
    <main>
        <h1>Nmap Security Assessment</h1>
        <p>Service inventory and preliminary security review</p>
    </main>
</header>
<main>
    <section class="summary">
        <div class="metric"><span>Hosts in scan</span><strong>{len(hosts)}</strong></div>
        <div class="metric"><span>Hosts reported up</span><strong>{active_hosts}</strong></div>
        <div class="metric"><span>Open ports</span><strong>{total_open}</strong></div>
        <div class="metric"><span>Review findings</span><strong>{len(findings)}</strong></div>
    </section>

    <h2>Finding severity summary</h2>
    <section class="summary">{severity_cards}</section>

    <section class="card">
        <h2>Report details</h2>
        <p><strong>Source:</strong> {esc(source_file)}</p>
        <p><strong>Generated:</strong> {esc(generated)}</p>
        <p><strong>Assessment scope:</strong> Supplied Nmap XML only.</p>
    </section>

    <h2>Security findings</h2>
    <p class="muted">
        Severity indicates a preliminary review priority, not a confirmed
        vulnerability or a measured likelihood of exploitation.
        Informational findings identify open services that need classification.
    </p>
    <section class="card table-wrap">
        <table>
            <thead><tr>
                <th>Severity</th><th>Finding</th><th>Asset</th><th>Evidence and recommendation</th>
            </tr></thead>
            <tbody>{''.join(finding_rows)}</tbody>
        </table>
    </section>

    <h2>Host inventory</h2>
    {''.join(host_sections)}

    <section class="notice">
        <h2>Important limitations</h2>
        <ul>
            <li>Open ports and service banners do not prove a vulnerability.</li>
            <li>Findings require verification against configuration, exposure, and patch status.</li>
            <li>Unclassified open ports require identification, not an assumption of vulnerability.</li>
            <li>Only assess systems you own or are authorized to test.</li>
        </ul>
    </section>
    <p class="muted">Generated locally by the Python Nmap XML report generator.</p>
</main>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate TXT, JSON, and HTML reports from existing Nmap XML."
    )
    parser.add_argument("xml_file", type=Path, help="Existing Nmap XML file")
    parser.add_argument(
        "--out-dir", type=Path,
        help="Output directory (defaults to the XML file's directory)"
    )
    args = parser.parse_args()

    xml_file = args.xml_file.expanduser()

    if not xml_file.is_file():
        parser.error(f"XML file not found: {xml_file}")

    try:
        hosts = parse_scan(xml_file)
    except ET.ParseError as exc:
        parser.error(f"Invalid XML: {exc}")
    except ValueError as exc:
        parser.error(f"Invalid scan file: {exc}")
    except OSError as exc:
        parser.error(f"Could not read XML file: {exc}")

    findings = build_findings(hosts)
    counts = Counter(item["severity"] for item in findings)
    out_dir = (args.out_dir or xml_file.parent).expanduser()

    now = datetime.now()
    generated = now.isoformat(timespec="seconds")
    base = f"{xml_file.stem}_report_{now.strftime('%Y%m%d_%H%M%S')}"

    total_open = sum(len(host["open_ports"]) for host in hosts)

    lines = [
        "NMAP SECURITY ASSESSMENT REPORT",
        "=" * 32,
        f"Source file: {xml_file.resolve()}",
        f"Generated: {generated}",
        f"Hosts in scan: {len(hosts)}",
        f"Open ports found: {total_open}",
        f"Security review findings: {len(findings)}",
        "",
        "FINDINGS SUMMARY",
    ]

    for level in SEVERITY_ORDER:
        lines.append(f"{level}: {counts.get(level, 0)}")

    lines.extend(["", "SECURITY FINDINGS"])

    if not findings:
        lines.append(
            "No open ports were reported. This does not prove security."
        )

    for finding in findings:
        lines.extend([
            "",
            f"[{finding['severity']}] {finding['title']}",
            f"Finding ID: {finding['id']}",
            f"Asset: {finding['host']}:{finding['port']}/{finding['protocol']}",
            f"Service: {finding['service']}",
            f"Evidence: {finding['evidence']}",
            f"Reason: {finding['reason']}",
            f"Recommendation: {finding['recommendation']}",
            f"Status: {finding['status']}",
        ])

    lines.extend(["", "HOST INVENTORY"])

    for host in hosts:
        lines.extend([
            "",
            f"Host: {host['hostname']} ({host['ip']})",
            f"Host status: {host['state']}",
        ])

        if not host["open_ports"]:
            lines.append("No open ports reported in supplied scan data.")

        for port in host["open_ports"]:
            software = " ".join(
                value for value in (
                    port["product"], port["version"], port["extra_info"]
                ) if value
            ) or "Not identified"

            lines.append(
                f"  {port['port']}/{port['protocol']} | "
                f"{port['service']} | {software}"
            )

    lines.extend([
        "",
        "LIMITATIONS",
        "- Findings are preliminary screening indicators, not confirmed vulnerabilities.",
        "- Verify service configuration, exposure, and patch status.",
        "- Unclassified open ports receive informational review findings.",
        "- Findings are limited to the supplied Nmap XML.",
        "",
    ])

    json_data = {
        "source_file": str(xml_file.resolve()),
        "generated": generated,
        "host_count": len(hosts),
        "open_port_count": total_open,
        "finding_count": len(findings),
        "severity_counts": {
            level: counts.get(level, 0) for level in SEVERITY_ORDER
        },
        "findings": findings,
        "hosts": hosts,
    }

    try:
        out_dir.mkdir(parents=True, exist_ok=True)

        text_path = out_dir / f"{base}.txt"
        json_path = out_dir / f"{base}.json"
        html_path = out_dir / f"{base}.html"

        text_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        json_path.write_text(
            json.dumps(json_data, indent=2), encoding="utf-8"
        )
        html_path.write_text(
            build_html_report(
                hosts, findings, str(xml_file.resolve()), generated
            ),
            encoding="utf-8",
        )

    except OSError as exc:
        parser.error(f"Could not write reports: {exc}")

    print("\n".join(lines))
    print("\nReports generated successfully:")
    print(f"TXT:  {text_path}")
    print(f"JSON: {json_path}")
    print(f"HTML: {html_path}")


if __name__ == "__main__":
    main()
