import urllib.request
import urllib.error
from datetime import datetime

url = "http://127.0.0.1:8080/"
methods = ["GET", "HEAD", "OPTIONS", "POST"]
results = []

for method in methods:
    request = urllib.request.Request(url, method=method)

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.status
            reason = "Success"
            headers = dict(response.headers.items())

    except urllib.error.HTTPError as error:
        status = error.code
        reason = str(error.reason)
        headers = dict(error.headers.items()) if error.headers else {}

    except urllib.error.URLError as error:
        status = "ERROR"
        reason = str(error.reason)
        headers = {}

    results.append({
        "method": method,
        "status": status,
        "reason": reason,
        "headers": headers
    })

report_path = "http_assessment.txt"

with open(report_path, "w") as report:
    report.write("HTTP Assessment Report\n")
    report.write(f"Target: {url}\n")
    report.write(f"Date: {datetime.now().isoformat()}\n")
    report.write("Scope: Local lab server\n\n")

    for result in results:
        report.write(f"Method: {result['method']}\n")
        report.write(f"Status: {result['status']}\n")
        report.write(f"Result: {result['reason']}\n")

        for name in [
            "Server",
            "Content-Type",
            "Content-Length",
            "Last-Modified"
        ]:
            value = result["headers"].get(name)
            if value:
                report.write(f"{name}: {value}\n")

        report.write("\n")

print(f"Report saved to {report_path}")
print("\n--- Security Observations ---")

server_header = None

for result in results:
    value = result["headers"].get("Server")
    if value:
        server_header = value
        break

if server_header:
    print(f"[INFO] Server identifies itself as: {server_header}")
    print("[NOTE] Version disclosure alone does not prove a vulnerability.")

for result in results:
    if result["status"] == 501:
        print(
            f"[INFO] {result['method']} is unsupported "
            "by this server implementation."
        )

print("[SUMMARY] No confirmed vulnerabilities identified by these tests.")
