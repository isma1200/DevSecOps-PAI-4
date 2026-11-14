import os
import sys
import requests
from pathlib import Path

DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "")
ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1")
PRODUCT_NAME = os.environ.get("DEFECTDOJO_PRODUCT_NAME", "OWASP NodeGoat")
ENGAGEMENT_NAME = os.environ.get("DEFECTDOJO_ENGAGEMENT_NAME", "Pipeline DevSecOps - main")

REPORTS_MAP = [
    ("reports/semgrep-report.json", "Semgrep JSON Report", "SAST - Semgrep"),
    ("reports/dependency-check-report.xml", "Dependency Check Scan", "SCA - OWASP Dependency-Check"),
    ("reports/checkov-report.json", "Checkov Scan", "IaC - Checkov"),
    ("reports/zap-report.xml", "ZAP Scan", "DAST - OWASP ZAP"),
]

def upload_to_defectdojo(file_path: str, scan_type: str, test_title: str):
    path = Path(file_path)
    if not path.exists():
        print(f"[!] Informe no encontrado ({file_path}), omitiendo importación de {test_title}.")
        return

    url = f"{DEFECTDOJO_URL}/api/v2/reimport-scan/"
    headers = {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}"
    }
    data = {
        "scan_type": scan_type,
        "product_name": PRODUCT_NAME,
        "engagement_name": ENGAGEMENT_NAME,
        "engagement": ENGAGEMENT_ID,
        "test_title": test_title,
        "active": "true",
        "verified": "false",
        "close_old_findings": "true",
        "auto_create_context": "true",
        "minimum_severity": "Info",
    }

    print(f"[*] Subiendo {file_path} ({scan_type}) a DefectDojo...")
    with path.open("rb") as f:
        files = {"file": (path.name, f)}
        response = requests.post(url, headers=headers, data=data, files=files, timeout=120)

    if response.status_code in (200, 201):
        res_json = response.json()
        print(f"✅ [OK] {test_title} importado correctamente en DefectDojo (Test ID: {res_json.get('test')}).")
    else:
        print(f"❌ [ERROR] Fallo al subir {test_title} (HTTP {response.status_code}): {response.text}")
        sys.exit(1)

if __name__ == "__main__":
    if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
        print("❌ [ERROR] Faltan los secretos DEFECTDOJO_URL o DEFECTDOJO_API_KEY.")
        sys.exit(1)

    for report_file, scan_type, title in REPORTS_MAP:
        upload_to_defectdojo(report_file, scan_type, title)