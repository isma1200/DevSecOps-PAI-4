import os
import sys
import uuid
import json
import urllib.request
import urllib.error
from pathlib import Path

DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").strip().rstrip("/")
if not DEFECTDOJO_URL:
    DEFECTDOJO_URL = "http://localhost:8080"

DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "").strip()
ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1").strip() or "1"
PRODUCT_NAME = os.environ.get("DEFECTDOJO_PRODUCT_NAME", "OWASP NodeGoat")
ENGAGEMENT_NAME = os.environ.get("DEFECTDOJO_ENGAGEMENT_NAME", "Pipeline DevSecOps - main")

REPORTS_MAP = [
    ("reports/semgrep-report.json", "Semgrep JSON Report", "SAST - Semgrep"),
    ("reports/dependency-check-report.xml", "Dependency Check Scan", "SCA - OWASP Dependency-Check"),
    ("reports/checkov-report.json", "Checkov Scan", "IaC - Checkov"),
    ("reports/zap-report.xml", "ZAP Scan", "DAST - OWASP ZAP"),
]

def build_multipart(fields: dict, file_field: str, filename: str, file_bytes: bytes):
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    body = bytearray()

    for k, v in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{v}\r\n".encode("utf-8"))

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode("utf-8")
    )
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    content_type = f"multipart/form-data; boundary={boundary}"
    return bytes(body), content_type

def get_or_confirm_engagement_id() -> str:
    """Verifica si el engagement existe; si no, busca el primer engagement disponible en DefectDojo."""
    req = urllib.request.Request(
        f"{DEFECTDOJO_URL}/api/v2/engagements/",
        headers={"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = data.get("results", [])
            for eng in results:
                if str(eng.get("id")) == str(ENGAGEMENT_ID):
                    return str(ENGAGEMENT_ID)
            if results:
                first_id = str(results[0].get("id"))
                print(f"[*] Usando Engagement ID detectado automáticamente en DefectDojo: {first_id}")
                return first_id
    except Exception as e:
        print(f"[!] Aviso al consultar engagements ({e}), usando ID={ENGAGEMENT_ID}")
    return ENGAGEMENT_ID

def upload_to_defectdojo(file_path: str, scan_type: str, test_title: str, eng_id: str):
    path = Path(file_path)
    if not path.exists():
        print(f"[!] Informe no encontrado ({file_path}), omitiendo {test_title}.")
        return

    fields = {
        "scan_type": scan_type,
        "engagement": eng_id,
        "test_title": test_title,
        "active": "true",
        "verified": "false",
        "close_old_findings": "true",
        "minimum_severity": "Info",
    }

    body, content_type = build_multipart(fields, "file", path.name, path.read_bytes())
    url = f"{DEFECTDOJO_URL}/api/v2/reimport-scan/"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {DEFECTDOJO_API_KEY}",
            "Content-Type": content_type,
        },
    )

    print(f"[*] Subiendo {file_path} ({scan_type}) a {url} (Engagement ID: {eng_id})...")
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            print(f"✅ [OK] {test_title} importado correctamente en DefectDojo (Test ID: {res_json.get('test')}).")
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        print(f"⚠️ [AVISO HTTP {e.code}] Al importar {test_title}: {err_msg}")
    except Exception as e:
        print(f"⚠️ [AVISO RED] No se pudo conectar con DefectDojo en {DEFECTDOJO_URL}: {e}")

if __name__ == "__main__":
    if not DEFECTDOJO_API_KEY:
        print("⚠️ [AVISO] El secreto DEFECTDOJO_API_KEY está vacío en GitHub (Settings -> Secrets -> Actions).")
        sys.exit(0)

    real_eng_id = get_or_confirm_engagement_id()
    for report_file, scan_type, title in REPORTS_MAP:
        upload_to_defectdojo(report_file, scan_type, title, real_eng_id)