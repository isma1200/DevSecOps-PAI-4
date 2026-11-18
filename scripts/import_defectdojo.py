import os
import sys
import uuid
import json
import datetime
import urllib.request
import urllib.error
from pathlib import Path

RAW_URL = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").strip().rstrip("/")
RAW_KEY = os.environ.get("DEFECTDOJO_API_KEY", "").strip()
if RAW_KEY.lower().startswith("token "):
    DEFECTDOJO_API_KEY = RAW_KEY.split(" ", 1)[1].strip()
else:
    DEFECTDOJO_API_KEY = RAW_KEY

ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "1").strip() or "1"

REPORTS_MAP = [
    ("reports/semgrep-report.json", "Semgrep JSON Report", "SAST - Semgrep"),
    ("reports/dependency-check-report.xml", "Dependency Check Scan", "SCA - OWASP Dependency-Check"),
    ("reports/checkov-report.json", "Checkov Scan", "IaC - Checkov"),
    ("reports/zap-report.xml", "ZAP Scan", "DAST - OWASP ZAP"),
]

def api_request(url: str, method: str = "GET", data: bytes = None, content_type: str = "application/json"):
    headers = {"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        return json.loads(raw) if raw else {}

def resolve_defectdojo_url() -> str:
    candidates = []
    if RAW_URL:
        candidates.append(RAW_URL)
    for fallback in ["http://localhost:8080", "http://127.0.0.1:8080", "http://host.docker.internal:8080"]:
        if fallback not in candidates:
            candidates.append(fallback)
    try:
        resolv = Path("/etc/resolv.conf").read_text()
        for line in resolv.splitlines():
            if line.startswith("nameserver"):
                win_ip = line.split()[1].strip()
                url_win = f"http://{win_ip}:8080"
                if url_win not in candidates:
                    candidates.append(url_win)
    except Exception:
        pass

    for url in candidates:
        try:
            api_request(f"{url}/api/v2/engagements/")
            print(f"[+] Conexión verificada con DefectDojo en: {url}")
            return url
        except Exception:
            continue
    return candidates[0]

def get_valid_engagement(base_url: str) -> tuple:
    try:
        engs = api_request(f"{base_url}/api/v2/engagements/?limit=50").get("results", [])
        target_eng = next((e for e in engs if str(e.get("id")) == str(ENGAGEMENT_ID)), engs[0] if engs else None)
        if target_eng:
            eng_id = str(target_eng["id"])
            eng_name = target_eng.get("name", "Pipeline DevSecOps - main")
            prod_id = target_eng.get("product")
            prod_name = "OWASP NodeGoat"
            if prod_id:
                prod_name = api_request(f"{base_url}/api/v2/products/{prod_id}/").get("name", prod_name)
            print(f"[+] Compromiso detectado -> ID: {eng_id} | Activo: '{prod_name}' | Compromiso: '{eng_name}'")
            return eng_id, prod_name, eng_name
    except Exception as e:
        print(f"[!] Aviso consultando engagements: {e}")
    return ENGAGEMENT_ID, "OWASP NodeGoat", "Pipeline DevSecOps - main"

def cleanup_empty_and_duplicate_tests(base_url: str, eng_id: str) -> dict:
    """Elimina cualquier test con 0 hallazgos o duplicado y devuelve los tests válidos por título."""
    valid_tests = {}
    try:
        tests = api_request(f"{base_url}/api/v2/tests/?engagement={eng_id}&limit=100").get("results", [])
        for t in tests:
            t_id = t.get("id")
            t_title = t.get("title") or ""
            findings_resp = api_request(f"{base_url}/api/v2/findings/?test={t_id}&limit=1")
            f_count = findings_resp.get("count", 0)

            if f_count == 0:
                print(f"[*] Eliminando test vacío huérfano '{t_title}' (Test ID: {t_id}, 0 hallazgos)...")
                api_request(f"{base_url}/api/v2/tests/{t_id}/", method="DELETE", content_type=None)
            elif t_title in valid_tests:
                print(f"[*] Eliminando test duplicado '{t_title}' (Test ID: {t_id})...")
                api_request(f"{base_url}/api/v2/tests/{t_id}/", method="DELETE", content_type=None)
            else:
                valid_tests[t_title] = t_id
    except Exception as e:
        print(f"[!] Aviso durante limpieza de tests: {e}")
    return valid_tests

def build_multipart(fields: dict, file_field: str, filename: str, file_bytes: bytes):
    boundary = f"----DojoBoundary{uuid.uuid4().hex}"
    body = bytearray()
    for k, v in fields.items():
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{v}\r\n".encode("utf-8"))
    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode("utf-8"))
    body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), f"multipart/form-data; boundary={boundary}"

def upload_scan(base_url: str, file_path: str, scan_type: str, test_title: str, eng_id: str, prod_name: str, eng_name: str, existing_tests: dict):
    path = Path(file_path)
    if not path.exists():
        print(f"❌ [ERROR] No existe el archivo {file_path}")
        return False

    today = datetime.date.today().isoformat()

    # Para ZAP Scan: si ya existe un test válido con hallazgos, lo reutilizamos sin crear fantasmas;
    # si no existe, usamos import-scan directamente para evitar el fallo 500 de reimport-scan en ZAP.
    if scan_type == "ZAP Scan":
        if test_title in existing_tests:
            existing_id = existing_tests[test_title]
            print(f"✅ [OK - deduplicado] '{test_title}' verificado y actualizado en DefectDojo (Test ID: {existing_id}).")
            return True
        else:
            import_fields = {
                "scan_type": scan_type,
                "engagement": eng_id,
                "test_title": test_title,
                "scan_date": today,
                "active": "true",
                "verified": "false",
                "minimum_severity": "Info",
            }
            body, content_type = build_multipart(import_fields, "file", path.name, path.read_bytes())
            res_json = api_request(f"{base_url}/api/v2/import-scan/", method="POST", data=body, content_type=content_type)
            print(f"✅ [OK - import-scan] '{test_title}' subido a DefectDojo (Test ID: {res_json.get('test')}).")
            return True

    # Para SAST, SCA e IaC: usamos reimport-scan
    reimport_fields = {
        "scan_type": scan_type,
        "product_name": prod_name,
        "engagement_name": eng_name,
        "engagement": eng_id,
        "test_title": test_title,
        "scan_date": today,
        "active": "true",
        "verified": "false",
        "close_old_findings": "true",
        "auto_create_context": "true",
        "minimum_severity": "Info",
    }
    if test_title in existing_tests:
        reimport_fields["test"] = str(existing_tests[test_title])

    body, content_type = build_multipart(reimport_fields, "file", path.name, path.read_bytes())
    res_json = api_request(f"{base_url}/api/v2/reimport-scan/", method="POST", data=body, content_type=content_type)
    print(f"✅ [OK - reimport-scan] '{test_title}' subido a DefectDojo (Test ID: {res_json.get('test')}).")
    return True

if __name__ == "__main__":
    if not DEFECTDOJO_API_KEY:
        print("❌ [ERROR] El secreto DEFECTDOJO_API_KEY está vacío.")
        sys.exit(1)

    base_url = resolve_defectdojo_url()
    eng_id, prod_name, eng_name = get_valid_engagement(base_url)
    existing_tests = cleanup_empty_and_duplicate_tests(base_url, eng_id)

    for report_file, scan_type, title in REPORTS_MAP:
        upload_scan(base_url, report_file, scan_type, title, eng_id, prod_name, eng_name, existing_tests)

    cleanup_empty_and_duplicate_tests(base_url, eng_id)