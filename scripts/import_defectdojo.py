import os
import sys
import uuid
import json
import datetime
import urllib.request
import urllib.error
from pathlib import Path

# Limpieza de variables de entorno / secretos
RAW_URL = os.environ.get("DEFECTDOJO_URL", "http://localhost:8080").strip().rstrip("/")
RAW_KEY = os.environ.get("DEFECTDOJO_API_KEY", "").strip()
# Si el usuario pegó "Token xxxx" en el secreto, extraemos solo la clave
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

def resolve_defectdojo_url() -> str:
    """Detecta automáticamente la URL accesible de DefectDojo desde WSL o Windows."""
    candidates = []
    if RAW_URL:
        candidates.append(RAW_URL)
    for fallback in ["http://localhost:8080", "http://127.0.0.1:8080", "http://host.docker.internal:8080"]:
        if fallback not in candidates:
            candidates.append(fallback)

    # También añadimos la IP del host Windows vista desde WSL (/etc/resolv.conf)
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
            req = urllib.request.Request(
                f"{url}/api/v2/engagements/",
                headers={"Authorization": f"Token {DEFECTDOJO_API_KEY}"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    print(f"[+] Conexión verificada con DefectDojo en: {url}")
                    return url
        except urllib.error.HTTPError as e:
            print(f"[!] DefectDojo respondió en {url} con HTTP {e.code}. Revisa DEFECTDOJO_API_KEY.")
            return url
        except Exception:
            continue

    print(f"[!] No se pudo contactar automáticamente; usando URL por defecto: {candidates[0]}")
    return candidates[0]

def get_valid_engagement(base_url: str) -> tuple:
    """Obtiene el (engagement_id, product_name, engagement_name) real existente en DefectDojo."""
    headers = {
        "Authorization": f"Token {DEFECTDOJO_API_KEY}",
        "Content-Type": "application/json"
    }
    try:
        req = urllib.request.Request(f"{base_url}/api/v2/engagements/?limit=50", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            engs = json.loads(resp.read().decode("utf-8")).get("results", [])

        target_eng = None
        for e in engs:
            if str(e.get("id")) == str(ENGAGEMENT_ID):
                target_eng = e
                break
        if not target_eng and engs:
            target_eng = engs[0]

        if target_eng:
            eng_id = str(target_eng["id"])
            eng_name = target_eng.get("name", "Pipeline DevSecOps - main")
            prod_id = target_eng.get("product")
            prod_name = "OWASP NodeGoat"
            if prod_id:
                req_p = urllib.request.Request(f"{base_url}/api/v2/products/{prod_id}/", headers=headers)
                with urllib.request.urlopen(req_p, timeout=10) as resp_p:
                    prod_name = json.loads(resp_p.read().decode("utf-8")).get("name", prod_name)
            print(f"[+] Compromiso detectado -> ID: {eng_id} | Activo: '{prod_name}' | Compromiso: '{eng_name}'")
            return eng_id, prod_name, eng_name
    except Exception as e:
        print(f"[!] Error consultando engagements existentes: {e}")

    return ENGAGEMENT_ID, "OWASP NodeGoat", "Pipeline DevSecOps - main"

def build_multipart(fields: dict, file_field: str, filename: str, file_bytes: bytes):
    boundary = f"----DojoBoundary{uuid.uuid4().hex}"
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

    return bytes(body), f"multipart/form-data; boundary={boundary}"

def upload_scan(base_url: str, file_path: str, scan_type: str, test_title: str, eng_id: str, prod_name: str, eng_name: str):
    path = Path(file_path)
    if not path.exists():
        print(f"❌ [ERROR] No existe el archivo local {file_path}")
        return False

    today = datetime.date.today().isoformat()

    # 1. Intentamos primero reimport-scan con todos los campos que exige DefectDojo v2
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

    body, content_type = build_multipart(reimport_fields, "file", path.name, path.read_bytes())
    req = urllib.request.Request(
        f"{base_url}/api/v2/reimport-scan/",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Token {DEFECTDOJO_API_KEY}",
            "Content-Type": content_type,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            res_json = json.loads(resp.read().decode("utf-8"))
            print(f"✅ [OK - reimport-scan] '{test_title}' subido a DefectDojo (Test ID: {res_json.get('test')}).")
            return True
    except urllib.error.HTTPError as e:
        err_text = e.read().decode("utf-8", errors="ignore")
        print(f"[*] reimport-scan devolvió HTTP {e.code} ({err_text[:120]}). Probando import-scan directo por ID de compromiso...")

    # 2. Respaldo garantizado: import-scan directo contra el Engagement ID numérico
    import_fields = {
        "scan_type": scan_type,
        "engagement": eng_id,
        "test_title": test_title,
        "scan_date": today,
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
    }
    body2, content_type2 = build_multipart(import_fields, "file", path.name, path.read_bytes())
    req2 = urllib.request.Request(
        f"{base_url}/api/v2/import-scan/",
        data=body2,
        method="POST",
        headers={
            "Authorization": f"Token {DEFECTDOJO_API_KEY}",
            "Content-Type": content_type2,
        },
    )

    try:
        with urllib.request.urlopen(req2, timeout=60) as resp2:
            res_json2 = json.loads(resp2.read().decode("utf-8"))
            print(f"✅ [OK - import-scan] '{test_title}' subido a DefectDojo (Test ID: {res_json2.get('test')}).")
            return True
    except urllib.error.HTTPError as e2:
        err_text2 = e2.read().decode("utf-8", errors="ignore")
        print(f"❌ [ERROR HTTP {e2.code}] Falló la subida de '{test_title}': {err_text2}")
        return False
    except Exception as ex:
        print(f"❌ [ERROR RED] Falló la conexión al subir '{test_title}': {ex}")
        return False

if __name__ == "__main__":
    if not DEFECTDOJO_API_KEY:
        print("❌ [ERROR CRÍTICO] El secreto DEFECTDOJO_API_KEY está vacío. Configúralo en GitHub -> Settings -> Secrets and variables -> Actions.")
        sys.exit(1)

    base_url = resolve_defectdojo_url()
    eng_id, prod_name, eng_name = get_valid_engagement(base_url)

    all_ok = True
    for report_file, scan_type, title in REPORTS_MAP:
        ok = upload_scan(base_url, report_file, scan_type, title, eng_id, prod_name, eng_name)
        if not ok:
            all_ok = False

    if not all_ok:
        sys.exit(1)