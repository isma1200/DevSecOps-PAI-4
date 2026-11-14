import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def check_semgrep(report_path: str, max_high_critical: int = 0) -> int:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    results = data.get("results", [])
    high_crit = [
        r for r in results
        if r.get("extra", {}).get("severity", "").upper() in ("ERROR", "HIGH", "CRITICAL")
    ]
    print(f"[SAST - Semgrep] Total hallazgos: {len(results)} | Alta/Crítica (ERROR): {len(high_crit)}")
    return 1 if len(high_crit) > max_high_critical else 0

def check_checkov(report_path: str, max_failed: int = 0) -> int:
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    reports = data if isinstance(data, list) else [data]
    failed_count = 0
    for rep in reports:
        failed_checks = rep.get("results", {}).get("failed_checks", [])
        failed_count += len(failed_checks)
    print(f"[IaC - Checkov] Controles de infraestructura fallidos: {failed_count}")
    return 1 if failed_count > max_failed else 0

def check_dependency_check(report_path: str, max_high_critical: int = 0) -> int:
    tree = ET.parse(report_path)
    root = tree.getroot()
    ns = {"dc": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    vulns = root.findall(".//dc:vulnerability", ns) if ns else root.findall(".//vulnerability")
    high_crit = 0
    for v in vulns:
        sev_elem = v.find("dc:severity", ns) if ns else v.find("severity")
        if sev_elem is not None and sev_elem.text and sev_elem.text.upper() in ("HIGH", "CRITICAL"):
            high_crit += 1
    print(f"[SCA - Dependency-Check] Total CVEs: {len(vulns)} | Alta/Crítica: {high_crit}")
    return 1 if high_crit > max_high_critical else 0

def check_zap(report_path: str, max_high_medium: int = 0) -> int:
    tree = ET.parse(report_path)
    root = tree.getroot()
    alerts = root.findall(".//alertitem")
    blocking_alerts = []
    for alert in alerts:
        riskcode = alert.findtext("riskcode", default="0")
        name = alert.findtext("alert", default="Unknown")
        # riskcode: 3 = High, 2 = Medium, 1 = Low, 0 = Informational
        if int(riskcode) >= 2:
            blocking_alerts.append((name, riskcode))
    print(f"[DAST - OWASP ZAP] Total tipos de alerta: {len(alerts)} | Riesgo Alto/Medio (>=2): {len(blocking_alerts)}")
    for name, code in blocking_alerts:
        sev = "ALTO" if code == "3" else "MEDIO"
        print(f"   -> [{sev}] {name}")
    return 1 if len(blocking_alerts) > max_high_medium else 0

if __name__ == "__main__":
    tool = sys.argv[1]
    path = sys.argv[2]
    threshold = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    if not Path(path).exists():
        print(f"[!] No se encontró el informe en {path}")
        sys.exit(1)

    if tool == "semgrep":
        rc = check_semgrep(path, threshold)
    elif tool == "checkov":
        rc = check_checkov(path, threshold)
    elif tool == "dependency-check":
        rc = check_dependency_check(path, threshold)
    elif tool == "zap":
        rc = check_zap(path, threshold)
    else:
        print(f"Herramienta no reconocida: {tool}")
        sys.exit(1)

    if rc != 0:
        print(f"❌ [QUALITY GATE SUPERADO] {tool.upper()} ha detectado vulnerabilidades por encima del umbral permitido ({threshold}).")
        sys.exit(1)
    else:
        print(f"✅ [QUALITY GATE OK] {tool.upper()} cumple con el umbral de seguridad.")
        sys.exit(0)