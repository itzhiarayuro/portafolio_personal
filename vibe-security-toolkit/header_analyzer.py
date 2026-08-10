#!/usr/bin/env python3
"""
VibeCoding Header Analyzer - Análisis pasivo de headers HTTP de seguridad.

Solo analiza información pública que cualquier navegador recibe.
Una sola petición GET por URL. No es un escáner agresivo.

AVISO LEGAL: Solo para uso educativo y con autorización.
"""

import json
import urllib.request
import urllib.error
import argparse
import datetime
from pathlib import Path

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HTTP Strict Transport Security (HSTS)",
        "severity": "MEDIUM",
        "recommendation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "description": "Content Security Policy (CSP)",
        "severity": "HIGH",
        "recommendation": "Configurar CSP restrictiva para prevenir XSS",
        "cwe": "CWE-693",
    },
    "X-Frame-Options": {
        "description": "Protección contra Clickjacking",
        "severity": "MEDIUM",
        "recommendation": "Añadir: X-Frame-Options: DENY o SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "X-Content-Type-Options": {
        "description": "Prevención de MIME sniffing",
        "severity": "LOW",
        "recommendation": "Añadir: X-Content-Type-Options: nosniff",
        "cwe": "CWE-430",
    },
    "Referrer-Policy": {
        "description": "Control de información de referrer",
        "severity": "LOW",
        "recommendation": "Añadir: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "description": "Control de permisos del navegador",
        "severity": "LOW",
        "recommendation": "Configurar Permissions-Policy para limitar APIs del navegador",
        "cwe": "CWE-693",
    },
    "Cache-Control": {
        "description": "Control de caché para datos sensibles",
        "severity": "LOW",
        "recommendation": "Para rutas autenticadas: Cache-Control: no-store",
        "cwe": "CWE-524",
    },
}

DISCLOSURE_HEADERS = {
    "Server": "Versión del servidor expuesta",
    "X-Powered-By": "Tecnología del backend expuesta",
    "X-Generator": "Generador del sitio expuesto",
    "X-AspNet-Version": "Versión ASP.NET expuesta",
    "X-Runtime": "Runtime expuesto",
}


def analyze_headers(url: str, timeout: int = 10) -> dict:
    """Realiza una petición GET y analiza los headers de seguridad."""
    result = {
        "url": url,
        "timestamp": datetime.datetime.now().isoformat(),
        "status_code": None,
        "error": None,
        "missing_security_headers": [],
        "present_security_headers": [],
        "disclosure_headers": [],
        "cors_issues": [],
        "cookie_issues": [],
        "raw_headers": {},
        "risk_score": 0,
        "risk_level": "LOW",
    }

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; SecurityResearch/1.0; "
                    "+https://github.com/ethicalsec)"
                )
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result["status_code"] = response.status
            headers = dict(response.headers)
            result["raw_headers"] = {k: v for k, v in headers.items()}

            _check_security_headers(result, headers)
            _check_disclosure(result, headers)
            _check_cors(result, headers)
            _check_cookies(result, headers)
            _calculate_risk(result)

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["error"] = f"URL Error: {e.reason}"
    except Exception as e:
        result["error"] = f"Error inesperado: {str(e)}"

    return result


def _check_security_headers(result: dict, headers: dict) -> None:
    """Verifica presencia de headers de seguridad."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header, info in SECURITY_HEADERS.items():
        if header.lower() in headers_lower:
            result["present_security_headers"].append(
                {
                    "header": header,
                    "value": headers_lower[header.lower()],
                    "description": info["description"],
                }
            )
        else:
            result["missing_security_headers"].append(
                {
                    "header": header,
                    "description": info["description"],
                    "severity": info["severity"],
                    "recommendation": info["recommendation"],
                    "cwe": info["cwe"],
                }
            )


def _check_disclosure(result: dict, headers: dict) -> None:
    """Detecta headers que revelan información del sistema."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    for header, description in DISCLOSURE_HEADERS.items():
        if header.lower() in headers_lower:
            result["disclosure_headers"].append(
                {
                    "header": header,
                    "value": headers_lower[header.lower()],
                    "issue": description,
                    "recommendation": f"Eliminar o ofuscar el header '{header}'",
                }
            )


def _check_cors(result: dict, headers: dict) -> None:
    """Verifica configuración de CORS."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    cors_origin = headers_lower.get("access-control-allow-origin", "")
    if cors_origin == "*":
        result["cors_issues"].append(
            {
                "header": "Access-Control-Allow-Origin",
                "value": cors_origin,
                "severity": "MEDIUM",
                "issue": "CORS wildcard permite peticiones desde cualquier origen",
                "recommendation": "Especificar dominios permitidos explícitamente",
                "cwe": "CWE-942",
            }
        )


def _check_cookies(result: dict, headers: dict) -> None:
    """Analiza flags de seguridad en cookies."""
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            cookie_issues = []
            if "secure" not in value.lower():
                cookie_issues.append("Falta flag 'Secure'")
            if "httponly" not in value.lower():
                cookie_issues.append("Falta flag 'HttpOnly'")
            if "samesite" not in value.lower():
                cookie_issues.append("Falta atributo 'SameSite'")

            if cookie_issues:
                cookie_name = value.split("=")[0].strip()
                result["cookie_issues"].append(
                    {
                        "cookie": cookie_name,
                        "issues": cookie_issues,
                        "severity": "MEDIUM",
                        "recommendation": "Añadir flags Secure, HttpOnly y SameSite=Strict",
                        "cwe": "CWE-614",
                    }
                )


def _calculate_risk(result: dict) -> None:
    """Calcula score de riesgo basado en hallazgos."""
    score = 0
    severity_scores = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

    for item in result["missing_security_headers"]:
        score += severity_scores.get(item["severity"], 0)
    for item in result["disclosure_headers"]:
        score += 5
    for item in result["cors_issues"]:
        score += severity_scores.get(item["severity"], 0)
    for item in result["cookie_issues"]:
        score += severity_scores.get(item["severity"], 0)

    result["risk_score"] = min(score, 100)
    if score >= 50:
        result["risk_level"] = "HIGH"
    elif score >= 25:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"


def format_report(analysis: dict) -> str:
    """Formatea el análisis como reporte legible."""
    risk_colors = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}
    severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    risk_icon = risk_colors.get(analysis["risk_level"], "⚪")

    lines = [
        "=" * 60,
        "  ANÁLISIS DE HEADERS DE SEGURIDAD HTTP",
        "=" * 60,
        f"  URL: {analysis['url']}",
        f"  Timestamp: {analysis['timestamp']}",
        f"  Status HTTP: {analysis.get('status_code', 'N/A')}",
        f"  Riesgo: {risk_icon} {analysis['risk_level']} (Score: {analysis['risk_score']}/100)",
        "=" * 60,
    ]

    if analysis.get("error"):
        lines += ["", f"❌ ERROR: {analysis['error']}", ""]
        return "\n".join(lines)

    if analysis["missing_security_headers"]:
        lines += ["", "[ HEADERS DE SEGURIDAD FALTANTES ]", ""]
        for item in analysis["missing_security_headers"]:
            icon = severity_icons.get(item["severity"], "⚪")
            lines += [
                f"  {icon} {item['header']} [{item['severity']}]",
                f"     {item['description']}",
                f"     Recomendación: {item['recommendation']}",
                f"     CWE: {item['cwe']}",
                "",
            ]

    if analysis["present_security_headers"]:
        lines += ["[ HEADERS DE SEGURIDAD PRESENTES ✓ ]", ""]
        for item in analysis["present_security_headers"]:
            lines.append(f"  ✅ {item['header']}: {item['value'][:60]}")
        lines.append("")

    if analysis["disclosure_headers"]:
        lines += ["[ INFORMACIÓN DIVULGADA EN HEADERS ]", ""]
        for item in analysis["disclosure_headers"]:
            lines += [
                f"  ⚠️  {item['header']}: {item['value']}",
                f"     Issue: {item['issue']}",
                "",
            ]

    if analysis["cors_issues"]:
        lines += ["[ PROBLEMAS DE CORS ]", ""]
        for item in analysis["cors_issues"]:
            lines += [
                f"  🟡 {item['header']}: {item['value']}",
                f"     {item['issue']}",
                "",
            ]

    if analysis["cookie_issues"]:
        lines += ["[ PROBLEMAS EN COOKIES ]", ""]
        for item in analysis["cookie_issues"]:
            lines += [
                f"  🟡 Cookie '{item['cookie']}'",
                f"     Issues: {', '.join(item['issues'])}",
                "",
            ]

    lines += ["=" * 60]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding Header Analyzer - Análisis pasivo de seguridad HTTP"
    )
    parser.add_argument(
        "--url",
        default="https://httpbin.org",
        help="URL a analizar (con https://)",
    )
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout en segundos")
    args = parser.parse_args()

    print(f"\n[*] Analizando headers de: {args.url}")
    print("[!] Solo se realiza UNA petición GET. No es un escáner agresivo.\n")

    analysis = analyze_headers(args.url, args.timeout)

    report = format_report(analysis)
    print(report)

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    json_path = output_dir / "header_analysis.json"
    json_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n[+] Análisis JSON guardado: {json_path}")


if __name__ == "__main__":
    main()
