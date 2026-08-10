#!/usr/bin/env python3
"""
VibeCoding Report Generator - Generador de reportes de Responsible Disclosure.

Genera reportes profesionales en Markdown y JSON para notificación ética
de vulnerabilidades encontradas en aplicaciones de Vibe Coding.
"""

import json
import argparse
import datetime
from pathlib import Path
from typing import Optional

CVSS_RATINGS = {
    "CRITICAL": {"range": "9.0-10.0", "color": "🔴"},
    "HIGH": {"range": "7.0-8.9", "color": "🟠"},
    "MEDIUM": {"range": "4.0-6.9", "color": "🟡"},
    "LOW": {"range": "0.1-3.9", "color": "🟢"},
    "INFORMATIONAL": {"range": "0.0", "color": "🔵"},
}

VULN_TEMPLATES = {
    "rls_disabled": {
        "title": "Row Level Security (RLS) Deshabilitado en Supabase",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-285",
        "owasp": "A01:2021 - Broken Access Control",
        "description": (
            "La base de datos Supabase utilizada por la aplicación tiene Row Level Security "
            "deshabilitado en tablas con datos sensibles. Esto permite que cualquier usuario "
            "autenticado (o incluso anónimo con la clave ANON) pueda leer, modificar o eliminar "
            "registros de otros usuarios."
        ),
        "impact": (
            "Exposición masiva de datos personales de todos los usuarios. "
            "Posibilidad de modificación o eliminación de datos ajenos."
        ),
        "reproduction": [
            "1. Obtener la SUPABASE_URL y SUPABASE_ANON_KEY del código cliente",
            "2. Realizar petición: GET {SUPABASE_URL}/rest/v1/users?select=*",
            "3. Header: apikey: {SUPABASE_ANON_KEY}",
            "4. Observar que devuelve todos los registros de la tabla users",
        ],
        "remediation": (
            "Ejecutar en Supabase SQL Editor: "
            "ALTER TABLE public.users ENABLE ROW LEVEL SECURITY; "
            "Luego crear políticas específicas para cada operación (SELECT, INSERT, UPDATE, DELETE)."
        ),
        "references": [
            "https://supabase.com/docs/guides/auth/row-level-security",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        ],
    },
    "api_key_exposed": {
        "title": "Clave de API con privilegios elevados expuesta en código cliente",
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-312",
        "owasp": "A02:2021 - Cryptographic Failures",
        "description": (
            "La SERVICE_ROLE key de Supabase (o equivalente con privilegios de administrador) "
            "está embebida en el código JavaScript del frontend, accesible desde el navegador "
            "sin autenticación."
        ),
        "impact": (
            "Control total sobre la base de datos. Bypass completo de Row Level Security. "
            "Acceso, modificación y eliminación de todos los datos."
        ),
        "reproduction": [
            "1. Abrir DevTools en el navegador (F12)",
            "2. Ir a Sources o Network",
            "3. Buscar 'service_role' o 'SERVICE_ROLE' en los archivos JS",
            "4. La clave está expuesta en texto plano",
        ],
        "remediation": (
            "NUNCA incluir SERVICE_ROLE key en código frontend. "
            "Usar únicamente ANON key en el cliente. "
            "Operaciones privilegiadas solo desde Edge Functions o backend propio. "
            "Rotar inmediatamente la clave comprometida."
        ),
        "references": [
            "https://supabase.com/docs/guides/api/api-keys",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ],
    },
    "admin_panel_exposed": {
        "title": "Panel de administración accesible sin autenticación",
        "severity": "HIGH",
        "cvss_score": 8.6,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe": "CWE-306",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "description": (
            "La ruta /admin (o similar) del panel de administración es accesible "
            "desde internet sin requerir autenticación ni autorización."
        ),
        "impact": (
            "Acceso a funciones administrativas, gestión de usuarios, "
            "configuración del sistema y datos sensibles sin credenciales."
        ),
        "reproduction": [
            "1. Navegar directamente a https://[dominio]/admin",
            "2. Observar que se carga el panel sin solicitar credenciales",
            "3. Las funciones administrativas son funcionales",
        ],
        "remediation": (
            "Implementar autenticación robusta (OAuth2 + MFA) en todas las rutas /admin. "
            "Usar middleware de autorización basado en roles (RBAC). "
            "Considerar IP allowlisting para acceso administrativo."
        ),
        "references": [
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        ],
    },
    "cors_wildcard": {
        "title": "CORS configurado con wildcard (*)",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "cwe": "CWE-942",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": (
            "El servidor responde con Access-Control-Allow-Origin: * permitiendo "
            "peticiones cross-origin desde cualquier dominio."
        ),
        "impact": (
            "En combinación con cookies de sesión, podría permitir ataques CSRF "
            "y lectura de datos mediante peticiones desde sitios maliciosos."
        ),
        "reproduction": [
            "1. Realizar petición: curl -H 'Origin: https://evil.com' https://[dominio]/api",
            "2. Observar en la respuesta: Access-Control-Allow-Origin: *",
        ],
        "remediation": (
            "Especificar dominios permitidos explícitamente: "
            "Access-Control-Allow-Origin: https://tudominio.com. "
            "Si se necesitan múltiples dominios, usar una lista de dominios permitidos."
        ),
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        ],
    },
    "missing_security_headers": {
        "title": "Headers de seguridad HTTP críticos ausentes",
        "severity": "LOW",
        "cvss_score": 3.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "cwe": "CWE-693",
        "owasp": "A05:2021 - Security Misconfiguration",
        "description": (
            "La aplicación no implementa headers de seguridad HTTP recomendados: "
            "Content-Security-Policy, Strict-Transport-Security, X-Frame-Options."
        ),
        "impact": (
            "Mayor superficie de ataque para XSS, clickjacking "
            "y ataques de downgrade de protocolo."
        ),
        "reproduction": [
            "1. curl -I https://[dominio]",
            "2. Verificar ausencia de CSP, HSTS, X-Frame-Options",
        ],
        "remediation": (
            "Añadir en el servidor/CDN:\n"
            "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "- Content-Security-Policy: default-src 'self'\n"
            "- X-Frame-Options: DENY\n"
            "- X-Content-Type-Options: nosniff"
        ),
        "references": [
            "https://securityheaders.com",
            "https://owasp.org/www-project-secure-headers/",
        ],
    },
}


class VulnerabilityReport:
    def __init__(
        self,
        organization: str,
        researcher_name: str,
        researcher_email: str,
        target_url: str = "",
    ):
        self.organization = organization
        self.researcher_name = researcher_name
        self.researcher_email = researcher_email
        self.target_url = target_url
        self.findings = []
        self.report_id = f"VCT-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}"
        self.date = datetime.datetime.now().isoformat()

    def add_finding(
        self,
        vuln_type: str,
        affected_url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> None:
        if vuln_type not in VULN_TEMPLATES:
            raise ValueError(f"Tipo de vulnerabilidad desconocido: {vuln_type}")
        finding = VULN_TEMPLATES[vuln_type].copy()
        finding["vuln_type"] = vuln_type
        finding["affected_url"] = affected_url or self.target_url
        finding["notes"] = notes or ""
        finding["finding_id"] = f"{self.report_id}-{len(self.findings) + 1:02d}"
        self.findings.append(finding)

    def _severity_order(self, severity: str) -> int:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        return order.get(severity, 99)

    def generate_json(self) -> dict:
        sorted_findings = sorted(
            self.findings, key=lambda x: self._severity_order(x["severity"])
        )
        severity_counts = {}
        for f in self.findings:
            sev = f["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "report_id": self.report_id,
            "generated_at": self.date,
            "organization": self.organization,
            "target_url": self.target_url,
            "researcher": {
                "name": self.researcher_name,
                "email": self.researcher_email,
            },
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": severity_counts,
            },
            "findings": sorted_findings,
        }

    def generate_markdown(self) -> str:
        data = self.generate_json()
        lines = [
            f"# Reporte de Seguridad — {self.organization}",
            f"**ID de Reporte:** `{self.report_id}`  ",
            f"**Fecha:** {self.date[:10]}  ",
            f"**Investigador:** {self.researcher_name} ({self.researcher_email})  ",
            f"**URL Objetivo:** {self.target_url}  ",
            "",
            "---",
            "",
            "## Resumen Ejecutivo",
            "",
            f"Se identificaron **{len(self.findings)} hallazgo(s)** de seguridad "
            f"en la aplicación web de **{self.organization}**.",
            "",
            "| Severidad | Cantidad |",
            "|-----------|----------|",
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            count = data["summary"]["by_severity"].get(sev, 0)
            if count:
                info = CVSS_RATINGS[sev]
                lines.append(f"| {info['color']} {sev} | {count} |")

        lines += [
            "",
            "**Metodología:** OWASP Testing Guide v4.2, análisis manual pasivo",
            "**Herramientas:** VibeCoding Security Toolkit (análisis de información pública)",
            "",
            "---",
            "",
            "## Hallazgos",
            "",
        ]

        for i, finding in enumerate(
            sorted(self.findings, key=lambda x: self._severity_order(x["severity"])), 1
        ):
            sev_info = CVSS_RATINGS[finding["severity"]]
            lines += [
                f"### {i}. {finding['title']}",
                "",
                f"| Campo | Valor |",
                f"|-------|-------|",
                f"| **ID** | `{finding['finding_id']}` |",
                f"| **Severidad** | {sev_info['color']} {finding['severity']} |",
                f"| **CVSS Score** | {finding['cvss_score']} |",
                f"| **CVSS Vector** | `{finding['cvss_vector']}` |",
                f"| **CWE** | [{finding['cwe']}](https://cwe.mitre.org/data/definitions/{finding['cwe'].split('-')[1]}.html) |",
                f"| **OWASP** | {finding['owasp']} |",
                f"| **URL Afectada** | `{finding['affected_url']}` |",
                "",
                "**Descripción:**",
                "",
                finding["description"],
                "",
                "**Impacto:**",
                "",
                finding["impact"],
                "",
                "**Pasos de reproducción:**",
                "",
            ]
            for step in finding["reproduction"]:
                lines.append(f"{step}")
            lines += [
                "",
                "**Remediación recomendada:**",
                "",
                finding["remediation"],
                "",
                "**Referencias:**",
                "",
            ]
            for ref in finding["references"]:
                lines.append(f"- {ref}")

            if finding.get("notes"):
                lines += ["", f"**Notas adicionales:** {finding['notes']}"]

            lines += ["", "---", ""]

        lines += [
            "## Proceso de Divulgación Responsable",
            "",
            "Este reporte se comparte siguiendo el estándar de Responsible Disclosure:",
            "",
            "- **Día 0:** Descubrimiento y documentación",
            "- **Día 1-3:** Notificación a security@{organización}",
            "- **Día 7:** Seguimiento si no hay respuesta",
            "- **Día 90:** Divulgación pública (si no hay remediación)",
            "",
            "Por favor, confirme recepción de este reporte en un plazo de 5 días hábiles.",
            "",
            "---",
            "",
            f"*Reporte generado con VibeCoding Security Toolkit — {self.date[:10]}*",
            "*Para investigación ética y Responsible Disclosure*",
        ]

        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding Report Generator - Reportes de Responsible Disclosure"
    )
    parser.add_argument("--org", default="Empresa Demo SA", help="Organización objetivo")
    parser.add_argument("--researcher", default="Investigador Anónimo", help="Tu nombre")
    parser.add_argument("--email", default="researcher@example.com", help="Tu email")
    parser.add_argument("--url", default="https://app-demo.lovable.app", help="URL objetivo")
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    report = VulnerabilityReport(
        organization=args.org,
        researcher_name=args.researcher,
        researcher_email=args.email,
        target_url=args.url,
    )

    # Añadir hallazgos de ejemplo (en uso real, solo los encontrados)
    report.add_finding(
        "rls_disabled",
        affected_url=f"{args.url}/api/users",
        notes="Tabla 'users' y 'orders' sin RLS. Verificado sin autenticación.",
    )
    report.add_finding(
        "missing_security_headers",
        notes="Faltan CSP, HSTS y X-Frame-Options en todas las rutas.",
    )
    report.add_finding(
        "cors_wildcard",
        affected_url=f"{args.url}/api",
        notes="CORS wildcard en todas las rutas /api/*",
    )

    # Guardar JSON
    json_path = output_dir / "vulnerability_report.json"
    json_path.write_text(
        json.dumps(report.generate_json(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[+] Reporte JSON: {json_path}")

    # Guardar Markdown
    md_path = output_dir / "vulnerability_report.md"
    md_path.write_text(report.generate_markdown(), encoding="utf-8")
    print(f"[+] Reporte Markdown: {md_path}")

    data = report.generate_json()
    print(f"\n[+] Reporte ID: {data['report_id']}")
    print(f"[+] Hallazgos totales: {data['summary']['total_findings']}")
    for sev, count in data["summary"]["by_severity"].items():
        icon = CVSS_RATINGS[sev]["color"]
        print(f"    {icon} {sev}: {count}")


if __name__ == "__main__":
    main()
