#!/usr/bin/env python3
"""
VibeCoding Security Toolkit — Flujo completo de demostración.

Ejecuta todos los módulos del toolkit con datos de ejemplo
para demostrar el flujo completo de investigación ética.

Uso: python3 example_workflow.py [--domain DOMINIO] [--company EMPRESA]
"""

import argparse
import sys
import datetime
from pathlib import Path

# Añadir el directorio actual al path
sys.path.insert(0, str(Path(__file__).parent))

from osint_scanner import generate_dorks, generate_markdown_report
from header_analyzer import analyze_headers, format_report
from report_generator import VulnerabilityReport
from notification_templates import (
    generate_initial_notification,
    generate_followup,
)
from github_secrets_dorks import generate_github_dorks, generate_markdown_report as generate_github_md


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         VIBE CODING SECURITY TOOLKIT v1.0                   ║
║         Investigación ética de aplicaciones IA              ║
╠══════════════════════════════════════════════════════════════╣
║  AVISO LEGAL: Solo para uso educativo y con autorización.   ║
║  El acceso no autorizado a sistemas es ilegal.              ║
╚══════════════════════════════════════════════════════════════╝
"""

DEMO_FINDINGS = [
    {
        "severity": "CRITICAL",
        "title": "RLS Deshabilitado en Supabase",
        "cvss_score": 9.8,
        "cwe": "CWE-285",
    },
    {
        "severity": "MEDIUM",
        "title": "CORS Wildcard en API",
        "cvss_score": 5.3,
        "cwe": "CWE-942",
    },
    {
        "severity": "LOW",
        "title": "Headers de Seguridad Ausentes",
        "cvss_score": 3.1,
        "cwe": "CWE-693",
    },
]


def step_banner(step: int, title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  PASO {step}: {title}")
    print("─" * 60)


def run_workflow(domain: str, company: str, output_dir: Path, analyze_url: str) -> None:
    print(BANNER)
    print(f"  Empresa/Organización: {company}")
    print(f"  Dominio: {domain}")
    print(f"  Directorio de salida: {output_dir}")
    print(f"  Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────
    # PASO 1: OSINT pasivo
    # ─────────────────────────────────────────────────
    step_banner(1, "OSINT PASIVO — Generación de Google Dorks")

    dorks = generate_dorks(domain, company)
    total_dorks = dorks["metadata"]["total_dorks"]

    json_path = output_dir / "dorks.json"
    import json
    json_path.write_text(json.dumps(dorks, ensure_ascii=False, indent=2), encoding="utf-8")

    md_path = output_dir / "dorks_report.md"
    generate_markdown_report(dorks, md_path)

    print(f"  ✓ {total_dorks} consultas OSINT generadas")
    print(f"  ✓ Guardado en: {json_path}")
    print(f"  ✓ Reporte: {md_path}")
    print(f"\n  Distribución por categoría:")
    for cat_name, cat_data in dorks["categories"].items():
        count = len(cat_data["dorks"])
        sev = cat_data["severity"]
        severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        icon = severity_icons.get(sev, "⚪")
        print(f"    {icon} {cat_data['description']}: {count} queries")

    # ─────────────────────────────────────────────────
    # PASO 2: Análisis de headers
    # ─────────────────────────────────────────────────
    step_banner(2, "ANÁLISIS DE HEADERS HTTP (solo 1 petición GET)")
    print(f"  URL objetivo: {analyze_url}")

    analysis = analyze_headers(analyze_url, timeout=10)
    report_text = format_report(analysis)
    print(report_text)

    analysis_path = output_dir / "header_analysis.json"
    analysis_path.write_text(
        json.dumps(analysis, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"\n  ✓ Análisis guardado: {analysis_path}")

    # ─────────────────────────────────────────────────
    # PASO 3: Generación de reporte
    # ─────────────────────────────────────────────────
    step_banner(3, "GENERACIÓN DE REPORTE DE RESPONSIBLE DISCLOSURE")

    researcher_name = "Investigador Demo"
    researcher_email = "security-researcher@example.com"

    report = VulnerabilityReport(
        organization=company,
        researcher_name=researcher_name,
        researcher_email=researcher_email,
        target_url=f"https://{domain}",
    )

    report.add_finding(
        "rls_disabled",
        affected_url=f"https://{domain}/api/users",
        notes="Hallazgo hipotético de demostración. Tabla users sin RLS.",
    )
    report.add_finding(
        "cors_wildcard",
        affected_url=f"https://{domain}/api",
        notes="CORS wildcard detectado en header de respuesta.",
    )
    report.add_finding(
        "missing_security_headers",
        notes="Faltan CSP, HSTS y X-Frame-Options.",
    )

    report_json = report.generate_json()
    report_md = report.generate_markdown()

    json_report_path = output_dir / "vulnerability_report.json"
    json_report_path.write_text(
        json.dumps(report_json, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    md_report_path = output_dir / "vulnerability_report.md"
    md_report_path.write_text(report_md, encoding="utf-8")

    print(f"  ✓ Reporte ID: {report_json['report_id']}")
    print(f"  ✓ Hallazgos documentados: {report_json['summary']['total_findings']}")
    for sev, count in report_json["summary"]["by_severity"].items():
        print(f"      - {sev}: {count}")
    print(f"  ✓ JSON: {json_report_path}")
    print(f"  ✓ Markdown: {md_report_path}")

    # ─────────────────────────────────────────────────
    # PASO 4: Plantillas de notificación
    # ─────────────────────────────────────────────────
    step_banner(4, "GENERACIÓN DE PLANTILLAS DE NOTIFICACIÓN ÉTICA")

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    initial_email = generate_initial_notification(
        researcher_name=researcher_name,
        researcher_email=researcher_email,
        organization=company,
        target_url=f"https://{domain}",
        findings=DEMO_FINDINGS,
        lang="es",
    )

    followup_email = generate_followup(
        researcher_name=researcher_name,
        researcher_email=researcher_email,
        organization=company,
        target_url=f"https://{domain}",
        initial_date=today,
        report_id=report_json["report_id"],
        finding_count=len(DEMO_FINDINGS),
        days_since=7,
    )

    notification_path = output_dir / "notification.txt"
    notification_content = "\n".join(
        [
            "=" * 70,
            "EMAIL 1: NOTIFICACIÓN INICIAL",
            "=" * 70,
            initial_email,
            "",
            "=" * 70,
            "EMAIL 2: SEGUIMIENTO (Día 7)",
            "=" * 70,
            followup_email,
        ]
    )
    notification_path.write_text(notification_content, encoding="utf-8")

    print(f"  ✓ Email inicial generado (ES)")
    print(f"  ✓ Email de seguimiento generado")
    print(f"  ✓ Guardado en: {notification_path}")

    # ─────────────────────────────────────────────────
    # PASO 5: GitHub Secrets Dorks
    # ─────────────────────────────────────────────────
    step_banner(5, "GITHUB SECRETS DORKS (basado en CVE-2025-48757 + hallazgos WIRED 2026)")

    github_data = generate_github_dorks()
    gh_json_path = output_dir / "github_secrets_dorks.json"
    gh_json_path.write_text(
        json.dumps(github_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    gh_md_path = output_dir / "github_secrets_dorks.md"
    generate_github_md(github_data, gh_md_path)

    print(f"  ✓ {github_data['metadata']['total_queries']} consultas GitHub Code Search generadas")
    print(f"  ✓ JSON: {gh_json_path}")
    print(f"  ✓ Markdown: {gh_md_path}")
    print(f"\n  Categorías críticas:")
    for cat_name, cat in github_data["categories"].items():
        if cat["severity"] == "CRITICAL":
            print(f"    🔴 {cat['description'][:55]}: {len(cat['queries'])} queries")

    # ─────────────────────────────────────────────────
    # RESUMEN FINAL
    # ─────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  RESUMEN DEL WORKFLOW COMPLETADO")
    print("═" * 60)

    files = list(output_dir.glob("*"))
    print(f"\n  Archivos generados en {output_dir}/:")
    for f in sorted(files):
        size = f.stat().st_size
        print(f"    📄 {f.name} ({size:,} bytes)")

    print("\n  PRÓXIMOS PASOS (manual):")
    print("  1. Revisar dorks_report.md y buscar manualmente en Google")
    print("  2. Validar hallazgos en systems propios o con autorización")
    print("  3. Completar vulnerability_report.md con hallazgos reales")
    print("  4. Enviar notification.txt a security@{organización}")
    print("  5. Esperar respuesta. Si no hay en 90 días: divulgación pública")

    print("\n  CANALES DE NOTIFICACIÓN:")
    print(f"  - https://{domain}/.well-known/security.txt")
    print(f"  - https://{domain}/security")
    print(f"  - security@{domain}")
    print(f"  - HackerOne / Bugcrowd / Intigriti (si aplica)")

    print("\n" + "═" * 60)
    print("  ✓ Toolkit ejecutado correctamente. Actúa siempre con ética.")
    print("═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding Security Toolkit — Flujo completo de demostración"
    )
    parser.add_argument("--domain", default="ejemplo.com", help="Dominio objetivo")
    parser.add_argument("--company", default="Empresa Demo SA", help="Nombre de la empresa")
    parser.add_argument("--analyze-url", default="https://httpbin.org", help="URL para analizar headers")
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    args = parser.parse_args()

    run_workflow(
        domain=args.domain,
        company=args.company,
        output_dir=Path(args.output),
        analyze_url=args.analyze_url,
    )


if __name__ == "__main__":
    main()
