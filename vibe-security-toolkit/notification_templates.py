#!/usr/bin/env python3
"""
VibeCoding Notification Templates - Plantillas de notificación ética.

Genera emails profesionales de Responsible Disclosure en español e inglés
siguiendo las mejores prácticas del sector de seguridad.
"""

import argparse
import datetime
from pathlib import Path

INITIAL_ES = """
Asunto: [Responsible Disclosure] Vulnerabilidades de seguridad identificadas — {organization}

Estimado/a equipo de seguridad de {organization},

Mi nombre es {researcher_name} y me dedico a la investigación de seguridad de aplicaciones web,
con foco en aplicaciones generadas mediante herramientas de Inteligencia Artificial (Vibe Coding).

Durante una investigación pasiva de OSINT y análisis de información pública, he identificado
{finding_count} hallazgo(s) de seguridad en su aplicación {target_url} que podrían representar
un riesgo para sus usuarios y datos.

HALLAZGOS IDENTIFICADOS
{findings_summary}

METODOLOGÍA
La investigación se realizó de forma exclusivamente pasiva, analizando únicamente información
públicamente accesible. No se realizaron ataques, no se accedió a datos reales de usuarios,
y no se modificó ningún sistema.

ACCIÓN REQUERIDA
Le solicito amablemente:
1. Confirmar recepción de este reporte en un plazo de 5 días hábiles
2. Proporcionar una estimación del tiempo de remediación
3. Notificarme cuando las vulnerabilidades hayan sido corregidas

CRONOGRAMA DE DIVULGACIÓN
Siguiendo las mejores prácticas de Responsible Disclosure (RFC 9116):
- Día 0 (hoy): Notificación inicial
- Día 7: Seguimiento si no hay respuesta
- Día 90: Posible divulgación pública coordinada

Adjunto encontrará el reporte técnico completo con detalles, pasos de reproducción
y recomendaciones de remediación específicas.

No busco recompensa económica. Mi único objetivo es mejorar la seguridad de su plataforma
y proteger a sus usuarios.

Quedo a su disposición para cualquier consulta técnica adicional.

Atentamente,
{researcher_name}
{researcher_email}
{report_date}

---
POLÍTICA DE SEGURIDAD
Si su organización dispone de una política de seguridad (security.txt o similar),
por favor indíqueme el canal preferido para este tipo de comunicaciones.

PGP: Si desea comunicación cifrada, por favor proporcione su clave pública.
""".strip()

INITIAL_EN = """
Subject: [Responsible Disclosure] Security Vulnerabilities Identified — {organization}

Dear {organization} Security Team,

My name is {researcher_name}, and I conduct security research on AI-generated web applications
(commonly known as Vibe Coding applications).

During a passive OSINT investigation analyzing only publicly available information, I identified
{finding_count} security finding(s) in your application at {target_url} that could pose risks
to your users and data.

IDENTIFIED FINDINGS
{findings_summary}

METHODOLOGY
This research was conducted passively, analyzing only publicly accessible information.
No attacks were performed, no real user data was accessed, and no systems were modified.

REQUESTED ACTION
I kindly request:
1. Confirmation of receipt within 5 business days
2. An estimated remediation timeline
3. Notification once vulnerabilities have been addressed

DISCLOSURE TIMELINE
Following Responsible Disclosure best practices (RFC 9116):
- Day 0 (today): Initial notification
- Day 7: Follow-up if no response
- Day 90: Potential coordinated public disclosure

The attached technical report includes detailed findings, reproduction steps,
and specific remediation recommendations.

I am not seeking monetary compensation. My sole objective is to improve your platform's
security and protect your users.

Please feel free to reach out with any technical questions.

Best regards,
{researcher_name}
{researcher_email}
{report_date}

---
SECURITY POLICY
If your organization has a security policy (security.txt or similar),
please indicate your preferred channel for this type of communication.

PGP: If you require encrypted communication, please provide your public key.
""".strip()

FOLLOWUP_ES = """
Asunto: [SEGUIMIENTO] Responsible Disclosure — {organization} — {report_id}

Estimado/a equipo de seguridad de {organization},

El {initial_date} les envié un reporte de Responsible Disclosure identificando
{finding_count} vulnerabilidad(es) de seguridad en {target_url}.

Han transcurrido {days_since} días sin recibir confirmación de recepción.

Les escribo para:
1. Confirmar que recibieron el reporte inicial
2. Solicitar una actualización del estado de remediación
3. Recordar el cronograma de divulgación (Día 90: {disclosure_date})

Si el email anterior no llegó correctamente, puedo reenviar el reporte completo.

Atentamente,
{researcher_name}
{researcher_email}
""".strip()

PUBLIC_DISCLOSURE_ES = """
# Divulgación Pública de Vulnerabilidades — {organization}
**Fecha de descubrimiento:** {discovery_date}
**Fecha de notificación:** {notification_date}
**Fecha de divulgación pública:** {public_date}
**Estado:** {status}

## Resumen

{finding_count} vulnerabilidad(es) de seguridad fueron identificadas en {target_url}
durante investigación pasiva de OSINT.

La organización {notification_status}.

## Hallazgos

{findings_detail}

## Cronograma

- **{discovery_date}:** Descubrimiento de vulnerabilidades
- **{notification_date}:** Notificación a {organization}
- **{followup_date}:** Seguimiento (sin respuesta)
- **{public_date}:** Divulgación pública (90 días cumplidos)

## Créditos

Investigación realizada por {researcher_name} siguiendo las mejores prácticas
de Responsible Disclosure.
""".strip()


def generate_initial_notification(
    researcher_name: str,
    researcher_email: str,
    organization: str,
    target_url: str,
    findings: list,
    lang: str = "es",
) -> str:
    """Genera email inicial de Responsible Disclosure."""
    findings_summary = ""
    for i, f in enumerate(findings, 1):
        findings_summary += f"\n{i}. [{f['severity']}] {f['title']}"

    template = INITIAL_ES if lang == "es" else INITIAL_EN
    return template.format(
        researcher_name=researcher_name,
        researcher_email=researcher_email,
        organization=organization,
        target_url=target_url,
        finding_count=len(findings),
        findings_summary=findings_summary,
        report_date=datetime.datetime.now().strftime("%d/%m/%Y"),
    )


def generate_followup(
    researcher_name: str,
    researcher_email: str,
    organization: str,
    target_url: str,
    initial_date: str,
    report_id: str,
    finding_count: int,
    days_since: int = 7,
) -> str:
    """Genera email de seguimiento."""
    initial_dt = datetime.datetime.strptime(initial_date, "%Y-%m-%d")
    disclosure_dt = initial_dt + datetime.timedelta(days=90)

    return FOLLOWUP_ES.format(
        organization=organization,
        initial_date=initial_dt.strftime("%d/%m/%Y"),
        finding_count=finding_count,
        target_url=target_url,
        days_since=days_since,
        disclosure_date=disclosure_dt.strftime("%d/%m/%Y"),
        report_id=report_id,
        researcher_name=researcher_name,
        researcher_email=researcher_email,
    )


def generate_public_disclosure(
    researcher_name: str,
    organization: str,
    target_url: str,
    findings: list,
    discovery_date: str,
    notification_date: str,
    responded: bool = False,
) -> str:
    """Genera plantilla de divulgación pública (para usar tras 90 días sin remediación)."""
    disc_dt = datetime.datetime.strptime(notification_date, "%Y-%m-%d")
    followup_dt = disc_dt + datetime.timedelta(days=7)
    public_dt = disc_dt + datetime.timedelta(days=90)

    notification_status = (
        "respondió pero no proporcionó actualizaciones de remediación"
        if responded
        else "no respondió a las notificaciones"
    )

    findings_detail = ""
    for f in findings:
        findings_detail += f"\n### {f['title']}\n"
        findings_detail += f"**Severidad:** {f['severity']}  \n"
        findings_detail += f"**CVSS:** {f.get('cvss_score', 'N/A')}  \n"
        findings_detail += f"**CWE:** {f.get('cwe', 'N/A')}  \n\n"

    return PUBLIC_DISCLOSURE_ES.format(
        organization=organization,
        target_url=target_url,
        finding_count=len(findings),
        discovery_date=discovery_date,
        notification_date=notification_date,
        followup_date=followup_dt.strftime("%Y-%m-%d"),
        public_date=public_dt.strftime("%Y-%m-%d"),
        status="Vulnerabilidades sin confirmar remediación",
        notification_status=notification_status,
        findings_detail=findings_detail,
        researcher_name=researcher_name,
    )


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding Notification Templates - Plantillas de notificación ética"
    )
    parser.add_argument("--researcher", default="Investigador Demo", help="Tu nombre")
    parser.add_argument("--email", default="researcher@example.com", help="Tu email")
    parser.add_argument("--org", default="Empresa Demo SA", help="Organización")
    parser.add_argument("--url", default="https://app.ejemplo.com", help="URL objetivo")
    parser.add_argument("--lang", default="es", choices=["es", "en"], help="Idioma")
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    demo_findings = [
        {"severity": "CRITICAL", "title": "RLS Deshabilitado en Supabase"},
        {"severity": "MEDIUM", "title": "CORS Wildcard en API"},
        {"severity": "LOW", "title": "Headers de Seguridad Ausentes"},
    ]

    today = datetime.datetime.now().strftime("%Y-%m-%d")

    initial = generate_initial_notification(
        researcher_name=args.researcher,
        researcher_email=args.email,
        organization=args.org,
        target_url=args.url,
        findings=demo_findings,
        lang=args.lang,
    )

    followup = generate_followup(
        researcher_name=args.researcher,
        researcher_email=args.email,
        organization=args.org,
        target_url=args.url,
        initial_date=today,
        report_id="VCT-20260810-1234",
        finding_count=len(demo_findings),
        days_since=7,
    )

    output = "\n".join(
        [
            "=" * 70,
            "EMAIL 1: NOTIFICACIÓN INICIAL",
            "=" * 70,
            initial,
            "",
            "=" * 70,
            "EMAIL 2: SEGUIMIENTO (Día 7 sin respuesta)",
            "=" * 70,
            followup,
        ]
    )

    notif_path = output_dir / "notification.txt"
    notif_path.write_text(output, encoding="utf-8")
    print(f"[+] Plantillas de notificación guardadas: {notif_path}")
    print(f"    - Email inicial ({args.lang})")
    print(f"    - Email de seguimiento")
    print(f"\n[!] Recuerda: Busca primero security@{args.org.split()[0].lower()}.com")
    print("[!] o el archivo /.well-known/security.txt en el dominio objetivo.")


if __name__ == "__main__":
    main()
