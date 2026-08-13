#!/usr/bin/env python3
"""
VibeCoding GitHub Secrets Dorks — Generador de consultas de auditoría pasiva.

Genera búsquedas listas para pegar en https://github.com/search (Code search).
NO realiza scraping, NO descarga repositorios y NO accede a nada automáticamente.

AVISO LEGAL: Solo para repositorios propios o con autorización explícita.
Ejecutar búsquedas MANUALMENTE. Automatizar viola los TOS de GitHub y puede ser ilegal.
"""

import json
import argparse
import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Patrones basados en hallazgos reales publicados (WIRED May-2026, CVE-2025-48757,
# securityscanner.dev, Matt Palmer, Taimur Khan, reportes públicos)
# ─────────────────────────────────────────────────────────────────────────────

DORK_CATEGORIES = {
    "supabase_service_role": {
        "description": "Supabase SERVICE_ROLE key en código fuente (riesgo crítico — bypass total de RLS)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "context": (
            "CVE-2025-48757: Lovable generaba proyectos Supabase sin RLS. "
            "Cualquier app con service_role expuesta da control total sobre la DB."
        ),
        "queries": [
            '"service_role" filename:.env',
            '"SUPABASE_SERVICE_ROLE_KEY" filename:.env',
            '"VITE_SUPABASE_SERVICE_ROLE"',
            '"NEXT_PUBLIC_SUPABASE" "service_role"',
            '"supabase_service_role_key" language:JavaScript',
            '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" "service_role"',
        ],
    },
    "supabase_anon_and_url": {
        "description": "Supabase ANON key + URL expuestas (permite acceso a tablas sin RLS)",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "context": (
            "La anon key es pública por diseño, pero si RLS está deshabilitado, "
            "permite SELECT/INSERT/UPDATE/DELETE en todas las tablas."
        ),
        "queries": [
            '"SUPABASE_URL" "SUPABASE_ANON_KEY" filename:.env',
            '"VITE_SUPABASE_URL" "VITE_SUPABASE_ANON_KEY"',
            '"NEXT_PUBLIC_SUPABASE_URL" "NEXT_PUBLIC_SUPABASE_ANON_KEY"',
            '"supabaseUrl" "supabaseKey" language:JavaScript',
            '"supabase.co" "eyJ" language:JavaScript',
        ],
    },
    "stripe_secrets": {
        "description": "Claves secretas de Stripe (sk_live_ o sk_test_) en código fuente",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "context": "Casos reportados: sk_live_ hardcodeada en bundle frontend de apps Vibe Coded.",
        "queries": [
            '"sk_live_" filename:.env',
            '"STRIPE_SECRET_KEY" filename:.env',
            '"sk_live_" language:JavaScript',
            '"sk_test_" "STRIPE" filename:.env',
            '"STRIPE_SECRET" NOT "pk_"',
        ],
    },
    "openai_and_ai_keys": {
        "description": "API keys de LLMs (OpenAI, Anthropic, xAI, Google AI)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "context": (
            "Hallazgos reportados: OPENAI_API_KEY hardcodeada en frontend de apps "
            "generadas con Bolt y Lovable. Impacto: facturas ilimitadas y acceso a datos."
        ),
        "queries": [
            '"OPENAI_API_KEY" filename:.env',
            '"sk-proj-" language:JavaScript',
            '"sk-proj-" filename:.env',
            '"ANTHROPIC_API_KEY" filename:.env',
            '"GOOGLE_AI_API_KEY" filename:.env',
            '"XAI_API_KEY" filename:.env',
            '"OPENAI_API_KEY" NOT "your_" NOT "placeholder" NOT "example"',
        ],
    },
    "generic_env_files": {
        "description": "Archivos .env completos expuestos en repositorios públicos",
        "severity": "HIGH",
        "cwe": "CWE-538",
        "context": (
            "Patrones frecuentes en apps Vibe Coded: .env, .env.local, "
            ".env.production commiteados por error."
        ),
        "queries": [
            'filename:.env "DATABASE_URL"',
            'filename:.env.local "SUPABASE"',
            'filename:.env.production "SECRET"',
            'filename:.env "API_KEY" NOT ".env.example"',
            'filename:.env "PASSWORD" NOT "example" NOT "test"',
        ],
    },
    "google_firebase": {
        "description": "Claves de Firebase / Google Cloud en código fuente",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "context": "Firebase apiKey expuesta en frontend (común en apps React + Firebase).",
        "queries": [
            '"AIzaSy" filename:firebaseConfig.js',
            '"apiKey" "authDomain" "projectId" language:JavaScript',
            '"FIREBASE_SERVICE_ACCOUNT" filename:.env',
            '"firebase" "private_key" filename:.json',
            '"AIzaSy" "storageBucket" language:TypeScript',
        ],
    },
    "other_common": {
        "description": "Otros secretos frecuentes (AWS, SendGrid, JWT secrets, etc.)",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "context": "Patrones encontrados en auditorías públicas de apps Vibe Coded.",
        "queries": [
            '"AWS_SECRET_ACCESS_KEY" filename:.env',
            '"SENDGRID_API_KEY" filename:.env',
            '"JWT_SECRET" filename:.env NOT "example"',
            '"PRIVATE_KEY" "-----BEGIN" filename:.env',
            '"DATABASE_URL" "postgres://" filename:.env',
            '"TWILIO_AUTH_TOKEN" filename:.env',
        ],
    },
    "vibe_platform": {
        "description": "Secretos en repos de apps generadas con plataformas Vibe Coding",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "context": (
            "Patrones específicos de Lovable, Bolt, Replit. "
            "WIRED May-2026: ~380.000 assets públicos, ~40 % exponiendo datos sensibles."
        ),
        "queries": [
            '"lovable" "SUPABASE_SERVICE_ROLE" filename:.env',
            '"bolt" "OPENAI_API_KEY" filename:.env',
            '"replit" "DATABASE_URL" filename:.env',
            '"vite.config" "VITE_" "SECRET" language:TypeScript',
            '"lovable-tagger" "service_role" language:JavaScript',
        ],
    },
}

VIBE_PLATFORMS = ["lovable.app", "bolt.new", "repl.co", "base44.app"]

LOCAL_TOOLS = [
    {"name": "gitleaks", "url": "https://github.com/gitleaks/gitleaks", "desc": "Escáner de secretos en Git history"},
    {"name": "trufflehog", "url": "https://github.com/trufflesecurity/trufflehog", "desc": "Detecta secretos en repos y pipelines CI/CD"},
    {"name": "git-secrets", "url": "https://github.com/awslabs/git-secrets", "desc": "Previene commits con secretos (AWS)"},
    {"name": "vibe-scanner", "url": "https://github.com/search?q=vibe-scanner", "desc": "Auditoría específica de apps Vibe Coded"},
    {"name": "rlsgate", "url": "https://github.com/search?q=rlsgate", "desc": "Verifica políticas RLS de Supabase"},
]


def generate_github_dorks(scope_prefix: str = "") -> dict:
    """Genera consultas de GitHub Code Search estructuradas."""
    results = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "scope": scope_prefix or "general (sin scope — solo repos propios/autorizados)",
            "total_queries": 0,
            "search_url_base": "https://github.com/search?type=code&q=",
            "disclaimer": (
                "Solo para repositorios propios o con autorización explícita. "
                "Ejecutar MANUALMENTE en https://github.com/search. "
                "No automatizar — viola TOS de GitHub."
            ),
            "references": [
                "CVE-2025-48757 (Matt Palmer — Lovable/Supabase RLS)",
                "WIRED May-2026: RedAccess — 380K assets Vibe Coded expuestos",
                "securityscanner.dev 2026: 5.5% apps críticas (RLS deshabilitado)",
                "Taimur Khan: 16 vulns en una sola app Vibe Coded (6 críticas)",
            ],
        },
        "categories": {},
        "local_analysis_tools": LOCAL_TOOLS,
    }

    total = 0
    for cat_name, cat_data in DORK_CATEGORIES.items():
        queries_with_links = []
        for q in cat_data["queries"]:
            full_query = f"{scope_prefix} {q}".strip() if scope_prefix else q
            encoded = full_query.replace(" ", "+").replace('"', "%22")
            queries_with_links.append(
                {
                    "query": full_query,
                    "github_url": f"https://github.com/search?type=code&q={encoded}",
                }
            )
            total += 1

        results["categories"][cat_name] = {
            "description": cat_data["description"],
            "severity": cat_data["severity"],
            "cwe": cat_data["cwe"],
            "context": cat_data["context"],
            "queries": queries_with_links,
        }

    results["metadata"]["total_queries"] = total
    return results


def generate_markdown_report(data: dict, output_path: Path) -> None:
    """Genera reporte Markdown con las consultas y enlaces directos."""
    severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    lines = [
        "# GitHub Secrets Dorks — VibeCoding Security Toolkit",
        "",
        f"**Generado:** {data['metadata']['generated_at']}  ",
        f"**Scope:** `{data['metadata']['scope']}`  ",
        f"**Total de consultas:** {data['metadata']['total_queries']}",
        "",
        "> ⚠️ **AVISO LEGAL:** Solo para repositorios **propios** o con **autorización explícita**.",
        "> Ejecutar **manualmente** en [github.com/search](https://github.com/search?type=code).",
        "> No automatizar (viola TOS de GitHub y puede ser ilegal).",
        "",
        "---",
        "",
        "## Contexto — Hallazgos reales publicados",
        "",
        "| Investigación | Hallazgo |",
        "|---------------|----------|",
        "| WIRED / RedAccess (May 2026) | ~380.000 assets públicos en Lovable/Base44/Replit/Netlify. ~40 % exponiendo datos sensibles. |",
        "| CVE-2025-48757 (Matt Palmer) | Lovable generaba proyectos **sin RLS**. 170+ apps, 303 endpoints vulnerables. |",
        "| securityscanner.dev (2026) | 5,5 % de 1.169 apps con críticos. Lovable 7,1 %, Bolt 7,3 %. |",
        "| Taimur Khan | Una sola app: 16 vulnerabilidades, 6 críticas, 18.697 registros expuestos. |",
        "",
        "---",
        "",
        "## Consultas por categoría",
        "",
    ]

    for cat_name, cat_data in data["categories"].items():
        icon = severity_icons.get(cat_data["severity"], "⚪")
        count = len(cat_data["queries"])
        lines += [
            f"### {icon} {cat_data['description']}",
            f"**Severidad:** {cat_data['severity']} · **CWE:** [{cat_data['cwe']}](https://cwe.mitre.org/data/definitions/{cat_data['cwe'].split('-')[1]}.html) · {count} consultas",
            "",
            f"*Contexto:* {cat_data['context']}",
            "",
            "| Consulta | Abrir en GitHub |",
            "|----------|----------------|",
        ]
        for q in cat_data["queries"]:
            safe_q = q["query"].replace("|", "\\|")
            lines.append(f"| `{safe_q}` | [🔍 Buscar]({q['github_url']}) |")
        lines += ["", ""]

    lines += [
        "---",
        "",
        "## Herramientas recomendadas para análisis local",
        "",
        "*Para repositorios que ya tienes clonados (propios o autorizados):*",
        "",
        "| Herramienta | Descripción |",
        "|-------------|-------------|",
    ]
    for tool in data["local_analysis_tools"]:
        lines.append(f"| [{tool['name']}]({tool['url']}) | {tool['desc']} |")

    lines += [
        "",
        "---",
        "",
        "## Flujo de Responsible Disclosure si encuentras algo ajeno",
        "",
        "1. **No accedas** al sistema (aunque la clave funcione)",
        "2. **Documenta** solo con captura de pantalla del repositorio público",
        "3. **Notifica** al propietario: `security@empresa.com` o DM en GitHub",
        "4. **Espera** 90 días antes de cualquier divulgación pública",
        "5. Usa las plantillas del toolkit: `python3 notification_templates.py`",
        "",
        "---",
        "",
        f"*Generado con VibeCoding Security Toolkit — {data['metadata']['generated_at'][:10]}*",
    ]

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Secrets Dorks — Generador de consultas de auditoría pasiva"
    )
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument("--org", help="Limitar a una organización: org:nombre-org")
    scope_group.add_argument("--user", help="Limitar a un usuario: user:nombre-usuario")
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    args = parser.parse_args()

    scope_prefix = ""
    if args.org:
        scope_prefix = f"org:{args.org}"
    elif args.user:
        scope_prefix = f"user:{args.user}"

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    scope_label = scope_prefix or "general"
    print(f"\n[*] Generando GitHub Secrets Dorks — scope: {scope_label}")
    print("[!] Recuerda: ejecutar búsquedas MANUALMENTE en github.com/search\n")

    data = generate_github_dorks(scope_prefix)

    json_path = output_dir / "github_secrets_dorks.json"
    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON guardado: {json_path}")

    md_path = output_dir / "github_secrets_dorks.md"
    generate_markdown_report(data, md_path)
    print(f"[+] Reporte Markdown: {md_path}")

    print(f"\n[+] Total de consultas generadas: {data['metadata']['total_queries']}")
    print("\n[+] Distribución por categoría:")
    severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
    for cat_name, cat_data in data["categories"].items():
        icon = severity_icons.get(cat_data["severity"], "⚪")
        print(f"    {icon} {cat_data['description'][:55]}: {len(cat_data['queries'])} queries")

    print("\n[!] Recuerda: solo úsalo sobre repos propios o con autorización.\n")


if __name__ == "__main__":
    main()
