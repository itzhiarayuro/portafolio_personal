#!/usr/bin/env python3
"""
VibeCoding OSINT Scanner - Generador de Google Dorks para investigación ética.

AVISO LEGAL: Solo para uso educativo, bug bounty autorizado e investigación ética.
Nunca ejecutes búsquedas ni pruebas contra sistemas sin permiso explícito por escrito.
"""

import json
import argparse
import datetime
from pathlib import Path

VIBE_PLATFORMS = {
    "lovable": "lovable.app",
    "replit": "repl.co",
    "netlify": "netlify.app",
    "vercel": "vercel.app",
    "base44": "base44.app",
    "bolt": "bolt.new",
    "firebase": "web.app",
    "surge": "surge.sh",
    "glitch": "glitch.me",
    "heroku": "herokuapp.com",
    "render": "onrender.com",
}

DORK_CATEGORIES = {
    "admin_exposure": {
        "description": "Paneles de administración expuestos",
        "severity": "HIGH",
        "cve_ref": None,
        "templates": [
            'site:{platform} intitle:"admin" "{company}"',
            'site:{platform} inurl:admin "{company}"',
            'site:{platform} inurl:dashboard "{company}"',
            'site:{platform} intitle:"login" inurl:admin "{company}"',
            'site:{platform} inurl:/admin/users "{company}"',
        ],
    },
    "config_files": {
        "description": "Archivos de configuración y secretos expuestos",
        "severity": "CRITICAL",
        "cve_ref": "CVE-2025-48757",
        "templates": [
            'site:{platform} filetype:env "{company}"',
            'site:{platform} inurl:.env "{company}"',
            'site:{platform} "SUPABASE_ANON_KEY" "{company}"',
            'site:{platform} "VITE_SUPABASE_SERVICE_ROLE" "{company}"',
            'site:{platform} "VITE_SUPABASE" "service_role" "{company}"',
            'site:{platform} "REACT_APP_" filetype:js "{company}"',
            'site:{platform} "firebase" "apiKey" "{company}"',
            'site:{platform} "OPENAI_API_KEY" "{company}"',
            'site:{platform} "sk-proj-" "{company}"',
        ],
    },
    "api_exposure": {
        "description": "APIs sin autenticación aparente",
        "severity": "HIGH",
        "cve_ref": None,
        "templates": [
            'site:{platform} inurl:api/users "{company}"',
            'site:{platform} inurl:api/admin "{company}"',
            'site:{platform} inurl:api/data "{company}"',
            'site:{platform} "\"email\"" "\"password\"" inurl:api "{company}"',
            'site:{platform} inurl:/rest/v1/ "{company}"',
        ],
    },
    "shadow_it": {
        "description": "Shadow IT - apps no inventariadas",
        "severity": "MEDIUM",
        "cve_ref": None,
        "templates": [
            'site:{platform} "{company}"',
            'site:{platform} "{domain}"',
            'site:{platform} "{company}" inurl:app',
            'site:{platform} "{company}" intitle:dashboard',
            'site:{platform} "{company}" intitle:portal',
        ],
    },
    "vcs_exposure": {
        "description": "Sistemas de control de versiones expuestos",
        "severity": "HIGH",
        "cve_ref": None,
        "templates": [
            'site:{platform} inurl:.git "{company}"',
            'site:{platform} inurl:.svn "{company}"',
            'site:{platform} "/.git/config" "{company}"',
        ],
    },
    "database_exposure": {
        "description": "Credenciales de base de datos y RLS deshabilitado",
        "severity": "CRITICAL",
        "cve_ref": "CVE-2025-48757",
        "templates": [
            'site:{platform} "supabase.co" "service_role" "{company}"',
            'site:{platform} "supabase.co" "USING (true)" "{company}"',
            'site:{platform} "mongodb+srv" "{company}"',
            'site:{platform} "DATABASE_URL" "{company}"',
            'site:{platform} "postgres://" "{company}"',
            'site:{platform} "ALTER TABLE" "DISABLE ROW LEVEL SECURITY" "{company}"',
        ],
    },
    "information_disclosure": {
        "description": "Divulgación de información sensible y errores",
        "severity": "MEDIUM",
        "cve_ref": None,
        "templates": [
            'site:{platform} intitle:"error" "{company}"',
            'site:{platform} "stack trace" "{company}"',
            'site:{platform} "Internal Server Error" "{company}"',
            'site:{platform} "supabase" "anon" "JWT" "{company}"',
        ],
    },
    "rls_and_auth_bypass": {
        "description": "RLS deshabilitado / bypass de autenticación (patrón CVE-2025-48757)",
        "severity": "CRITICAL",
        "cve_ref": "CVE-2025-48757",
        "templates": [
            'site:{platform} inurl:/rest/v1/users "apikey" "{company}"',
            'site:{platform} "enable_rls" "false" "{company}"',
            'site:{platform} inurl:supabase "policy" "USING (true)" "{company}"',
            'site:{platform} "createClient" "service_role" "{company}"',
        ],
    },
}


def generate_dorks(domain: str, company: str) -> dict:
    """Genera Google Dorks estructurados para OSINT pasivo."""
    results = {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "target_domain": domain,
            "target_company": company,
            "total_dorks": 0,
            "disclaimer": (
                "Solo para investigación ética autorizada. "
                "Ejecutar manualmente en motores de búsqueda."
            ),
        },
        "categories": {},
    }

    total = 0
    for cat_name, cat_data in DORK_CATEGORIES.items():
        results["categories"][cat_name] = {
            "description": cat_data["description"],
            "severity": cat_data["severity"],
            "cve_ref": cat_data.get("cve_ref"),
            "dorks": [],
        }
        for platform_name, platform_domain in VIBE_PLATFORMS.items():
            for template in cat_data["templates"]:
                dork = template.format(
                    platform=platform_domain,
                    company=company,
                    domain=domain,
                )
                results["categories"][cat_name]["dorks"].append(
                    {
                        "platform": platform_name,
                        "query": dork,
                        "search_url": f"https://www.google.com/search?q={dork.replace(' ', '+')}",
                    }
                )
                total += 1

    results["metadata"]["total_dorks"] = total
    return results


def generate_markdown_report(dorks: dict, output_path: Path) -> None:
    """Genera reporte Markdown legible con los dorks."""
    lines = [
        "# Reporte OSINT - VibeCoding Security Toolkit",
        "",
        f"**Empresa/Organización:** `{dorks['metadata']['target_company']}`",
        f"**Dominio objetivo:** `{dorks['metadata']['target_domain']}`",
        f"**Generado:** {dorks['metadata']['generated_at']}",
        f"**Total de consultas:** {dorks['metadata']['total_dorks']}",
        "",
        "> ⚠️ **AVISO:** Estas búsquedas son solo para investigación ética autorizada.",
        "> Ejecutar **manualmente** en motores de búsqueda. No automatizar sin permiso.",
        "",
        "---",
        "",
        "## Categorías de búsqueda",
        "",
    ]

    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    for cat_name, cat_data in dorks["categories"].items():
        emoji = severity_emoji.get(cat_data["severity"], "⚪")
        count = len(cat_data["dorks"])
        lines += [
            f"### {emoji} {cat_data['description']} (`{cat_data['severity']}`)",
            f"*{count} consultas generadas*",
            "",
            "| Plataforma | Consulta Google Dork |",
            "|-----------|---------------------|",
        ]
        seen_platforms = set()
        for dork in cat_data["dorks"]:
            if dork["platform"] not in seen_platforms:
                seen_platforms.add(dork["platform"])
                safe_query = dork["query"].replace("|", "\\|")
                lines.append(f"| `{dork['platform']}` | `{safe_query}` |")
        lines += ["", ""]

    lines += [
        "---",
        "",
        "## Instrucciones de uso ético",
        "",
        "1. Copia cada consulta y pégala **manualmente** en Google/Bing",
        "2. Revisa los resultados buscando exposiciones accidentales",
        "3. **NO** accedas a sistemas sin autorización explícita",
        "4. Documenta hallazgos con capturas de pantalla (sin interacción)",
        "5. Reporta responsablemente siguiendo el proceso de Responsible Disclosure",
        "",
        "## Plataformas cubiertas",
        "",
    ]
    for name, domain in VIBE_PLATFORMS.items():
        lines.append(f"- **{name}**: `{domain}`")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding OSINT Scanner - Generador de dorks para investigación ética"
    )
    parser.add_argument("--domain", default="ejemplo.com", help="Dominio objetivo")
    parser.add_argument("--company", default="Empresa Demo SA", help="Nombre de la empresa")
    parser.add_argument("--output", default="demo_output", help="Directorio de salida")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    print(f"\n[*] Generando dorks OSINT para: {args.company} ({args.domain})")
    dorks = generate_dorks(args.domain, args.company)

    json_path = output_dir / "dorks.json"
    json_path.write_text(json.dumps(dorks, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] JSON guardado: {json_path}")

    md_path = output_dir / "dorks_report.md"
    generate_markdown_report(dorks, md_path)
    print(f"[+] Reporte Markdown: {md_path}")

    print(f"\n[+] Total de consultas generadas: {dorks['metadata']['total_dorks']}")
    print("[!] Recuerda: Ejecutar manualmente en motores de búsqueda, nunca automatizar.\n")


if __name__ == "__main__":
    main()
