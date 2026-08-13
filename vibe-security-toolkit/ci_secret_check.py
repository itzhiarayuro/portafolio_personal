#!/usr/bin/env python3
"""
VibeCoding CI Secret Checker — Scanner local de secretos y patrones inseguros.

Solo analiza el árbol de trabajo del repositorio. No hace conexiones externas.
Diseñado para ejecutarse en CI/CD (GitHub Actions, GitLab CI) y en pre-commit.

Uso:
  python3 ci_secret_check.py --path .
  python3 ci_secret_check.py --path . --fail-on high
  python3 ci_secret_check.py --path . --json
"""

import re
import sys
import json
import argparse
import datetime
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SECRET_PATTERNS = [
    {
        "id": "SUPABASE_SERVICE_ROLE_JWT",
        "description": "Supabase service_role JWT embebido",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(
            r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            re.IGNORECASE,
        ),
        "context_check": re.compile(r'service.?role', re.IGNORECASE),
        "requires_context": True,
        "remediation": "Rota el JWT de inmediato. Nunca incluyas service_role en el frontend.",
    },
    {
        "id": "SUPABASE_SERVICE_ROLE_VAR",
        "description": "Variable SUPABASE_SERVICE_ROLE_KEY asignada",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(
            r'(?:SUPABASE_SERVICE_ROLE_KEY|VITE_SUPABASE_SERVICE_ROLE|NEXT_PUBLIC_SUPABASE_SERVICE_ROLE)\s*[=:]\s*["\']?[A-Za-z0-9._\-]{20,}',
            re.IGNORECASE,
        ),
        "requires_context": False,
        "remediation": (
            "Elimina la SERVICE_ROLE key del frontend. "
            "Úsala solo en Edge Functions o backend propio."
        ),
    },
    {
        "id": "SUPABASE_RLS_DISABLED",
        "description": "RLS deshabilitado en Supabase (patrón CVE-2025-48757)",
        "severity": "CRITICAL",
        "cwe": "CWE-285",
        "pattern": re.compile(
            r'(?:DISABLE ROW LEVEL SECURITY|enable_rls.*false|USING\s*\(\s*true\s*\))',
            re.IGNORECASE,
        ),
        "requires_context": False,
        "remediation": (
            "Habilita RLS: ALTER TABLE ... ENABLE ROW LEVEL SECURITY; "
            "y crea políticas específicas por operación."
        ),
    },
    {
        "id": "STRIPE_LIVE_KEY",
        "description": "Stripe secret key de producción (sk_live_)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
        "requires_context": False,
        "remediation": "Rota la clave en dashboard.stripe.com. Usa variables de entorno del servidor.",
    },
    {
        "id": "OPENAI_KEY",
        "description": "OpenAI API key (sk-proj-)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(r'sk-proj-[A-Za-z0-9_\-]{40,}'),
        "requires_context": False,
        "remediation": "Rota en platform.openai.com. Nunca expongas en variables VITE_ o NEXT_PUBLIC_.",
    },
    {
        "id": "ANTHROPIC_KEY",
        "description": "Anthropic/Claude API key (sk-ant-)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(r'sk-ant-[A-Za-z0-9_\-]{40,}'),
        "requires_context": False,
        "remediation": "Rota en console.anthropic.com. Usa solo en backend.",
    },
    {
        "id": "XAI_KEY",
        "description": "xAI API key",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(r'xai-[A-Za-z0-9]{40,}'),
        "requires_context": False,
        "remediation": "Rota la clave en el panel de xAI.",
    },
    {
        "id": "GOOGLE_FIREBASE_KEY",
        "description": "Google/Firebase API key (AIzaSy...)",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "pattern": re.compile(r'AIzaSy[A-Za-z0-9_\-]{33}'),
        "requires_context": False,
        "remediation": (
            "Restringe la clave en console.cloud.google.com a dominios y APIs específicas. "
            "Considera revocarla si está sin restricciones."
        ),
    },
    {
        "id": "AWS_ACCESS_KEY",
        "description": "AWS Access Key ID (AKIA...)",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(r'AKIA[A-Z0-9]{16}'),
        "requires_context": False,
        "remediation": "Rota en AWS IAM. Revisa CloudTrail para uso no autorizado.",
    },
    {
        "id": "AWS_SECRET_KEY",
        "description": "AWS Secret Access Key",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "pattern": re.compile(
            r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}',
            re.IGNORECASE,
        ),
        "requires_context": False,
        "remediation": "Rota en AWS IAM inmediatamente.",
    },
    {
        "id": "GENERIC_API_KEY_ASSIGNMENT",
        "description": "Asignación hardcodeada de api_key o secret",
        "severity": "MEDIUM",
        "cwe": "CWE-312",
        "pattern": re.compile(
            r'(?:api_key|apikey|api_secret|secret_key)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{16,}["\']',
            re.IGNORECASE,
        ),
        "requires_context": False,
        "remediation": "Mueve el valor a una variable de entorno del servidor.",
    },
    {
        "id": "PASSWORD_IN_CONFIG",
        "description": "Contraseña hardcodeada en archivo de configuración",
        "severity": "HIGH",
        "cwe": "CWE-259",
        "pattern": re.compile(
            r'(?:password|passwd|db_pass|db_password)\s*[=:]\s*["\'][^"\']{8,}["\']',
            re.IGNORECASE,
        ),
        "requires_context": False,
        "remediation": "Usa variables de entorno. Nunca hardcodees contraseñas.",
    },
    {
        "id": "SENDGRID_KEY",
        "description": "SendGrid API key",
        "severity": "HIGH",
        "cwe": "CWE-312",
        "pattern": re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        "requires_context": False,
        "remediation": "Rota en app.sendgrid.com.",
    },
    {
        "id": "STRIPE_TEST_KEY",
        "description": "Stripe test key (sk_test_) — bajo riesgo pero no debe estar en código",
        "severity": "LOW",
        "cwe": "CWE-312",
        "pattern": re.compile(r'sk_test_[A-Za-z0-9]{24,}'),
        "requires_context": False,
        "remediation": "Mueve a variable de entorno. Las test keys también pueden tener datos reales.",
    },
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".lock", ".map",
    ".pyc", ".pyo",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".nuxt", "coverage", ".pytest_cache",
    "demo_output",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "ci_secret_check.py",
    "github_secrets_dorks.py",
    "osint_scanner.py",
    ".gitleaks.toml",
}

ALLOWLIST_PATTERNS = [
    re.compile(r'sk_live_XXXX|sk_live_example|sk_live_YOUR', re.IGNORECASE),
    re.compile(r'AKIA_EXAMPLE|AKIAIOSFODNN7EXAMPLE', re.IGNORECASE),
    re.compile(r'your[-_]?api[-_]?key|YOUR_API_KEY|<API_KEY>|API_KEY_HERE', re.IGNORECASE),
    re.compile(r'example|placeholder|dummy|fake|test_only|redacted', re.IGNORECASE),
]


def is_allowlisted(line: str) -> bool:
    return any(p.search(line) for p in ALLOWLIST_PATTERNS)


def scan_file(file_path: Path) -> list:
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        if is_allowlisted(line):
            continue
        for rule in SECRET_PATTERNS:
            match = rule["pattern"].search(line)
            if not match:
                continue
            if rule.get("requires_context"):
                context_window = "\n".join(lines[max(0, line_num - 5):line_num + 5])
                if not rule["context_check"].search(context_window):
                    continue
            snippet = line.strip()
            if len(snippet) > 120:
                start = max(0, match.start() - 20)
                snippet = f"...{line[start:start+80]}..."
            findings.append(
                {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "cwe": rule["cwe"],
                    "file": str(file_path),
                    "line": line_num,
                    "snippet": snippet,
                    "remediation": rule["remediation"],
                }
            )
    return findings


def scan_path(root: Path) -> list:
    all_findings = []
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in file_path.parts):
            continue
        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        if file_path.name in SKIP_FILES:
            continue
        all_findings.extend(scan_file(file_path))
    return all_findings


def severity_passes_threshold(finding_sev: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return SEVERITY_ORDER.get(finding_sev, 99) <= SEVERITY_ORDER.get(threshold, 99)


def print_report(findings: list, root: Path) -> None:
    severity_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    if not findings:
        print("✅ No se encontraron secretos o patrones inseguros.")
        return

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    print(f"\n{'═' * 60}")
    print(f"  VIBE CODING CI SECRET CHECKER — {len(findings)} hallazgo(s)")
    print(f"{'═' * 60}\n")

    for f in sorted_findings:
        icon = severity_icons.get(f["severity"], "⚪")
        rel = Path(f["file"]).relative_to(root) if root in Path(f["file"]).parents else f["file"]
        print(f"  {icon} [{f['severity']}] {f['rule_id']}")
        print(f"     Archivo : {rel}:{f['line']}")
        print(f"     Snippet : {f['snippet'][:100]}")
        print(f"     CWE     : {f['cwe']}")
        print(f"     Fix     : {f['remediation']}")
        print()

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"{'─' * 60}")
    print("  RESUMEN:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in counts:
            print(f"    {severity_icons[sev]} {sev}: {counts[sev]}")
    print()
    print("  REMEDIACIÓN URGENTE si hay CRITICAL:")
    print("  1. Rota la clave comprometida INMEDIATAMENTE")
    print("  2. Elimina del historial: git filter-repo o BFG Repo Cleaner")
    print("  3. Añade .env* a .gitignore")
    print("  4. Para Supabase: ENABLE ROW LEVEL SECURITY en todas las tablas")
    print(f"{'═' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="VibeCoding CI Secret Checker — Scanner local de secretos"
    )
    parser.add_argument("--path", default=".", help="Ruta a escanear (por defecto: .)")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Severidad mínima para fallar el job CI (por defecto: high)",
    )
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    findings = scan_path(root)

    if args.json:
        output = {
            "scanned_at": datetime.datetime.now().isoformat(),
            "path": str(root),
            "total_findings": len(findings),
            "findings": findings,
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print_report(findings, root)

    threshold = args.fail_on.upper() if args.fail_on != "none" else "none"
    should_fail = any(severity_passes_threshold(f["severity"], threshold) for f in findings)
    sys.exit(1 if should_fail else 0)


if __name__ == "__main__":
    main()
