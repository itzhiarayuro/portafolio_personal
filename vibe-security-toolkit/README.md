# VibeCoding Security Toolkit

Herramientas Python para investigación ética de seguridad en aplicaciones generadas por IA (Vibe Coding).

> ⚠️ **AVISO LEGAL:** Solo para uso educativo, bug bounty autorizado e investigación ética con permiso explícito. El acceso no autorizado a sistemas es ilegal.

## Módulos

| Archivo | Función |
|---------|---------|
| `osint_scanner.py` | Genera Google Dorks para 11 plataformas de Vibe Coding |
| `header_analyzer.py` | Análisis pasivo de headers HTTP de seguridad |
| `report_generator.py` | Reportes profesionales de Responsible Disclosure |
| `notification_templates.py` | Plantillas de email ético (ES/EN) |
| `example_workflow.py` | Flujo completo de demostración |

## Uso rápido

```bash
# Flujo completo con datos de ejemplo
python3 example_workflow.py --domain tudominio.com --company "Tu Empresa"

# Solo OSINT
python3 osint_scanner.py --domain tudominio.com --company "Tu Empresa"

# Solo análisis de headers
python3 header_analyzer.py --url https://tuapp.com

# Solo reporte
python3 report_generator.py --org "Empresa" --researcher "Tu Nombre" --email tu@email.com
```

## Plataformas cubiertas

Lovable, Replit, Netlify, Vercel, Base44, Bolt, Firebase, Surge, Glitch, Heroku, Render

## Vulnerabilidades típicas en Vibe Coding

| Vulnerabilidad | Severidad | Mitigación |
|----------------|-----------|-----------|
| RLS Deshabilitado (Supabase) | 🔴 CRITICAL | `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` |
| API Keys hardcodeadas | 🔴 CRITICAL | Variables de entorno + backend proxy |
| Panel /admin sin auth | 🟠 HIGH | OAuth2 + MFA + RBAC |
| CORS Wildcard | 🟡 MEDIUM | Dominios explícitos |
| Headers faltantes | 🟢 LOW | Configurar en servidor/CDN |

## Sin dependencias externas

Solo biblioteca estándar de Python 3.8+. No requiere `pip install`.
