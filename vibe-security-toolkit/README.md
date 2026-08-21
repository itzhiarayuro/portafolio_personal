# Vibe Security Toolkit

Coleccion de scripts de seguridad ofensiva/defensiva para detectar secretos expuestos, analizar HTTP headers, escanear superficies de ataque (OSINT) y generar reportes automatizados en CI/CD.

## 🎯 Problema

Los equipos de desarrollo y seguridad enfrentan estos desafios:

- **Secretos expuestos en codigo**: API keys, tokens, passwords y credenciales hardcodeadas que se filtran a repositorios.
- **Falta de visibilidad en headers HTTP**: Configuraciones inseguras de headers que exponen aplicaciones a ataques comunes.
- **Superficie de ataque desconocida**: Subdominios, puertos y servicios expuestos sin inventario actualizado.
- **Reportes manuales y fragmentados**: Informes de seguridad que requieren trabajo manual y no se integran en pipelines CI/CD.

## 💡 Solucion

Vibe Security Toolkit automatiza estas tareas mediante scripts modulares en Python que pueden:

- Escanear codigo y commits en busca de patrones de secretos (API keys, tokens, credenciales).
- Analizar headers HTTP de dominios y detectar configuraciones inseguras.
- Realizar reconnaissance basico (OSINT) de dominios: subdominios, puertos abiertos, tecnologias detectadas.
- Generar reportes consolidados en formatos legibles (Markdown, HTML, JSON).
- Integrarse en pipelines CI/CD (GitHub Actions, GitLab CI) para escaneos automaticos en cada push/PR.

## ✨ Funcionalidades

- **Deteccion de secretos**: Busca patrones de API keys (AWS, GitHub, Stripe, Slack, etc.), tokens JWT, passwords y credenciales en archivos y diffs de Git.
- ** Analisis de headers HTTP**: Evalua headers de seguridad (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.) y reporta configuraciones faltantes o inseguras.
- **OSINT Scanner**: Realiza enumeracion de subdominios, escaneo de puertos basicos y deteccion de tecnologias web.
- **Generador de reportes**: Crea reportes consolidados en Markdown, HTML y JSON con hallazgos de todos los modulos.
- **Notificaciones**: Plantillas para notificaciones de hallazgos criticos (email, Slack, Teams - por configurar).
- **Integracion CI/CD**: Workflows de GitHub Actions y configuracion de GitLab CI para escaneos automaticos.
- **Configuracion de Gitleaks**: Archivo `.gitleaks.toml` con reglas personalizadas para deteccion de secretos.

## 🛠️ Tecnologias

| Tecnologia | Uso |
|---|---|
| Python 3 | Lenguaje principal de todos los scripts |
| requests | Peticiones HTTP para analisis de headers y OSINT |
| re (regex) | Expresiones regulares para patrones de secretos |
| json / csv | Manejo de datos estructurados y reportes |
| markdown / HTML | Generacion de reportes |
| GitHub Actions | Automatizacion de escaneos en CI/CD |
| GitLab CI | Pipeline alternativo de integracion continua |
| Gitleaks | Motor de deteccion de secretos (configuracion personalizada) |

## 🏗️ Arquitectura / Estructura

El proyecto sigue una arquitectura modular: cada script es independiente pero puede ser orquestado por el generador de reportes o por pipelines CI/CD.

```
vibe-security-toolkit/
├── .github/
│   └── workflows/
│       └── security-scan.yml        # Workflow de GitHub Actions para escaneos automaticos
├── .gitignore                       # Archivos y directorios ignorados por Git
├── .gitlab-ci.yml                   # Pipeline de GitLab CI para escaneos
├── .gitleaks.toml                   # Configuracion de reglas para deteccion de secretos
├── README.md                        # Documentacion del proyecto
├── ci_secret_check.py               # Script principal para deteccion de secretos en CI/CD
├── example_workflow.py              # Ejemplo de orquestacion de escaneos
├── github_secrets_dorks.py          # Patrones y dorks para busqueda de secretos en GitHub
├── header_analyzer.py               # Analisis de headers HTTP de dominios
├── notification_templates.py        # Plantillas para notificaciones de hallazgos
├── osint_scanner.py                 # Escaneo OSINT: subdominios, puertos, tecnologias
└── report_generator.py              # Generador de reportes consolidados (MD, HTML, JSON)
```

### Modulos principales

| Script | Responsabilidad |
|---|---|
| `ci_secret_check.py` | Escanea archivos y diffs de Git en busca de secretos; diseñado para ejecucion en CI/CD |
| `header_analyzer.py` | Analiza headers HTTP de un dominio y reporta configuraciones inseguras |
| `osint_scanner.py` | Realiza reconnaissance de dominios: subdominios, puertos, tecnologias detectadas |
| `report_generator.py` | Consolida hallazgos de todos los modulos y genera reportes en MD, HTML y JSON |
| `github_secrets_dorks.py` | Contiene patrones y dorks para busqueda de secretos en repositorios GitHub |
| `notification_templates.py` | Plantillas de mensajes para notificaciones de hallazgos criticos |
| `example_workflow.py` | Ejemplo de como orquestar multiples escaneos en un solo flujo |

## 🚀 Como ejecutar

### Requisitos previos

- Python 3.8+
- pip (gestor de paquetes de Python)

### Instalacion de dependencias

Los scripts utilizan librerias estandar de Python y algunas externas. Para instalar dependencias:

```bash
pip install requests
```

### Ejecutar escaneo de secretos

```bash
python ci_secret_check.py --path /ruta/a/tu/repositorio
```

O para escanear el repositorio actual:

```bash
python ci_secret_check.py --path .
```

### Analizar headers de un dominio

```bash
python header_analyzer.py --url https://ejemplo.com
```

### Ejecutar OSINT scanner

```bash
python osint_scanner.py --domain ejemplo.com
```

### Generar reporte consolidado

```bash
python report_generator.py --input hallazgos.json --output reporte.md
```

### Ejecutar workflow de ejemplo

```bash
python example_workflow.py --target ejemplo.com
```

## 🔧 Integracion CI/CD

### GitHub Actions

El archivo `.github/workflows/security-scan.yml` define un workflow que se ejecuta en cada push o pull request.

### GitLab CI

El archivo `.gitlab-ci.yml` configura un pipeline equivalente para GitLab.

## 📋 Estado actual del proyecto

- ✅ Deteccion de secretos funcional (patrones basicos y personalizados)
- ✅ Analisis de headers HTTP implementado
- ✅ OSINT scanner basico (subdominios, puertos, tecnologias)
- ✅ Generador de reportes en MD, HTML y JSON
- ✅ Integracion con GitHub Actions y GitLab CI
- ⚠️ Notificaciones: plantillas disponibles, integracion con Slack/Email por configurar
- ⚠️ OSINT: escaneo de puertos basico, puede requerir ajustes para entornos de produccion

## 🧠 Lo que aprendi / Problemas tecnicos resueltos

- **Patrones regex para secretos**: Diseñ¿½¿ expresiones regulares especificas para detectar API keys de AWS, GitHub, Stripe, Slack y otros servicios sin generar falsos positivos excesivos.
- **Analisis de headers seguro**: Implemente validacion de headers HTTP manejando timeouts, redirecciones y errores de conexion de forma robusta.
- **Orquestacion modular**: Estructuré¿½ los scripts para que puedan ejecutarse de forma independiente o ser orquestados por un workflow central.
- **Reportes consolidados**: Creé¿½ un generador que unifica hallazgos de multiples fuentes en formatos legibles para equipos tecnicos y no tecnicos.
- **CI/CD nativo**: Integre los escaneos directamente en pipelines de GitHub Actions y GitLab CI para deteccion temprana de vulnerabilidades.

## 🤝 Como contribuir

Si deseas contribuir:

1. Haz fork del repositorio
2. Crea una rama con tu feature (`git checkout -b feature/nueva-funcionalidad`)
3. Asegurate de que los scripts no introducen falsos positivos excesivos
4. Abre un Pull Request describiendo los cambios

### Areas de mejora potencial

- Mejorar patrones de deteccion de secretos (reducir falsos positivos)
- Ampliar capacidades de OSINT (integracion con APIs de Shodan, Censys, etc.)
- Agregar soporte para notificaciones reales (Slack, Email, Teams)
- Implementar escaneo de dependencias vulnerables (npm, pip, etc.)
- Añadir tests unitarios para cada modulo

## 📄 Licencia

Este proyecto es de codigo abierto. Se permite su uso, modificacion y distribucion bajo los terminos que el autor determine.

## ⚠️ Aviso legal

Este toolkit esta diseñado para fines educativos y de seguridad defensiva. Utilizalo solo en sistemas que tengas permiso para escanear. El autor no se responsabiliza por el uso inadecuado de estas herramientas.

---

**Autor**: [@itzhiarayuro](https://github.com/itzhiarayuro)  
**Ultima actualizacion**: Agosto 2025
