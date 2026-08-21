# AI Security Orchestrator

Plataforma de auditoría de seguridad autónoma y multimotor, impulsada por IA local (Ollama / CodeLlama). Orquesta escáneres DAST, SAST, SCA y análisis de inteligencia artificial en contenedores Docker aislados.

---

## Visión del Producto

AI Security Orchestrator es una plataforma DevSecOps diseñada para ejecutar auditorías de seguridad completas de forma autónoma. Integra cuatro motores de escaneospecializados en contenedores Docker aislados, un motor de correlación SHA-256 para deduplicación de hallazgos, y un agente de IA que evalúa falsos positivos y genera parches de código.

**Características principales:**

- **4 Motores de Escaneo**: ZAP (DAST), Nuclei (CVE Templates), Semgrep (SAST), Trivy (SBOM/SCA)
- **Aislamiento Docker**: Cada escáner ejecuta en su propio contenedor con límites de recursos
- **Correlación SHA-256**: Deduplicación inteligente de hallazgos multi-escáner
- **AI Analyst (Ollama)**: Análisis de falsos positivos y generación de remediación
- **Retest Engine**: Verificación automática de correcciones con comparación de fingerprints
- **WebSocket en Tiempo Real**: Monitoreo en vivo del pipeline de auditoría
- **Reportes**: Generación de reportes JSON, HTML y PDF
- **Política de Seguridad**: Allowlist de herramientas y control de perímetros

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                      FRONTEND (React + Vite)                    │
│  Dashboard │ Scans │ Findings │ AI Assistant │ Reports │ Targets│
└───────────────────────────┬─────────────────────────────────────┘
                            │ WebSocket + REST API
┌───────────────────────────┴─────────────────────────────────────┐
│                    BACKEND (FastAPI + Python)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │   API    │ │WebSocket │ │ Correlation│ │  Retest Engine   │  │
│  │  Router  │ │ Manager  │ │  Engine    │ │  (SHA-256)       │  │
│  └────┬─────┘ └────┬─────┘ └─────┬─────┘ └────────┬─────────┘  │
│       │            │             │                 │             │
│  ┌────┴────────────┴─────────────┴─────────────────┴──────────┐ │
│  │              Runner Factory + BaseToolRunner                │ │
│  └───┬──────────┬──────────────┬──────────────┬───────────────┘ │
│      │          │              │              │                  │
│  ┌───┴──┐  ┌───┴────┐  ┌─────┴─────┐  ┌────┴──────┐           │
│  │ ZAP  │  │ Nuclei │  │  Semgrep  │  │   Trivy   │           │
│  │ DAST │  │  CVE   │  │   SAST    │  │   SBOM    │           │
│  └──┬───┘  └───┬────┘  └─────┬─────┘  └────┬──────┘           │
│     └──────────┴──────────────┴─────────────┘                   │
│                    Docker Containers (aislados)                  │
└─────────────────────────────────────────────────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
    ┌────┴────┐       ┌────┴────┐       ┌────┴────┐
    │PostgreSQL│       │  Redis  │       │ Ollama  │
    │  ( datos)│       │ (cache) │       │  (LLM)  │
    └─────────┘       └─────────┘       └─────────┘
```

---

## Requisitos

- **Docker** >= 24.0
- **Docker Compose** >= 2.20
- **Kali Linux** (recomendado) o cualquier distribución Linux
- **16 GB RAM** mínimo (para ejecutar todos los escáneres simultáneamente)
- **Puertos disponibles**: 80 (Frontend), 8000 (Backend), 5432 (PostgreSQL), 6379 (Redis)

### Opcional (para AI Analyst)

- **Ollama** instalado y ejecutándose en el host
- Modelo descargado: `ollama pull codellama`

---

## Instalación y Levantamiento

```bash
# 1. Clonar el repositorio
git clone https://github.com/Jhonmoreno000/ai-security-orchestrator.git
cd ai-security-orchestrator

# 2. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus configuraciones

# 3. Levantar todos los servicios
docker-compose up -d --build

# 4. Verificar estado
docker-compose ps
curl http://localhost:8000/health
```

### Acceso a la Plataforma

| Servicio | URL |
|----------|-----|
| Frontend (Dashboard) | http://localhost |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |

---

## Variables de Entorno

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| `POSTGRES_SERVER` | Host de PostgreSQL | `postgres` |
| `POSTGRES_DB` | Nombre de la base de datos | `orchestrator_db` |
| `POSTGRES_USER` | Usuario de PostgreSQL | `orchestrator_user` |
| `POSTGRES_PASSWORD` | Contraseña de PostgreSQL | `orchestrator_pass_secure` |
| `REDIS_HOST` | Host de Redis | `redis` |
| `OLLAMA_BASE_URL` | URL de Ollama | `http://host.docker.internal:11434` |
| `OLLAMA_MODEL` | Modelo de LLM | `codellama` |
| `AI_PROVIDER` | Proveedor de IA | `ollama` |
| `PRIVACY_MODE` | Modo de privacidad | `local` |
| `JOB_TIMEOUT` | Timeout de escáneres (seg) | `300` |
| `MAX_CONCURRENCY` | Concurrencia máxima | `2` |

---

## Stack Tecnológico

- **Backend**: Python 3.12, FastAPI, SQLAlchemy, Pydantic v2
- **Frontend**: React 18, TypeScript 5.3, Vite 5, Tailwind CSS 3.4
- **Base de Datos**: PostgreSQL 15, Redis 7
- **Contenedores**: Docker, Docker Compose
- **Escáneres**: ZAP, Nuclei, Semgrep, Trivy
- **IA**: Ollama (CodeLlama)
- **Comunicación**: WebSocket, REST API

---

## Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles.
