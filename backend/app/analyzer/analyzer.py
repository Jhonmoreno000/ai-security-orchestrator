import os
from pathlib import Path

import structlog

from app.schemas.analyzer import (
    APIContract,
    ProjectAnalysisResult,
    TechStack,
)

logger = structlog.get_logger()

LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "React",
    ".tsx": "React TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".r": "R",
    ".sql": "SQL",
    ".sh": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".vue": "Vue",
    ".svelte": "Svelte",
}

FRAMEWORK_INDICATORS = {
    "fastapi": "FastAPI",
    "django": "Django",
    "flask": "Flask",
    "express": "Express",
    "next": "Next.js",
    "nuxt": "Nuxt.js",
    "react": "React",
    "vue": "Vue",
    "angular": "Angular",
    "svelte": "Svelte",
    "spring": "Spring",
    "rails": "Rails",
    "laravel": "Laravel",
    "gin": "Gin",
    "fiber": "Fiber",
    "actix": "Actix",
    "rocket": "Rocket",
}

PACKAGE_MANAGER_FILES = {
    "requirements.txt": "pip",
    "setup.py": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pipenv",
    "poetry.lock": "poetry",
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Gemfile": "bundler",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "composer.json": "composer",
    "Package.swift": "swift",
}

DATABASE_INDICATORS = {
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mysql": "MySQL",
    "sqlite": "SQLite",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "redis": "Redis",
    "elasticsearch": "Elasticsearch",
    "cassandra": "Cassandra",
    "dynamodb": "DynamoDB",
}

SENSITIVE_FILE_PATTERNS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.staging",
    ".env.example",
    ".env.sample",
    "credentials.json",
    "service-account.json",
    "*.pem",
    "*.key",
    "*.cert",
    "id_rsa",
    "id_ed25519",
    ".htpasswd",
    ".netrc",
]

CONTAINER_FILES = [
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.dev.yml",
    "docker-compose.prod.yml",
    ".dockerignore",
]


class ProjectAnalyzer:
    """Analizador de proyectos que detecta tecnologias, APIs y configuraciones.

    Escanea el directorio objetivo y genera un mapa estructurado del stack:
    - Deteccion de Manifests (package.json, pom.xml, requirements.txt)
    - Identificacion de APIs (openapi.yaml, swagger.json, graphql)
    - Deteccion de Infraestructura (Dockerfile, docker-compose.yml)
    - Identificacion de Archivos Sensibles (.env.example, configs)
    """

    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self._detected_languages: set[str] = set()
        self._detected_frameworks: set[str] = set()
        self._detected_packages: set[str] = set()
        self._sensitive_files: list[str] = []

    def analyze(self) -> ProjectAnalysisResult:
        """Analiza el proyecto y retorna un resultado consolidado.

        Returns:
            ProjectAnalysisResult con el analisis completo.
        """
        logger.info("project_analysis_started", path=str(self.project_path))

        if not self.project_path.exists():
            logger.warning("project_path_not_found", path=str(self.project_path))
            return ProjectAnalysisResult(
                project_path=str(self.project_path),
                metadata={"error": "Path not found"},
            )

        self._scan_files(self.project_path)

        languages = list(self._detected_languages)
        frameworks = list(self._detected_frameworks)
        package_managers = list(self._detected_packages)

        api_contracts = self._detect_api_contracts()
        containerized = self._detect_containerization()
        backend = self._detect_backend()
        frontend = self._detect_frontend()
        database = self._detect_database()

        result = ProjectAnalysisResult(
            project_path=str(self.project_path),
            frontend=frontend,
            backend=backend,
            database=database,
            containerized=containerized,
            api_contracts=api_contracts,
            tech_stack=TechStack(
                languages=languages,
                frameworks=frameworks,
                package_managers=package_managers,
            ),
            sensitive_files=self._sensitive_files,
            metadata={
                "total_files_scanned": self._count_files(),
            },
        )

        logger.info(
            "project_analysis_completed",
            path=str(self.project_path),
            languages=languages,
            frameworks=frameworks,
            containerized=containerized,
        )

        return result

    def _scan_files(self, directory: Path, depth: int = 0) -> None:
        """Escanea archivos recursivamente."""
        if depth > 10:
            return

        try:
            for item in directory.iterdir():
                if item.name.startswith(".") and item.name not in [".env", ".env.example"]:
                    continue

                if item.is_dir():
                    if item.name not in ["node_modules", "__pycache__", ".git", "venv", ".venv", "vendor"]:
                        self._scan_files(item, depth + 1)
                elif item.is_file():
                    self._analyze_file(item)
        except PermissionError:
            pass

    def _analyze_file(self, file_path: Path) -> None:
        """Analiza un archivo individual."""
        ext = file_path.suffix.lower()
        name = file_path.name.lower()

        if ext in LANGUAGE_EXTENSIONS:
            lang = LANGUAGE_EXTENSIONS[ext]
            if lang not in ["YAML", "JSON", "XML", "HTML", "CSS", "SCSS"]:
                self._detected_languages.add(lang)

        if name in PACKAGE_MANAGER_FILES:
            self._detected_packages.add(PACKAGE_MANAGER_FILES[name])

        for pattern in SENSITIVE_FILE_PATTERNS:
            if file_path.match(pattern) or file_path.name == pattern:
                rel_path = str(file_path.relative_to(self.project_path))
                if rel_path not in self._sensitive_files:
                    self._sensitive_files.append(rel_path)

        self._detect_framework_from_file(file_path)

    def _detect_framework_from_file(self, file_path: Path) -> None:
        """Detecta frameworks basado en el nombre del archivo."""
        name = file_path.name.lower()

        if name == "package.json":
            try:
                import json
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for dep in deps:
                        if dep.lower() in FRAMEWORK_INDICATORS:
                            self._detected_frameworks.add(FRAMEWORK_INDICATORS[dep.lower()])
            except (json.JSONDecodeError, Exception):
                pass

        elif name == "requirements.txt" or name == "pyproject.toml":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                    for indicator, framework in FRAMEWORK_INDICATORS.items():
                        if indicator in content:
                            self._detected_frameworks.add(framework)
            except Exception:
                pass

    def _detect_api_contracts(self) -> APIContract:
        """Detecta especificaciones de API."""
        has_openapi = False
        has_graphql = False
        spec_paths: list[str] = []

        openapi_files = [
            "openapi.yaml",
            "openapi.json",
            "swagger.yaml",
            "swagger.json",
            "api-spec.yaml",
            "api-spec.json",
        ]

        graphql_files = [
            "schema.graphql",
            "graphql.schema",
            "*.graphql",
        ]

        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]

            for file in files:
                file_lower = file.lower()
                rel_path = str(Path(root).relative_to(self.project_path) / file)

                if file_lower in openapi_files or "openapi" in file_lower or "swagger" in file_lower:
                    has_openapi = True
                    if rel_path not in spec_paths:
                        spec_paths.append(rel_path)

                if file_lower.endswith(".graphql") or "graphql" in file_lower:
                    has_graphql = True
                    if rel_path not in spec_paths:
                        spec_paths.append(rel_path)

        return APIContract(
            has_openapi=has_openapi,
            has_graphql=has_graphql,
            spec_paths=spec_paths,
        )

    def _detect_containerization(self) -> bool:
        """Detecta si el proyecto esta containerizado."""
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git"]]

            for file in files:
                if file in CONTAINER_FILES:
                    return True

            break

        return False

    def _detect_backend(self) -> str | None:
        """Detecta el framework backend."""
        for framework in self._detected_frameworks:
            if framework in ["FastAPI", "Django", "Flask", "Express", "Spring", "Rails", "Laravel", "Gin", "Fiber", "Actix", "Rocket"]:
                return framework
        return None

    def _detect_frontend(self) -> str | None:
        """Detecta el framework frontend."""
        for framework in self._detected_frameworks:
            if framework in ["React", "Vue", "Angular", "Svelte", "Next.js", "Nuxt.js"]:
                return framework
        return None

    def _detect_database(self) -> str | None:
        """Detecta la base de datos."""
        try:
            for root, dirs, files in os.walk(self.project_path):
                dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]

                for file in files:
                    if file.lower() in ["docker-compose.yml", "docker-compose.yaml"]:
                        import yaml
                        with open(Path(root) / file, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if data and "services" in data:
                                for service_name, service_config in data["services"].items():
                                    image = service_config.get("image", "").lower()
                                    for db_key, db_name in DATABASE_INDICATORS.items():
                                        if db_key in image or db_key in service_name.lower():
                                            return db_name

                break
        except Exception:
            pass

        return None

    def _count_files(self) -> int:
        """Cuenta el numero total de archivos."""
        count = 0
        for root, dirs, files in os.walk(self.project_path):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__", "venv", ".venv"]]
            count += len(files)
        return count
