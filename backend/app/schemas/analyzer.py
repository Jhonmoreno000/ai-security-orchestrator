from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class TechStack(BaseModel):
    """Stack tecnologico detectado en el proyecto."""
    languages: list[str] = Field(default_factory=list, description="Lenguajes detectados (ej. Python, JavaScript)")
    frameworks: list[str] = Field(default_factory=list, description="Frameworks identificados (ej. FastAPI, React)")
    package_managers: list[str] = Field(default_factory=list, description="Gestores de paquetes (ej. pip, npm)")


class APIContract(BaseModel):
    """Contrato de API detectado en el proyecto."""
    has_openapi: bool = Field(default=False, description="True si encuentra OpenAPI/Swagger")
    has_graphql: bool = Field(default=False, description="True si encuentra esquemas GraphQL")
    spec_paths: list[str] = Field(default_factory=list, description="Rutas a archivos de especificacion")


class ProjectAnalysisResult(BaseModel):
    """Resultado consolidado del analisis del proyecto."""
    project_path: str = Field(..., description="Ruta del proyecto analizado")
    frontend: Optional[str] = Field(None, description="Framework frontend detectado")
    backend: Optional[str] = Field(None, description="Framework backend detectado")
    database: Optional[str] = Field(None, description="Base de datos detectada")
    containerized: bool = Field(default=False, description="True si tiene Dockerfile/docker-compose")
    api_contracts: APIContract = Field(default_factory=APIContract, description="Contratos de API detectados")
    tech_stack: TechStack = Field(default_factory=TechStack, description="Stack tecnologico completo")
    sensitive_files: list[str] = Field(default_factory=list, description="Archivos sensibles detectados")
    analyzed_at: datetime = Field(default_factory=datetime.utcnow, description="Fecha del analisis")
    metadata: dict = Field(default_factory=dict, description="Metadatos adicionales")
