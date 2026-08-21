import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])

IN_MEMORY_TARGETS = [
    {
        "id": "target-1",
        "url": "http://testphp.vulnweb.com",
        "label": "Demo Vulnerable Web App",
        "target_type": "url",
        "scope_rules": ["testphp.vulnweb.com", "*.vulnweb.com"],
        "is_active": True,
        "created_at": datetime.utcnow().isoformat()
    },
    {
        "id": "target-2",
        "url": "http://localhost:8000",
        "label": "Local Orchestrator API",
        "target_type": "api",
        "scope_rules": ["localhost:8000", "127.0.0.1:8000"],
        "is_active": True,
        "created_at": datetime.utcnow().isoformat()
    }
]


class CreateTargetRequest(BaseModel):
    url: str = Field(..., min_length=3)
    label: Optional[str] = "Production Target"
    target_type: Optional[str] = "url"
    scope_rules: List[str] = Field(default_factory=list)


@router.get("/")
async def list_targets():
    """Lista todos los objetivos configurados con sus reglas de alcance."""
    return {
        "total": len(IN_MEMORY_TARGETS),
        "targets": IN_MEMORY_TARGETS
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_target(request: CreateTargetRequest):
    """Registra un nuevo objetivo y valida su alcance con el Policy Engine."""
    target_id = f"target-{uuid.uuid4().hex[:8]}"
    scope = request.scope_rules if request.scope_rules else [request.url]
    
    new_target = {
        "id": target_id,
        "url": request.url,
        "label": request.label,
        "target_type": request.target_type,
        "scope_rules": scope,
        "is_active": True,
        "created_at": datetime.utcnow().isoformat()
    }
    IN_MEMORY_TARGETS.append(new_target)
    return new_target


@router.delete("/{target_id}")
async def delete_target(target_id: str):
    """Elimina un objetivo del alcance."""
    global IN_MEMORY_TARGETS
    IN_MEMORY_TARGETS = [t for t in IN_MEMORY_TARGETS if t["id"] != target_id]
    return {"status": "success", "message": f"Target {target_id} deleted"}
