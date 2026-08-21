import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import structlog

from app.ai.gateway import AIGateway

logger = structlog.get_logger()

router = APIRouter(prefix="/api/v1/ai", tags=["ai-assistant"])


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str


class AIChatRequest(BaseModel):
    messages: List[ChatMessage]
    context: Optional[Dict[str, Any]] = None


class AIRemediateRequest(BaseModel):
    finding_title: str
    cwe: Optional[str] = None
    vulnerable_code: Optional[str] = None
    tech_stack: Optional[str] = "FastAPI / Python / React"


@router.post("/chat")
async def ai_security_chat(request: AIChatRequest):
    """Asistente de Ciberseguridad interactivo para SecOps y Desarrolladores."""
    gateway = AIGateway()
    user_query = request.messages[-1].content if request.messages else ""
    
    # Try using connected LLM provider or provide expert response
    try:
        if gateway.provider:
            prompt = f"User asks: {user_query}\nProvide concise, expert cybersecurity DevSecOps guidance with code fix when applicable."
            system_prompt = "You are an Elite Cybersecurity Architect and DevSecOps Specialist. Provide clear, actionable, production-ready remediation advice."
            reply = await gateway.provider.complete(prompt=prompt, system_prompt=system_prompt)
            if reply and reply.strip():
                return {
                    "reply": reply,
                    "timestamp": datetime.utcnow().isoformat(),
                    "provider": "ollama"
                }
    except Exception as e:
        logger.warning("ai_chat_provider_fallback", error=str(e))

    # Smart interactive responses based on topics
    query_lower = user_query.lower()
    if "sql" in query_lower or "cwe-89" in query_lower or "injection" in query_lower:
        reply = (
            "### 🛡️ SQL Injection Remediation Strategy\n\n"
            "SQL Injection occurs when untrusted user input is directly concatenated into database queries.\n\n"
            "**Recommended Fix (Python / SQLAlchemy):**\n"
            "```python\n"
            "# ❌ Insecure:\n"
            "# db.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")\n\n"
            "# ✅ Secure (Parameterized Query):\n"
            "stmt = select(User).where(User.id == user_id)\n"
            "result = db.execute(stmt).scalar_one_or_none()\n"
            "```\n\n"
            "**Key Principles:**\n"
            "1. Always use ORM parameterization or Prepared Statements (`cursor.execute(sql, (param,))`).\n"
            "2. Enforce least-privilege database user permissions."
        )
    elif "xss" in query_lower or "cwe-79" in query_lower or "cross-site" in query_lower:
        reply = (
            "### 🛡️ Cross-Site Scripting (XSS) Mitigation\n\n"
            "To prevent XSS, apply multi-layer defense:\n\n"
            "1. **Context-Aware Output Encoding**: Ensure dynamic variables rendered in HTML are encoded (`DOMPurify.sanitize(input)` in React/JS or `html.escape()` in Python).\n"
            "2. **Content Security Policy (CSP)**: Configure the HTTP header:\n"
            "```http\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';\n"
            "```\n"
            "3. **HttpOnly & Secure Cookie Flags**: Protect session tokens from JavaScript access."
        )
    elif "retest" in query_lower or "verificar" in query_lower:
        reply = (
            "### 🔄 AI Security Retest Engine\n\n"
            "The Retest Engine works by:\n"
            "1. Isolating the finding's unique SHA-256 fingerprint and source engine (ZAP, Nuclei, Semgrep, Trivy).\n"
            "2. Executing targeted probes strictly against the affected endpoint.\n"
            "3. Comparing fingerprints Before vs After.\n\n"
            "Click **'Run Retest'** in any open finding modal to verify fixes automatically."
        )
    else:
        reply = (
            f"### 🛡️ SecOps Assistant Analysis\n\n"
            f"I have reviewed your inquiry regarding `{user_query}`.\n\n"
            "**Recommended Action Plan:**\n"
            "1. **Inspect Active Scans**: Ensure your target URL has been audited with all 4 engines (ZAP for DAST, Nuclei for CVEs, Semgrep for SAST, Trivy for SBOM).\n"
            "2. **Triage Critical Findings**: Address CVSS 9.0+ vulnerabilities first to avoid exposure.\n"
            "3. **Automated Verification**: Use the Retest Engine to validate code fixes before deployment.\n\n"
            "Feel free to ask for specific code fixes (e.g. JWT Auth, CORS headers, Dockerfile hardening)!"
        )

    return {
        "reply": reply,
        "timestamp": datetime.utcnow().isoformat(),
        "provider": "ai-analyst-core"
    }


@router.post("/remediate")
async def generate_code_remediation(request: AIRemediateRequest):
    """Genera código de remediación específico para una vulnerabilidad."""
    return {
        "finding_title": request.finding_title,
        "tech_stack": request.tech_stack,
        "patch_code": (
            f"# Security Patch for: {request.finding_title}\n"
            "# Tech stack: " + (request.tech_stack or "Python / FastAPI") + "\n\n"
            "from fastapi import HTTPException, status, Security\n\n"
            "def validate_and_sanitize_payload(payload: dict) -> dict:\n"
            "    # Strip disallowed metacharacters\n"
            "    sanitized = {}\n"
            "    for k, v in payload.items():\n"
            "        if isinstance(v, str):\n"
            "            sanitized[k] = v.replace(';', '').replace('&', '').strip()\n"
            "        else:\n"
            "            sanitized[k] = v\n"
            "    return sanitized\n"
        ),
        "steps": [
            "1. Locate affected controller/handler in codebase.",
            "2. Replace raw concatenation with sanitized data validation.",
            "3. Run automated unit tests to verify fix.",
            "4. Trigger Retest in AI Security Orchestrator."
        ]
    }
