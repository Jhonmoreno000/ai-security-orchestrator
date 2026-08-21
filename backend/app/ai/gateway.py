import os
import re
from typing import Any

import structlog

from app.ai.base_provider import BaseAIProvider
from app.schemas.ai import (
    AIProviderConfig,
    AIProviderType,
    SanitizationResult,
)

logger = structlog.get_logger()

AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama")

SANITIZATION_PATTERNS = [
    (r'(?i)(api[_-]?key\s*[=:]\s*)["\']?([A-Za-z0-9\-_]{20,})["\']?', "API_KEY"),
    (r'(?i)(token\s*[=:]\s*)["\']?([A-Za-z0-9\-_\.]{20,})["\']?', "TOKEN"),
    (r'(?i)(secret\s*[=:]\s*)["\']?([A-Za-z0-9\-_]{16,})["\']?', "SECRET"),
    (r'(?i)(password\s*[=:]\s*)["\']?([^\s"\']{8,})["\']?', "PASSWORD"),
    (r'(?i)(bearer\s+)([A-Za-z0-9\-_\.]{20,})', "BEARER_TOKEN"),
    (r'(?i)(authorization\s*[=:]\s*)["\']?(Basic\s+[A-Za-z0-9+/=]{20,})["\']?', "BASIC_AUTH"),
    (r'(?i)(aws[_-]?(?:access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\s*[=:]\s*)["\']?([A-Za-z0-9/+=]{16,})["\']?', "AWS_KEY"),
    (r'(?i)(ghp_[A-Za-z0-9]{36})', "GITHUB_TOKEN"),
    (r'(?i)(sk-[A-Za-z0-9]{20,})', "OPENAI_KEY"),
    (r'(?i)(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.]+)', "JWT_TOKEN"),
]


class AISanitizer:
    """Sanitizacion basica para enmascarar secretos antes de enviarlos a IA.

    Detecta y enmascara:
    - API keys
    - Tokens
    - Secrets
    - Passwords
    - Bearer tokens
    - AWS keys
    - GitHub tokens
    - OpenAI keys
    - JWT tokens
    """

    def __init__(self):
        self._compiled = [
            (re.compile(pattern), mask_name)
            for pattern, mask_name in SANITIZATION_PATTERNS
        ]

    def sanitize(self, text: str) -> SanitizationResult:
        """Enmascara secretos en el texto.

        Args:
            text: Texto a sanitizar.

        Returns:
            SanitizationResult con el texto sanitizado y metadata.
        """
        if not text:
            return SanitizationResult(original=text, sanitized=text)

        sanitized = text
        masks_count = 0
        patterns_matched: list[str] = []

        for pattern, mask_name in self._compiled:
            matches = pattern.findall(sanitized)
            if matches:
                masks_count += len(matches)
                if mask_name not in patterns_matched:
                    patterns_matched.append(mask_name)
                sanitized = pattern.sub(f"[REDACTED_{mask_name}]", sanitized)

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            masks_count=masks_count,
            patterns_matched=patterns_matched,
        )

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Enmascara secretos en un diccionario."""
        sanitized = {}
        for key, value in data.items():
            if isinstance(value, str):
                result = self.sanitize(value)
                sanitized[key] = result.sanitized
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_dict(item) if isinstance(item, dict)
                    else self.sanitize(item).sanitized if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized


class AIGateway:
    """Gateway unificado para interactuar con proveedores de IA.

    Funcionalidades:
    - Lee AI_PROVIDER del entorno (ollama, openai, gemini)
    - Instancia el proveedor correspondiente de forma transparente
    - Sanitizacion basica antes de enviar texto a IA
    """

    def __init__(self, provider_name: str | None = None):
        self._provider_name = provider_name or AI_PROVIDER
        self._provider: BaseAIProvider | None = None
        self._sanitizer = AISanitizer()
        self._initialize_provider()

    def _initialize_provider(self) -> None:
        """Inicializa el proveedor segun la variable de entorno AI_PROVIDER."""
        if self._provider_name == "ollama":
            self._init_ollama()
        elif self._provider_name == "openai":
            self._init_openai()
        elif self._provider_name == "gemini":
            self._init_gemini()
        else:
            logger.warning("ai_provider_unknown", provider=self._provider_name)
            self._init_ollama()

    def _init_ollama(self) -> None:
        """Inicializa el proveedor Ollama."""
        try:
            from app.ai.ollama_provider import OllamaProvider
            config = AIProviderConfig(
                provider_type=AIProviderType.OLLAMA,
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
                model=os.getenv("OLLAMA_MODEL", "codellama"),
            )
            self._provider = OllamaProvider(config)
            logger.info("ai_provider_initialized", provider="ollama")
        except Exception as e:
            logger.error("ai_provider_init_failed", provider="ollama", error=str(e))

    def _init_openai(self) -> None:
        """Inicializa el proveedor OpenAI."""
        logger.info("ai_provider_initialized", provider="openai (stub)")
        self._provider = None

    def _init_gemini(self) -> None:
        """Inicializa el proveedor Gemini."""
        logger.info("ai_provider_initialized", provider="gemini (stub)")
        self._provider = None

    @property
    def provider(self) -> BaseAIProvider | None:
        """Retorna el proveedor activo."""
        return self._provider

    @property
    def provider_name(self) -> str:
        """Retorna el nombre del proveedor activo."""
        return self._provider_name

    def sanitize_text(self, text: str) -> SanitizationResult:
        """Sanitiza texto antes de enviarlo a IA.

        Args:
            text: Texto a sanitizar.

        Returns:
            SanitizationResult con el texto sanitizado.
        """
        return self._sanitizer.sanitize(text)

    def sanitize_for_ai(self, text: str) -> str:
        """Sanitiza texto y retorna solo el texto limpio.

        Args:
            text: Texto a sanitizar.

        Returns:
            Texto sanitizado.
        """
        result = self._sanitizer.sanitize(text)
        if result.masks_count > 0:
            logger.info(
                "ai_text_sanitized",
                masks=result.masks_count,
                patterns=result.patterns_matched,
            )
        return result.sanitized

    def sanitize_dict_for_ai(self, data: dict[str, Any]) -> dict[str, Any]:
        """Sanitiza un diccionario completo antes de enviarlo a IA.

        Args:
            data: Diccionario a sanitizar.

        Returns:
            Diccionario sanitizado.
        """
        return self._sanitizer.sanitize_dict(data)

    async def health_check(self) -> dict[str, bool]:
        """Verifica salud del proveedor."""
        if self._provider is None:
            return {self._provider_name: False}
        try:
            result = await self._provider.health_check()
            return {self._provider_name: result}
        except Exception as e:
            logger.error("ai_health_check_failed", provider=self._provider_name, error=str(e))
            return {self._provider_name: False}

    async def close(self):
        """Cierra conexiones del proveedor."""
        if self._provider and hasattr(self._provider, "close"):
            await self._provider.close()
