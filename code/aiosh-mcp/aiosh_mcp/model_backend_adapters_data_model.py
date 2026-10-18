"""AI Control Plane Model Backend Adapters Data Model (MODADAPT-INV1..MODADAPT-INV5).

Defines canonical representations and validation invariants for model providers,
messages, capabilities, requests, responses, and endpoint configurations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional

MODADAPT_ERR_INVALID_ROLE = "MODADAPT_ERR_INVALID_ROLE"
MODADAPT_ERR_INVALID_PROVIDER = "MODADAPT_ERR_INVALID_PROVIDER"
MODADAPT_ERR_BOUNDS = "MODADAPT_ERR_BOUNDS"
MODADAPT_ERR_UNAUTHORIZED = "MODADAPT_ERR_UNAUTHORIZED"
MODADAPT_ERR_SECRET_LEAK = "MODADAPT_ERR_SECRET_LEAK"

VALID_ROLES = {"system", "user", "assistant", "tool"}
MIN_TIMEOUT_MS = 1000
MAX_TIMEOUT_MS = 300000


class ModelProviderType(str, Enum):
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    MOCK = "mock"


def validate_role(role: str) -> str:
    """Enforces MODADAPT-INV1: canonical role validation."""
    if not role or not isinstance(role, str):
        raise ValueError(f"{MODADAPT_ERR_INVALID_ROLE}: empty or non-string role")
    cleaned = role.strip().lower()
    if cleaned not in VALID_ROLES:
        raise ValueError(f"{MODADAPT_ERR_INVALID_ROLE}: role '{cleaned}' not in {sorted(list(VALID_ROLES))}")
    return cleaned


def validate_temperature(temperature: float) -> float:
    """Enforces MODADAPT-INV4: temperature bounds in [0.0, 2.0]."""
    if not (0.0 <= temperature <= 2.0):
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: temperature ({temperature}) out of bounds [0.0, 2.0]")
    return float(temperature)


@dataclass(frozen=True)
class ModelCapabilities:
    streaming: bool = True
    tool_calling: bool = True
    vision: bool = False
    json_mode: bool = True
    max_context_window: int = 128000
    max_output_tokens: int = 4096

    def to_dict(self) -> Dict[str, Any]:
        return {
            "streaming": self.streaming,
            "tool_calling": self.tool_calling,
            "vision": self.vision,
            "json_mode": self.json_mode,
            "max_context_window": self.max_context_window,
            "max_output_tokens": self.max_output_tokens,
        }


@dataclass
class ModelEndpointConfig:
    backend_id: str
    provider: ModelProviderType
    model_name: str
    base_url: Optional[str] = None
    api_key_env: Optional[str] = None
    timeout_ms: int = 30000
    max_retries: int = 3
    capabilities: ModelCapabilities = field(default_factory=ModelCapabilities)
    is_active: bool = True

    def validate(self) -> None:
        """Enforces MODADAPT-INV3 and MODADAPT-INV4."""
        if not self.backend_id or not self.backend_id.strip():
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: backend_id must be non-empty")
        if not self.model_name or not self.model_name.strip():
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: model_name must be non-empty")
        if self.timeout_ms < MIN_TIMEOUT_MS or self.timeout_ms > MAX_TIMEOUT_MS:
            raise ValueError(
                f"{MODADAPT_ERR_BOUNDS}: timeout_ms ({self.timeout_ms}) must be within [{MIN_TIMEOUT_MS}, {MAX_TIMEOUT_MS}]"
            )
        if self.max_retries < 0 or self.max_retries > 10:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: max_retries ({self.max_retries}) must be within [0, 10]")
        # Secret Isolation (MODADAPT-INV3): Disallow raw sk- keys in api_key_env
        if self.api_key_env:
            raw = self.api_key_env.strip()
            if raw.startswith("sk-") or raw.startswith("ghp_") or len(raw) > 64:
                raise ValueError(
                    f"{MODADAPT_ERR_SECRET_LEAK}: api_key_env appears to contain plaintext secret rather than env var name"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "provider": self.provider.value if isinstance(self.provider, ModelProviderType) else str(self.provider),
            "model_name": self.model_name,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "timeout_ms": self.timeout_ms,
            "max_retries": self.max_retries,
            "capabilities": self.capabilities.to_dict(),
            "is_active": self.is_active,
        }


@dataclass
class ModelMessage:
    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None

    def __post_init__(self) -> None:
        self.role = validate_role(self.role)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "role": self.role,
            "content": self.content,
        }
        if self.name is not None:
            d["name"] = self.name
        if self.tool_calls is not None:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        return d


@dataclass(frozen=True)
class ModelUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int

    def validate_invariants(self) -> None:
        """Enforces MODADAPT-INV2."""
        if self.prompt_tokens < 0 or self.completion_tokens < 0:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: token counts must be non-negative")
        if self.total_tokens != (self.prompt_tokens + self.completion_tokens):
            raise AssertionError(
                f"MODADAPT-INV2 violated: total_tokens ({self.total_tokens}) != "
                f"prompt ({self.prompt_tokens}) + completion ({self.completion_tokens})"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class ModelRequest:
    model_id: str
    messages: List[ModelMessage]
    temperature: float = 0.7
    max_tokens: Optional[int] = None
    tools: Optional[List[Dict[str, Any]]] = None
    stream: bool = False

    def validate(self) -> None:
        if not self.model_id or not self.model_id.strip():
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: model_id must be non-empty")
        if not self.messages:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: messages list must not be empty")
        self.temperature = validate_temperature(self.temperature)
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: max_tokens must be positive integer")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "messages": [m.to_dict() for m in self.messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "tools": self.tools,
            "stream": self.stream,
        }


@dataclass
class ModelResponse:
    id: str
    model: str
    content: str
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    usage: Optional[ModelUsage] = None
    finish_reason: str = "stop"
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "model": self.model,
            "content": self.content,
            "tool_calls": self.tool_calls,
            "usage": self.usage.to_dict() if self.usage else None,
            "finish_reason": self.finish_reason,
            "latency_ms": self.latency_ms,
        }
