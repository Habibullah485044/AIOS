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


BACKEND_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
MAX_MESSAGE_BYTES = 1024 * 1024  # 1 MiB


def validate_backend_id(backend_id: str) -> str:
    """Validates backend_id syntax and length."""
    if not backend_id or not isinstance(backend_id, str):
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: empty or non-string backend_id")
    cleaned = backend_id.strip()
    if not BACKEND_ID_PATTERN.match(cleaned):
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: backend_id '{cleaned}' does not match syntax ^[a-zA-Z0-9_\\-\\.]{{1,64}}$")
    if ".." in cleaned or "/" in cleaned or "\\" in cleaned or "\0" in cleaned:
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: directory traversal character detected in backend_id")
    return cleaned


def validate_base_url(url: Optional[str]) -> Optional[str]:
    """Validates custom endpoint base URL."""
    if not url:
        return None
    cleaned = url.strip()
    if not (cleaned.startswith("http://") or cleaned.startswith("https://") or cleaned.startswith("ws://") or cleaned.startswith("wss://")):
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: base_url must start with http:// or https://")
    if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
        raise ValueError(f"{MODADAPT_ERR_BOUNDS}: control character detected in base_url")
    return cleaned


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
        self.backend_id = validate_backend_id(self.backend_id)
        if not self.model_name or not self.model_name.strip():
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: model_name must be non-empty")
        if self.base_url:
            self.base_url = validate_base_url(self.base_url)
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
        if len(self.content.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: message content exceeds {MAX_MESSAGE_BYTES} bytes")


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


MAX_ENDPOINTS = 64


class ModelEndpointRegistry:
    """In-memory repository for configured model backend endpoints."""

    def __init__(self) -> None:
        self._endpoints: Dict[str, ModelEndpointConfig] = {}

    @classmethod
    def default(cls) -> "ModelEndpointRegistry":
        return build_default_model_registry()

    def register(self, config: ModelEndpointConfig) -> None:
        config.validate()
        if len(self._endpoints) >= MAX_ENDPOINTS and config.backend_id not in self._endpoints:
            raise ValueError(f"{MODADAPT_ERR_BOUNDS}: endpoint capacity ceiling of {MAX_ENDPOINTS} exceeded")
        self._endpoints[config.backend_id] = config

    def get(self, backend_id: str) -> ModelEndpointConfig:
        if backend_id not in self._endpoints:
            raise KeyError(f"Endpoint '{backend_id}' not found")
        return self._endpoints[backend_id]

    def list_endpoints(self) -> List[ModelEndpointConfig]:
        return list(self._endpoints.values())

    def remove(self, backend_id: str) -> bool:
        if backend_id in self._endpoints:
            del self._endpoints[backend_id]
            return True
        return False


def build_default_model_registry() -> ModelEndpointRegistry:
    """Builds and populates the default endpoint registry with standard backends."""
    registry = ModelEndpointRegistry()

    # Mock deterministic backend
    registry.register(
        ModelEndpointConfig(
            backend_id="mock-default",
            provider=ModelProviderType.MOCK,
            model_name="mock-model-v1",
            api_key_env="MOCK_API_KEY",
            capabilities=ModelCapabilities(streaming=True, tool_calling=True, vision=False),
        )
    )

    # OpenAI-compatible default
    registry.register(
        ModelEndpointConfig(
            backend_id="openai-primary",
            provider=ModelProviderType.OPENAI_COMPATIBLE,
            model_name="gpt-4o",
            api_key_env="OPENAI_API_KEY",
            capabilities=ModelCapabilities(streaming=True, tool_calling=True, vision=True),
        )
    )

    # Anthropic default
    registry.register(
        ModelEndpointConfig(
            backend_id="anthropic-primary",
            provider=ModelProviderType.ANTHROPIC,
            model_name="claude-3-7-sonnet",
            api_key_env="ANTHROPIC_API_KEY",
            capabilities=ModelCapabilities(streaming=True, tool_calling=True, vision=True),
        )
    )

    # Gemini default
    registry.register(
        ModelEndpointConfig(
            backend_id="gemini-primary",
            provider=ModelProviderType.GEMINI,
            model_name="gemini-2.5-flash",
            api_key_env="GEMINI_API_KEY",
            capabilities=ModelCapabilities(streaming=True, tool_calling=True, vision=True),
        )
    )

    # Ollama local daemon
    registry.register(
        ModelEndpointConfig(
            backend_id="ollama-local",
            provider=ModelProviderType.OLLAMA,
            model_name="llama3.2",
            base_url="http://localhost:11434",
            capabilities=ModelCapabilities(streaming=True, tool_calling=True, vision=False),
        )
    )

    return registry


_GLOBAL_MODEL_REGISTRY = build_default_model_registry()


def get_model_registry() -> ModelEndpointRegistry:
    return _GLOBAL_MODEL_REGISTRY


def model_message_from_dict(d: Dict[str, Any]) -> ModelMessage:
    return ModelMessage(
        role=d["role"],
        content=d.get("content", ""),
        name=d.get("name"),
        tool_calls=d.get("tool_calls"),
        tool_call_id=d.get("tool_call_id"),
    )


def model_endpoint_from_dict(d: Dict[str, Any]) -> ModelEndpointConfig:
    provider_str = d.get("provider", "mock")
    provider = ModelProviderType(provider_str)
    caps_data = d.get("capabilities", {})
    caps = ModelCapabilities(
        streaming=caps_data.get("streaming", True),
        tool_calling=caps_data.get("tool_calling", True),
        vision=caps_data.get("vision", False),
        json_mode=caps_data.get("json_mode", True),
        max_context_window=caps_data.get("max_context_window", 128000),
        max_output_tokens=caps_data.get("max_output_tokens", 4096),
    )
    return ModelEndpointConfig(
        backend_id=d["backend_id"],
        provider=provider,
        model_name=d["model_name"],
        base_url=d.get("base_url"),
        api_key_env=d.get("api_key_env"),
        timeout_ms=d.get("timeout_ms", 30000),
        max_retries=d.get("max_retries", 3),
        capabilities=caps,
        is_active=d.get("is_active", True),
    )


def register_model_adapter_tools(mcp_app: Any) -> None:
    """Register Model Backend Adapters tools with FastMCP (T-03168)."""

    @mcp_app.tool()
    def aios_model_endpoint_list() -> dict:
        """List all configured model backend adapters and their capabilities. Pure read-only (PoR Invariant I-2)."""
        try:
            endpoints = _GLOBAL_MODEL_REGISTRY.list_endpoints()
            return {
                "ok": True,
                "endpoints": [e.to_dict() for e in endpoints],
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    @mcp_app.tool()
    def aios_model_endpoint_register(
        backend_id: str,
        provider: str,
        model_name: str,
        base_url: Optional[str] = None,
        api_key_env: Optional[str] = None,
        timeout_ms: int = 30000,
        max_retries: int = 3,
        capability_token: str = "",
    ) -> dict:
        """Register or update a model backend adapter endpoint. Requires capability token (PoR Invariant I-2)."""
        from aiosh_mcp.capability_redeem import redeem_capability
        refused = redeem_capability(capability_token, tool="aios.model.endpoint.register",   # T-03429 F1
                                    command=f"model.endpoint.register {str(backend_id)[:128]}")
        if refused:
            return {
                "ok": False,
                "error": f"{MODADAPT_ERR_UNAUTHORIZED}: capability token required for endpoint registration "
                         f"(PoR Invariant I-2): {refused}",
            }
        try:
            prov_enum = ModelProviderType(provider.lower())
            config = ModelEndpointConfig(
                backend_id=backend_id,
                provider=prov_enum,
                model_name=model_name,
                base_url=base_url,
                api_key_env=api_key_env,
                timeout_ms=timeout_ms,
                max_retries=max_retries,
            )
            _GLOBAL_MODEL_REGISTRY.register(config)
            return {
                "ok": True,
                "backend_id": backend_id,
                "endpoint": config.to_dict(),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


