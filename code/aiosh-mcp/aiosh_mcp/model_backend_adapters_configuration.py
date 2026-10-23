"""AI Control Plane Model Backend Adapters Configuration (T-03205 scaffold / T-03206 impl).

Provides declarative configuration data structures, loading, and validation.
Conforms to SPEC-MODEL-BACKEND-ADAPTERS-CONFIGURATION and PoR Invariant I-2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import re
from typing import Any, Dict, List, Optional

from aiosh_mcp.model_backend_adapters_data_model import (
    ModelCapabilities,
    ModelEndpointConfig,
    ModelProviderType,
    MIN_TIMEOUT_MS,
    MAX_TIMEOUT_MS,
    validate_backend_id,
    validate_base_url,
)
from aiosh_mcp.model_backend_adapters_service import redact_secrets, MAX_FALLBACK_DEPTH

DEFAULT_TIMEOUT_MS: int = 30000
DEFAULT_RATE_LIMIT_RPM: int = 60


@dataclass
class ModelBackendConfig:
    version: str = "1.0"
    default_provider: str = "mock"
    default_timeout_ms: int = DEFAULT_TIMEOUT_MS
    max_fallback_depth: int = MAX_FALLBACK_DEPTH
    rate_limit_rpm: int = DEFAULT_RATE_LIMIT_RPM
    require_capability_tokens: bool = True
    endpoints: Dict[str, ModelEndpointConfig] = field(default_factory=dict)
    fallbacks: Dict[str, List[str]] = field(default_factory=dict)

    def to_dict(self, safe: bool = True) -> Dict[str, Any]:
        """Convert configuration to dictionary, redacting secrets if safe=True."""
        endpoints_dict = {}
        for bid, ep in self.endpoints.items():
            ep_dict = ep.to_dict()
            if safe and ep.api_key_env and (ep.api_key_env.startswith("sk-") or ep.api_key_env.startswith("ghp_")):
                ep_dict["api_key_env"] = "[REDACTED]"
            endpoints_dict[bid] = ep_dict

        return {
            "version": self.version,
            "default_provider": self.default_provider,
            "default_timeout_ms": self.default_timeout_ms,
            "max_fallback_depth": self.max_fallback_depth,
            "rate_limit_rpm": self.rate_limit_rpm,
            "require_capability_tokens": self.require_capability_tokens,
            "endpoints": endpoints_dict,
            "fallbacks": {k: list(v) for k, v in self.fallbacks.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ModelBackendConfig:
        """Parse configuration from dictionary."""
        endpoints_data = data.get("endpoints", {})
        endpoints: Dict[str, ModelEndpointConfig] = {}

        for bid, ep_info in endpoints_data.items():
            caps_data = ep_info.get("capabilities")
            caps = ModelCapabilities()
            if caps_data and isinstance(caps_data, dict):
                caps = ModelCapabilities(
                    streaming=caps_data.get("streaming", True),
                    tool_calling=caps_data.get("tool_calling", True),
                    vision=caps_data.get("vision", False),
                    json_mode=caps_data.get("json_mode", True),
                    max_context_window=caps_data.get("max_context_window", 128000),
                    max_output_tokens=caps_data.get("max_output_tokens", 4096),
                )

            prov_str = ep_info.get("provider", "mock")
            try:
                provider = ModelProviderType(prov_str)
            except ValueError:
                provider = ModelProviderType.MOCK

            ep = ModelEndpointConfig(
                backend_id=validate_backend_id(bid),
                provider=provider,
                model_name=ep_info.get("model_name", "default"),
                base_url=validate_base_url(ep_info.get("base_url")),
                api_key_env=ep_info.get("api_key_env"),
                timeout_ms=int(ep_info.get("timeout_ms", DEFAULT_TIMEOUT_MS)),
                max_retries=int(ep_info.get("max_retries", 3)),
                capabilities=caps,
                is_active=bool(ep_info.get("is_active", True)),
            )
            ep.validate()
            endpoints[bid] = ep

        fallbacks_data = data.get("fallbacks", {})
        fallbacks: Dict[str, List[str]] = {}
        for k, v in fallbacks_data.items():
            fallbacks[k] = list(v)

        return cls(
            version=str(data.get("version", "1.0")),
            default_provider=str(data.get("default_provider", "mock")),
            default_timeout_ms=int(data.get("default_timeout_ms", DEFAULT_TIMEOUT_MS)),
            max_fallback_depth=int(data.get("max_fallback_depth", MAX_FALLBACK_DEPTH)),
            rate_limit_rpm=int(data.get("rate_limit_rpm", DEFAULT_RATE_LIMIT_RPM)),
            require_capability_tokens=bool(data.get("require_capability_tokens", True)),
            endpoints=endpoints,
            fallbacks=fallbacks,
        )

    def validate(self) -> None:
        """Enforces MODCONF-INV1..MODCONF-INV4 invariants."""
        if not (MIN_TIMEOUT_MS <= self.default_timeout_ms <= MAX_TIMEOUT_MS):
            raise ValueError(f"default_timeout_ms {self.default_timeout_ms} out of bounds [{MIN_TIMEOUT_MS}, {MAX_TIMEOUT_MS}]")
        if not (1 <= self.max_fallback_depth <= 10):
            raise ValueError(f"max_fallback_depth {self.max_fallback_depth} out of bounds [1, 10]")
        if self.rate_limit_rpm <= 0:
            raise ValueError(f"rate_limit_rpm must be positive, got {self.rate_limit_rpm}")

        for bid, ep in self.endpoints.items():
            ep.validate()

        for bid, fb_list in self.fallbacks.items():
            if len(fb_list) > self.max_fallback_depth:
                raise ValueError(f"Endpoint {bid} fallbacks exceeds max_fallback_depth {self.max_fallback_depth}")
            if bid in fb_list:
                raise ValueError(f"Direct circular fallback detected in endpoint {bid}")


def load_config_from_dict(data: Dict[str, Any]) -> ModelBackendConfig:
    cfg = ModelBackendConfig.from_dict(data)
    cfg.validate()
    return cfg


def load_config_from_json(json_str: str) -> ModelBackendConfig:
    data = json.loads(json_str)
    return load_config_from_dict(data)


def load_config_from_env() -> ModelBackendConfig:
    """Construct configuration with environmental overrides."""
    cfg = ModelBackendConfig()
    if "AIOSH_MODEL_DEFAULT_PROVIDER" in os.environ:
        cfg.default_provider = os.environ["AIOSH_MODEL_DEFAULT_PROVIDER"]
    if "AIOSH_MODEL_TIMEOUT_MS" in os.environ:
        cfg.default_timeout_ms = int(os.environ["AIOSH_MODEL_TIMEOUT_MS"])
    if "AIOSH_MODEL_RATE_LIMIT_RPM" in os.environ:
        cfg.rate_limit_rpm = int(os.environ["AIOSH_MODEL_RATE_LIMIT_RPM"])
    cfg.validate()
    return cfg
