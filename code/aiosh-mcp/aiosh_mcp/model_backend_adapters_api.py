"""AI Control Plane Model Backend Adapters MCP/API Surface (T-03195 scaffold / T-03196 impl).

Wire protocol handler and JSON-RPC 2.0 adapter for ModelBackendService.
Conforms to SPEC-MODEL-BACKEND-ADAPTERS-MCP-API, ADR-0035 §D-2, and PoR Invariant I-2.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Union

from aiosh_mcp.model_backend_adapters_data_model import (
    ModelCapabilities,
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
    ModelResponse,
)
from aiosh_mcp.model_backend_adapters_service import (
    ModelBackendService,
    ModelServiceError,
    redact_secrets,
    MODSERV_ERR_UNKNOWN_BACKEND,
    MODSERV_ERR_TIMEOUT,
    MODSERV_ERR_RATE_LIMIT,
    MODSERV_ERR_AUTH,
    MODSERV_ERR_UNAVAILABLE,
    MAX_FALLBACK_DEPTH,
    MAX_REQUEST_MESSAGES,
)

PROTOCOL_VERSION: str = "2025-06-18"
SERVER_NAME: str = "aiosh-model-backend"
SERVER_VERSION: str = "0.1.0"

API_METHOD_LIST: str = "model_backend_list"
API_METHOD_SHOW: str = "model_backend_show"
API_METHOD_HEALTH: str = "model_backend_health"
API_METHOD_COMPLETE: str = "model_backend_complete"
API_METHOD_REGISTER: str = "model_backend_register"

ERR_SUCCESS: int = 0
ERR_INVALID_PARAMS: int = -32602
ERR_UNAUTHORIZED: int = -32003
ERR_NOT_FOUND: int = -32004
ERR_TIMEOUT: int = -32005
ERR_INTERNAL: int = -32603


def make_jsonrpc_error(
    req_id: Optional[Union[str, int]],
    code: int,
    message: str,
    data: Any = None,
) -> Dict[str, Any]:
    safe_msg = redact_secrets(message)
    err: Dict[str, Any] = {"code": code, "message": safe_msg}
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": err,
    }


def make_jsonrpc_result(
    req_id: Optional[Union[str, int]],
    result: Any,
) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


def validate_backend_id(backend_id: str) -> Optional[str]:
    """Validates backend identifier format and bounds.
    Returns error message if invalid, None if valid.
    """
    if not backend_id:
        return "Backend identifier cannot be empty"
    if len(backend_id) > 64:
        return f"Backend identifier exceeds 64 characters (length: {len(backend_id)})"
    if any(c in backend_id for c in ("\0", "/", "\\")) or ".." in backend_id:
        return "Backend identifier contains prohibited path traversal or control characters"
    if any(ord(c) < 32 or ord(c) == 127 for c in backend_id):
        return "Backend identifier contains prohibited control characters"
    return None


class ModelBackendApiHandler:
    """Dispatches wire MCP tool calls and JSON-RPC 2.0 requests to ModelBackendService."""

    def __init__(self, service: Optional[ModelBackendService] = None) -> None:
        self.service: ModelBackendService = service or ModelBackendService()

    def handle_ping(self, req_id: Optional[Union[str, int]]) -> Dict[str, Any]:
        """Liveness ping query."""
        return make_jsonrpc_result(
            req_id,
            {"status": "ok", "service": SERVER_NAME, "protocolVersion": PROTOCOL_VERSION},
        )

    def handle_list(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Pure read-only enumeration of configured endpoints (PoR I-2: 0 tokens)."""
        p = params or {}
        provider_filter = p.get("provider")
        active_only = p.get("active_only", False)

        configs = self.service.registry.list_endpoints()
        if provider_filter:
            configs = [
                c for c in configs
                if c.provider.value == provider_filter or c.provider.name.lower() == str(provider_filter).lower()
            ]
        if active_only:
            configs = [c for c in configs if c.is_active]

        return make_jsonrpc_result(
            req_id,
            {
                "status": "success",
                "ok": True,
                "count": len(configs),
                "endpoints": [c.to_dict() for c in configs],
            },
        )

    def handle_show(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Pure read-only inspection of an endpoint's metadata (PoR I-2: 0 tokens)."""
        p = params or {}
        backend_id = p.get("backend_id")
        if not backend_id:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Missing 'backend_id' parameter")

        err = validate_backend_id(str(backend_id))
        if err:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, err)

        try:
            cfg = self.service.registry.get(backend_id)
        except KeyError:
            return make_jsonrpc_error(req_id, ERR_NOT_FOUND, f"Endpoint '{backend_id}' not found")

        return make_jsonrpc_result(
            req_id,
            {
                "status": "success",
                "ok": True,
                "endpoint": cfg.to_dict(),
            },
        )

    def handle_health(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Pure read-only operational health report (PoR I-2: 0 tokens)."""
        p = params or {}
        backend_id = p.get("backend_id")
        if backend_id:
            err = validate_backend_id(str(backend_id))
            if err:
                return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, err)
            try:
                cfg = self.service.registry.get(backend_id)
            except KeyError:
                return make_jsonrpc_error(req_id, ERR_NOT_FOUND, f"Unknown backend '{backend_id}'")
            health_data = {
                "backend_id": backend_id,
                "provider": cfg.provider.value,
                "active": cfg.is_active,
                "adapter_available": cfg.provider in self.service._adapters,
            }
            return make_jsonrpc_result(req_id, {"status": "success", "ok": True, "data": health_data})

        summary = self.service.health_check()
        return make_jsonrpc_result(req_id, {"status": "success", "ok": True, "data": summary})

    async def handle_complete_async(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """State-mutating completion request strictly gated under PoR Invariant I-2."""
        p = params or {}
        backend_id = p.get("backend_id")
        prompt = p.get("prompt")
        cap_token = p.get("capability_token")

        # PoR Invariant I-2: capability token mandatory
        if not cap_token or not str(cap_token).strip():
            return make_jsonrpc_error(
                req_id,
                ERR_UNAUTHORIZED,
                "MODSERV_ERR_UNAUTHORIZED: 'capability_token' required for inference completion",
            )

        if not backend_id:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Missing 'backend_id' parameter")
        if not prompt:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Missing 'prompt' parameter")

        err = validate_backend_id(str(backend_id))
        if err:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, err)

        if "\0" in str(prompt):
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Prompt contains prohibited NUL byte")

        if len(str(prompt).encode("utf-8")) > 1024 * 1024:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Prompt exceeds 1 MiB limit")

        temp = p.get("temperature", 0.7)
        if temp < 0.0 or temp > 2.0:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, f"Temperature {temp} out of bounds [0.0, 2.0]")

        fallbacks = p.get("fallbacks", [])
        if len(fallbacks) > MAX_FALLBACK_DEPTH:
            return make_jsonrpc_error(
                req_id,
                ERR_INVALID_PARAMS,
                f"Fallback depth ({len(fallbacks)}) exceeds maximum of {MAX_FALLBACK_DEPTH}",
            )
        for fb in fallbacks:
            fb_err = validate_backend_id(str(fb))
            if fb_err:
                return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, f"Fallback backend invalid: {fb_err}")

        req = ModelRequest(
            model_id=backend_id,
            messages=[ModelMessage(role="user", content=prompt)],
            temperature=temp,
        )

        try:
            resp = await self.service.complete(req, fallback_backends=fallbacks)
            return make_jsonrpc_result(
                req_id,
                {
                    "status": "success",
                    "ok": True,
                    "response": resp.to_dict(),
                },
            )
        except ModelServiceError as e:
            code = ERR_TIMEOUT if e.code == MODSERV_ERR_TIMEOUT else ERR_INTERNAL
            return make_jsonrpc_error(req_id, code, f"{e.code}: {e.message}")

    def handle_complete(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for handle_complete_async."""
        return asyncio.run(self.handle_complete_async(req_id, params))

    def handle_register(
        self,
        req_id: Optional[Union[str, int]],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """State-mutating endpoint registration strictly gated under PoR Invariant I-2."""
        p = params or {}
        backend_id = p.get("backend_id")
        provider_str = p.get("provider")
        model_name = p.get("model_name")
        cap_token = p.get("capability_token")

        # PoR Invariant I-2: capability token mandatory
        if not cap_token or not str(cap_token).strip():
            return make_jsonrpc_error(
                req_id,
                ERR_UNAUTHORIZED,
                "MODSERV_ERR_UNAUTHORIZED: 'capability_token' required for endpoint registration",
            )

        if not backend_id or not provider_str or not model_name:
            return make_jsonrpc_error(
                req_id,
                ERR_INVALID_PARAMS,
                "Missing required parameters: 'backend_id', 'provider', 'model_name'",
            )

        err = validate_backend_id(str(backend_id))
        if err:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, err)

        try:
            provider = ModelProviderType(str(provider_str).lower())
        except ValueError:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, f"Invalid provider '{provider_str}'")

        timeout_ms = p.get("timeout_ms", 30000)
        if timeout_ms < 1000 or timeout_ms > 300000:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, f"Timeout {timeout_ms} out of bounds [1000, 300000] ms")

        try:
            cfg = ModelEndpointConfig(
                backend_id=backend_id,
                provider=provider,
                model_name=model_name,
                base_url=p.get("base_url"),
                api_key_env=p.get("api_key_env"),
                timeout_ms=timeout_ms,
            )
            self.service.registry.register(cfg)
            return make_jsonrpc_result(
                req_id,
                {
                    "status": "success",
                    "ok": True,
                    "registered": cfg.to_dict(),
                },
            )
        except ValueError as e:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, str(e))

    def handle_request(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an incoming JSON-RPC 2.0 request."""
        req_id = body.get("id")
        method = body.get("method")
        params = body.get("params")

        if not method:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "Missing 'method' field")

        if method in ("ping", "model_backend_ping"):
            return self.handle_ping(req_id)
        elif method in ("tools/list", "model_backend_list"):
            return self.handle_list(req_id, params)
        elif method in ("model_backend_show",):
            return self.handle_show(req_id, params)
        elif method in ("model_backend_health",):
            return self.handle_health(req_id, params)
        elif method in ("model_backend_complete",):
            return self.handle_complete(req_id, params)
        elif method in ("model_backend_register",):
            return self.handle_register(req_id, params)
        else:
            return make_jsonrpc_error(req_id, -32601, f"Method '{method}' not found")


def register_model_backend_tools(mcp_app: Any, service: Optional[ModelBackendService] = None) -> None:
    """Registers Model Backend Adapters tools with a FastMCP server application."""
    handler = ModelBackendApiHandler(service=service)

    @mcp_app.tool(name="model_backend_list", description="List registered model backend endpoints")
    def tool_list(provider: Optional[str] = None, active_only: bool = False) -> Dict[str, Any]:
        return handler.handle_list(None, {"provider": provider, "active_only": active_only})

    @mcp_app.tool(name="model_backend_show", description="Show details of a model backend endpoint")
    def tool_show(backend_id: str) -> Dict[str, Any]:
        return handler.handle_show(None, {"backend_id": backend_id})

    @mcp_app.tool(name="model_backend_health", description="Query health status of model backend endpoints")
    def tool_health(backend_id: Optional[str] = None) -> Dict[str, Any]:
        return handler.handle_health(None, {"backend_id": backend_id})

    @mcp_app.tool(name="model_backend_complete", description="Execute model inference through backend with fallback (PoR I-2 token required)")
    def tool_complete(backend_id: str, prompt: str, capability_token: str, temperature: float = 0.7, fallbacks: Optional[List[str]] = None) -> Dict[str, Any]:
        return handler.handle_complete(None, {
            "backend_id": backend_id,
            "prompt": prompt,
            "capability_token": capability_token,
            "temperature": temperature,
            "fallbacks": fallbacks or [],
        })

    @mcp_app.tool(name="model_backend_register", description="Register a new model backend endpoint (PoR I-2 token required)")
    def tool_register(backend_id: str, provider: str, model_name: str, capability_token: str, base_url: Optional[str] = None, api_key_env: Optional[str] = None, timeout_ms: int = 30000) -> Dict[str, Any]:
        return handler.handle_register(None, {
            "backend_id": backend_id,
            "provider": provider,
            "model_name": model_name,
            "capability_token": capability_token,
            "base_url": base_url,
            "api_key_env": api_key_env,
            "timeout_ms": timeout_ms,
        })
