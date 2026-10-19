"""AI Control Plane Model Backend Adapters CLI Surface (T-03185 Scaffold / T-03186 Impl).

Exposes command line operations for model adapter inspection, endpoint health,
completion dispatch, and dynamic registration in compliance with ADR-0035 §AF-2
and PoR Invariant I-2.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from aiosh_mcp.model_backend_adapters_data_model import (
    ModelCapabilities,
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
    ModelResponse,
    build_default_model_registry,
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

EXIT_SUCCESS: int = 0
EXIT_FAILURE: int = 1
EXIT_USAGE: int = 2
EXIT_UNAUTHORIZED: int = 3
EXIT_TIMEOUT: int = 4

VALID_SUBCOMMANDS = {"list", "show", "health", "complete", "register"}


@dataclass
class ModelCliOutput:
    """Standard output envelope for Model Backend Adapters CLI (MODCLI-INV3)."""

    exit_code: int
    message: str
    json_payload: Optional[Dict[str, Any]] = None

    @classmethod
    def success(cls, message: str, payload: Optional[Dict[str, Any]] = None) -> "ModelCliOutput":
        return cls(exit_code=EXIT_SUCCESS, message=message, json_payload=payload)

    @classmethod
    def failure(cls, exit_code: int, message: str) -> "ModelCliOutput":
        safe_msg = redact_secrets(message)
        return cls(exit_code=exit_code, message=safe_msg, json_payload=None)

    @classmethod
    def failure_with_json(cls, exit_code: int, message: str, json_mode: bool = False) -> "ModelCliOutput":
        safe_msg = redact_secrets(message)
        if json_mode:
            payload = {
                "status": "error",
                "ok": False,
                "exit_code": exit_code,
                "error_message": safe_msg,
            }
            return cls(exit_code=exit_code, message=json.dumps(payload), json_payload=payload)
        return cls(exit_code=exit_code, message=safe_msg, json_payload=None)


def parse_model_cli_args(args: List[str]) -> Tuple[str, Dict[str, Any]]:
    """Parses raw CLI arguments into (subcommand, options) tuple (MODCLI-INV1)."""
    if not args:
        raise ValueError("Missing model subcommand (choose from list, show, health, complete, register)")

    for arg in args:
        if "\0" in arg:
            raise ValueError("CLI argument contains prohibited NUL byte")

    subcmd = args[0]
    if subcmd not in VALID_SUBCOMMANDS:
        raise ValueError(f"Unknown subcommand '{subcmd}'. Choose from: {', '.join(sorted(VALID_SUBCOMMANDS))}")

    options: Dict[str, Any] = {
        "json": False,
        "provider": None,
        "active_only": False,
        "prompt": None,
        "temperature": 0.7,
        "fallbacks": [],
        "token": None,
        "model": None,
        "base_url": None,
        "env": None,
        "timeout": None,
        "positional": [],
    }

    i = 1
    while i < len(args):
        flag = args[i]
        if flag == "--json":
            options["json"] = True
        elif flag == "--active-only":
            options["active_only"] = True
        elif flag == "--provider":
            i += 1
            if i >= len(args):
                raise ValueError("--provider requires a value")
            options["provider"] = args[i]
        elif flag == "--prompt":
            i += 1
            if i >= len(args):
                raise ValueError("--prompt requires text")
            options["prompt"] = args[i]
        elif flag == "--temperature":
            i += 1
            if i >= len(args):
                raise ValueError("--temperature requires a float")
            try:
                t = float(args[i])
            except ValueError:
                raise ValueError(f"Invalid temperature: {args[i]}")
            if t < 0.0 or t > 2.0:
                raise ValueError(f"Invalid temperature: {args[i]} (must be within [0.0, 2.0])")
            options["temperature"] = t
        elif flag == "--fallback":
            i += 1
            if i >= len(args):
                raise ValueError("--fallback requires a backend id")
            if len(options["fallbacks"]) >= 5:
                raise ValueError("Fallback list exceeds max depth of 5")
            options["fallbacks"].append(args[i])
        elif flag == "--token":
            i += 1
            if i >= len(args):
                raise ValueError("--token requires a token value")
            options["token"] = args[i]
        elif flag == "--model":
            i += 1
            if i >= len(args):
                raise ValueError("--model requires a model name")
            options["model"] = args[i]
        elif flag == "--base-url":
            i += 1
            if i >= len(args):
                raise ValueError("--base-url requires a URL")
            options["base_url"] = args[i]
        elif flag == "--env":
            i += 1
            if i >= len(args):
                raise ValueError("--env requires an env var name")
            options["env"] = args[i]
        elif flag == "--timeout":
            i += 1
            if i >= len(args):
                raise ValueError("--timeout requires milliseconds")
            try:
                options["timeout"] = int(args[i])
            except ValueError:
                raise ValueError(f"Invalid timeout: {args[i]}")
            if options["timeout"] < 1000 or options["timeout"] > 300000:
                raise ValueError(f"Timeout {options['timeout']} out of bounds [1000, 300000] ms")
        elif not flag.startswith("-"):
            if len(flag) > 64:
                raise ValueError(f"Positional identifier exceeds max length of 64: {flag[:16]}...")
            if ".." in flag or "/" in flag or "\\" in flag:
                raise ValueError(f"Path traversal characters forbidden in identifier: {flag}")
            options["positional"].append(flag)
        else:
            raise ValueError(f"Unknown option '{flag}'")
        i += 1

    return subcmd, options


def dispatch_model_cli(args: List[str], service: Optional[ModelBackendService] = None) -> ModelCliOutput:
    """Dispatches model CLI commands with Proof-of-Restraint token enforcement (MODCLI-INV2)."""
    try:
        subcmd, opts = parse_model_cli_args(args)
    except ValueError as e:
        return ModelCliOutput.failure_with_json(EXIT_USAGE, str(e), json_mode=("--json" in args))

    json_mode = opts.get("json", False)

    # PoR Invariant I-2 gating: pure read commands require 0 tokens;
    # complete and register require valid capability token
    if subcmd in ("complete", "register"):
        token = opts.get("token")
        if not token or not token.strip():
            return ModelCliOutput.failure_with_json(
                EXIT_UNAUTHORIZED,
                f"MODSERV_ERR_UNAUTHORIZED: subcommand '{subcmd}' requires a capability token (--token)",
                json_mode=json_mode,
            )

    svc = service or ModelBackendService()

    if subcmd == "list":
        provider_filter = opts.get("provider")
        active_only = opts.get("active_only", False)
        configs = svc.registry.list_endpoints()
        if provider_filter:
            configs = [c for c in configs if c.provider.value == provider_filter or c.provider.name.lower() == provider_filter.lower()]
        if active_only:
            configs = [c for c in configs if c.is_active]

        if json_mode:
            payload = {
                "status": "success",
                "ok": True,
                "exit_code": EXIT_SUCCESS,
                "count": len(configs),
                "endpoints": [c.to_dict() for c in configs],
            }
            return ModelCliOutput.success(json.dumps(payload), payload)
        lines = [f"{c.backend_id} [{c.provider.value}] model={c.model_name} active={c.is_active}" for c in configs]
        return ModelCliOutput.success("\n".join(lines) if lines else "No endpoints found")

    elif subcmd == "show":
        positional = opts.get("positional", [])
        if not positional:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, "Missing backend_id argument", json_mode=json_mode)
        backend_id = positional[0]
        try:
            config = svc.registry.get(backend_id)
        except KeyError:
            return ModelCliOutput.failure_with_json(EXIT_FAILURE, f"Backend '{backend_id}' not found", json_mode=json_mode)

        if json_mode:
            payload = {
                "status": "success",
                "ok": True,
                "exit_code": EXIT_SUCCESS,
                "endpoint": config.to_dict(),
            }
            return ModelCliOutput.success(json.dumps(payload), payload)
        return ModelCliOutput.success(
            f"Backend: {config.backend_id}\nProvider: {config.provider.value}\nModel: {config.model_name}\nActive: {config.is_active}"
        )

    elif subcmd == "health":
        positional = opts.get("positional", [])
        target_id = positional[0] if positional else None

        if target_id:
            try:
                cfg = svc.registry.get(target_id)
            except KeyError:
                return ModelCliOutput.failure_with_json(EXIT_FAILURE, f"Unknown backend: {target_id}", json_mode=json_mode)
            health = svc.health_check(target_id)
            health_data = {
                "backend_id": target_id,
                "provider": cfg.provider.value,
                "active": cfg.is_active,
                "adapter_available": cfg.provider in svc._adapters,
            }
            if json_mode:
                payload = {
                    "status": "success",
                    "ok": True,
                    "exit_code": EXIT_SUCCESS,
                    "data": health_data,
                }
                return ModelCliOutput.success(json.dumps(payload), payload)
            return ModelCliOutput.success(f"{target_id}: active={cfg.is_active}, adapter_ready={health_data['adapter_available']}")

        health = svc.health_check()
        if json_mode:
            payload = {
                "status": "success",
                "ok": True,
                "exit_code": EXIT_SUCCESS,
                "data": health,
            }
            return ModelCliOutput.success(json.dumps(payload), payload)
        return ModelCliOutput.success(
            f"Health Summary: {health['active_endpoints']}/{health['total_endpoints']} active endpoints. Adapters: {', '.join(health['adapters_available'])}"
        )

    elif subcmd == "complete":
        positional = opts.get("positional", [])
        if not positional:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, "Missing backend_id argument", json_mode=json_mode)
        backend_id = positional[0]
        prompt = opts.get("prompt")
        if not prompt:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, "Missing --prompt argument", json_mode=json_mode)

        req = ModelRequest(
            model_id=backend_id,
            messages=[ModelMessage(role="user", content=prompt)],
            temperature=opts.get("temperature", 0.7),
        )
        try:
            resp = asyncio.run(svc.complete(req, fallback_backends=opts.get("fallbacks")))
            if json_mode:
                payload = {
                    "status": "success",
                    "ok": True,
                    "exit_code": EXIT_SUCCESS,
                    "response": resp.to_dict(),
                }
                return ModelCliOutput.success(json.dumps(payload), payload)
            return ModelCliOutput.success(f"[{resp.model}] {resp.content}")
        except ModelServiceError as e:
            code = EXIT_TIMEOUT if e.code == MODSERV_ERR_TIMEOUT else EXIT_FAILURE
            return ModelCliOutput.failure_with_json(code, f"{e.code}: {e.message}", json_mode=json_mode)

    elif subcmd == "register":
        positional = opts.get("positional", [])
        if not positional:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, "Missing backend_id argument", json_mode=json_mode)
        backend_id = positional[0]
        provider_str = opts.get("provider")
        model_name = opts.get("model")
        if not provider_str or not model_name:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, "--provider and --model are required", json_mode=json_mode)

        try:
            provider = ModelProviderType(provider_str.lower())
        except ValueError:
            return ModelCliOutput.failure_with_json(EXIT_USAGE, f"Invalid provider: {provider_str}", json_mode=json_mode)

        endpoint = ModelEndpointConfig(
            backend_id=backend_id,
            provider=provider,
            model_name=model_name,
            base_url=opts.get("base_url"),
            api_key_env=opts.get("env"),
            timeout_ms=opts.get("timeout") or 30000,
        )
        svc.registry.register(endpoint)

        if json_mode:
            payload = {
                "status": "success",
                "ok": True,
                "exit_code": EXIT_SUCCESS,
                "registered": endpoint.to_dict(),
            }
            return ModelCliOutput.success(json.dumps(payload), payload)
        return ModelCliOutput.success(f"Successfully registered backend '{backend_id}'")

    return ModelCliOutput.failure_with_json(EXIT_USAGE, f"Unhandled subcommand '{subcmd}'", json_mode=json_mode)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint returning exit code."""
    import sys
    args = argv if argv is not None else sys.argv[1:]
    out = dispatch_model_cli(args)
    if out.message:
        print(out.message)
    return out.exit_code


if __name__ == "__main__":
    import sys
    sys.exit(main())
