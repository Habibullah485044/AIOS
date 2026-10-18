"""AI Control Plane MCP Server Core Configuration Subsystem (T-03105 scaffold / T-03106 impl).

Defines configuration parameters, validation invariants, and resolution hierarchy
for McpServerCoreService in compliance with SPEC-MCP-SERVER-CORE-CONFIG and PoR Invariant I-2.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_STORE_PATH: str = ".aios/mcp_store.json"
DEFAULT_MAX_ACTIVE_SESSIONS: int = 64
DEFAULT_SESSION_IDLE_TIMEOUT: int = 3600
DEFAULT_EXECUTION_TIMEOUT: int = 30
DEFAULT_MAX_ARGUMENTS_SIZE: int = 1048576  # 1 MiB
DEFAULT_MAX_TOOLS_COUNT: int = 256
DEFAULT_REQUIRE_ADMIN_GRANT: bool = True
DEFAULT_AUTO_PRUNE_TERMINATED: bool = True

MIN_ACTIVE_SESSIONS: int = 1
MAX_ALLOWED_ACTIVE_SESSIONS: int = 512
MIN_IDLE_TIMEOUT: int = 60
MAX_ALLOWED_IDLE_TIMEOUT: int = 86400
MIN_EXECUTION_TIMEOUT: int = 1
MAX_ALLOWED_EXECUTION_TIMEOUT: int = 300
MIN_ARGUMENTS_SIZE: int = 1024
MAX_ALLOWED_ARGUMENTS_SIZE: int = 10 * 1024 * 1024  # 10 MiB
MIN_TOOLS_COUNT: int = 1
MAX_ALLOWED_TOOLS_COUNT: int = 1024
MAX_CONFIG_FILE_BYTES: int = 65536  # 64 KiB


class McpConfigError(ValueError):
    """Raised when an MCP configuration parameter violates bounds or validation rules."""
    pass


@dataclass
class McpServerCoreConfig:
    store_path: str = DEFAULT_STORE_PATH
    max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS
    session_idle_timeout_seconds: int = DEFAULT_SESSION_IDLE_TIMEOUT
    default_execution_timeout_seconds: int = DEFAULT_EXECUTION_TIMEOUT
    max_arguments_size_bytes: int = DEFAULT_MAX_ARGUMENTS_SIZE
    max_tools_count: int = DEFAULT_MAX_TOOLS_COUNT
    require_admin_grant: bool = DEFAULT_REQUIRE_ADMIN_GRANT
    auto_prune_terminated: bool = DEFAULT_AUTO_PRUNE_TERMINATED

    def validate(self) -> None:
        """Validate configuration parameters against invariants MCPCFG-INV1..MCPCFG-INV8."""
        if not self.store_path or not self.store_path.strip():
            raise McpConfigError("MCPCFG-INV1 violation: store_path cannot be empty")
        if "\0" in self.store_path:
            raise McpConfigError("MCPCFG-INV1 violation: store_path cannot contain NUL bytes")
        if ".." in Path(self.store_path).parts:
            raise McpConfigError("MCPCFG-INV1 violation: store_path cannot contain directory traversal ('..')")

        if not (MIN_ACTIVE_SESSIONS <= self.max_active_sessions <= MAX_ALLOWED_ACTIVE_SESSIONS):
            raise McpConfigError(
                f"MCPCFG-INV2 violation: max_active_sessions ({self.max_active_sessions}) "
                f"must be in [{MIN_ACTIVE_SESSIONS}, {MAX_ALLOWED_ACTIVE_SESSIONS}]"
            )

        if not (MIN_IDLE_TIMEOUT <= self.session_idle_timeout_seconds <= MAX_ALLOWED_IDLE_TIMEOUT):
            raise McpConfigError(
                f"MCPCFG-INV3 violation: session_idle_timeout_seconds ({self.session_idle_timeout_seconds}) "
                f"must be in [{MIN_IDLE_TIMEOUT}, {MAX_ALLOWED_IDLE_TIMEOUT}]"
            )

        if not (MIN_EXECUTION_TIMEOUT <= self.default_execution_timeout_seconds <= MAX_ALLOWED_EXECUTION_TIMEOUT):
            raise McpConfigError(
                f"MCPCFG-INV4 violation: default_execution_timeout_seconds ({self.default_execution_timeout_seconds}) "
                f"must be in [{MIN_EXECUTION_TIMEOUT}, {MAX_ALLOWED_EXECUTION_TIMEOUT}]"
            )

        if not (MIN_ARGUMENTS_SIZE <= self.max_arguments_size_bytes <= MAX_ALLOWED_ARGUMENTS_SIZE):
            raise McpConfigError(
                f"MCPCFG-INV5 violation: max_arguments_size_bytes ({self.max_arguments_size_bytes}) "
                f"must be in [{MIN_ARGUMENTS_SIZE}, {MAX_ALLOWED_ARGUMENTS_SIZE}]"
            )

        if not (MIN_TOOLS_COUNT <= self.max_tools_count <= MAX_ALLOWED_TOOLS_COUNT):
            raise McpConfigError(
                f"MCPCFG-INV6 violation: max_tools_count ({self.max_tools_count}) "
                f"must be in [{MIN_TOOLS_COUNT}, {MAX_ALLOWED_TOOLS_COUNT}]"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store_path": self.store_path,
            "max_active_sessions": self.max_active_sessions,
            "session_idle_timeout_seconds": self.session_idle_timeout_seconds,
            "default_execution_timeout_seconds": self.default_execution_timeout_seconds,
            "max_arguments_size_bytes": self.max_arguments_size_bytes,
            "max_tools_count": self.max_tools_count,
            "require_admin_grant": self.require_admin_grant,
            "auto_prune_terminated": self.auto_prune_terminated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> McpServerCoreConfig:
        cfg = cls(
            store_path=data.get("store_path", DEFAULT_STORE_PATH),
            max_active_sessions=int(data.get("max_active_sessions", DEFAULT_MAX_ACTIVE_SESSIONS)),
            session_idle_timeout_seconds=int(data.get("session_idle_timeout_seconds", DEFAULT_SESSION_IDLE_TIMEOUT)),
            default_execution_timeout_seconds=int(data.get("default_execution_timeout_seconds", DEFAULT_EXECUTION_TIMEOUT)),
            max_arguments_size_bytes=int(data.get("max_arguments_size_bytes", DEFAULT_MAX_ARGUMENTS_SIZE)),
            max_tools_count=int(data.get("max_tools_count", DEFAULT_MAX_TOOLS_COUNT)),
            require_admin_grant=bool(data.get("require_admin_grant", DEFAULT_REQUIRE_ADMIN_GRANT)),
            auto_prune_terminated=bool(data.get("auto_prune_terminated", DEFAULT_AUTO_PRUNE_TERMINATED)),
        )
        cfg.validate()
        return cfg

    def save_to_file(self, path: str) -> None:
        """Atomically persist configuration to path using temporary file and atomic rename."""
        self.validate()
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f"{p.name}.tmp.{os.getpid()}")
        data_str = json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(data_str)
        os.replace(tmp, p)

    @classmethod
    def load_from_file(cls, path: str) -> McpServerCoreConfig:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        if p.stat().st_size > MAX_CONFIG_FILE_BYTES:
            raise McpConfigError(f"Config file size {p.stat().st_size} exceeds {MAX_CONFIG_FILE_BYTES} bytes")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise McpConfigError("Config file must contain a JSON object")
        return cls.from_dict(data)

    @classmethod
    def resolve(
        cls,
        cli_opts: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
    ) -> McpServerCoreConfig:
        """Resolve configuration using strict precedence: CLI > Env > File > Defaults."""
        # 1. Start with defaults or file
        base_data: Dict[str, Any] = {}
        target_file = config_path or os.environ.get("AIOS_MCP_CONFIG_PATH")
        if target_file and os.path.exists(target_file):
            file_cfg = cls.load_from_file(target_file)
            base_data = file_cfg.to_dict()

        # 2. Overlay environment variables
        if "AIOS_MCP_STORE_PATH" in os.environ:
            base_data["store_path"] = os.environ["AIOS_MCP_STORE_PATH"]
        if "AIOS_MCP_MAX_SESSIONS" in os.environ:
            base_data["max_active_sessions"] = int(os.environ["AIOS_MCP_MAX_SESSIONS"])
        if "AIOS_MCP_IDLE_TIMEOUT" in os.environ:
            base_data["session_idle_timeout_seconds"] = int(os.environ["AIOS_MCP_IDLE_TIMEOUT"])
        if "AIOS_MCP_EXECUTION_TIMEOUT" in os.environ:
            base_data["default_execution_timeout_seconds"] = int(os.environ["AIOS_MCP_EXECUTION_TIMEOUT"])
        if "AIOS_MCP_MAX_ARGS_SIZE" in os.environ:
            base_data["max_arguments_size_bytes"] = int(os.environ["AIOS_MCP_MAX_ARGS_SIZE"])
        if "AIOS_MCP_REQUIRE_ADMIN_GRANT" in os.environ:
            base_data["require_admin_grant"] = os.environ["AIOS_MCP_REQUIRE_ADMIN_GRANT"].lower() in ("1", "true", "yes")

        # 3. Overlay explicit CLI options
        if cli_opts:
            for k, v in cli_opts.items():
                if v is not None:
                    base_data[k] = v

        cfg = cls.from_dict(base_data)
        cfg.validate()
        return cfg
