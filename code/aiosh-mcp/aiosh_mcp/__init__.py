"""AIOS MCP server — exposes the AIOS subsystem surface over MCP (ADR-0035 §D-2)."""
__version__ = "0.1.0"

from .release import PackageManifest, BackupSnapshot, generate_release, create_backup
from . import mcp_server_core_data_model
from . import mcp_server_core_service
from . import mcp_server_core_cli
from . import mcp_server_core_policy

