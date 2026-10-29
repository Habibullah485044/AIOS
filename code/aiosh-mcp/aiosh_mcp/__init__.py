"""AIOS MCP server — exposes the AIOS subsystem surface over MCP (ADR-0035 §D-2)."""
__version__ = "0.1.0"

from .release import PackageManifest, BackupSnapshot, generate_release, create_backup
from . import mcp_server_core_data_model
from . import mcp_server_core_service
from . import mcp_server_core_cli
from . import mcp_server_core_policy
from . import mcp_server_core_observability
from . import model_backend_adapters_data_model
from . import model_backend_adapters_service
from . import model_backend_adapters_cli
from . import model_backend_adapters_api


from . import model_backend_adapters_doc
