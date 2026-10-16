# ScopeSentry Reference & Architecture Notes

- **Project**: ScopeSentry
- **Official GitHub**: [Autumn-27/ScopeSentry](https://github.com/Autumn-27/ScopeSentry)
- **Scanner Core**: [Autumn-27/ScopeSentry-Scan](https://github.com/Autumn-27/ScopeSentry-Scan)
- **Official Website**: [https://www.scope-sentry.top](https://www.scope-sentry.top)
- **Official Documentation**: [https://www.scope-sentry.top/en/](https://www.scope-sentry.top/en/)
- **Plugin Marketplace**: [https://plugin.scope-sentry.top](https://plugin.scope-sentry.top)

---

## 1. Overview & Capabilities

ScopeSentry is an open-source security asset mapping and vulnerability detection platform designed for distributed environments:
- **Asset Mapping & Management**: Subdomain enumeration, open port discovery, service identification, ICP filing lookup, and asset categorization.
- **Vulnerability & Exposure Detection**: Proof-of-concept (POC) vulnerability scanning, information leakage detection, and subdomain takeover monitoring.
- **Web Crawling & Page Monitoring**: Automated crawler pipelines, directory brute-forcing, URL extraction, and web page modification monitoring.
- **Distributed Node Architecture**: Central management controller coordinating distributed scanner worker nodes across networks.
- **MCP Server Integration**: Includes a Model Context Protocol (MCP) server endpoint (`internal/mcp`) allowing MCP clients (such as Cursor or AI assistants) to query projects, tasks, templates, and asset metadata via API tokens.

---

## 2. Technical Stack & Architecture

| Layer | Technology | Primary Function |
|:---|:---|:---|
| **Backend Server** | Go / Gin / GORM | Central API server, scheduler, task coordination, database persistence, and MCP endpoint. |
| **Scanner Worker** | Go (`ScopeSentry-Scan`) | Distributed scanning agent executing port/web/vulnerability checks. |
| **Frontend UI** | Vue 3 + Vite + Element Plus | Web-based management console for projects, scans, rules, and plugins. |
| **Primary Database**| MongoDB 7.0+ | Stores asset records, scan results, vulnerability findings, and task history. |
| **Message Broker** | Redis 7.0+ | Task queues, node heartbeat management, and distributed caching. |
| **Orchestration**  | Docker & Docker Compose | Single-host or multi-node containerized deployment. |

---

## 3. Deployment & Setup Requirements

### Prerequisites
* **Docker Engine** & **Docker Compose**
* **MongoDB 7.0+**
* **Redis 7.0+**
* **Go 1.21+** (for building from source)
* **Node.js 18+ / NPM** (for frontend development)

### Standard Deployment (Docker Compose)
```bash
git clone https://github.com/Autumn-27/ScopeSentry.git
cd ScopeSentry

# Configure passwords and ports in .env
docker-compose -f single-host-deployment.yml up -d
```

Containers initialized:
1. `scopesentry-mongodb`: Database backend (`:27017`)
2. `scopesentry-redis`: Queue and cache broker (`:6379`)
3. `scope-sentry`: Management server (`:8082`)
4. `scopesentry-scan`: Default scanning worker node

---

## 4. MCP Protocol Configuration

ScopeSentry exposes an MCP server interface at `/mcp`:

```json
{
  "mcpServers": {
    "scopesentry": {
      "url": "http://<server-host>:8082/mcp",
      "headers": {
        "X-API-Key": "ssk_your_api_key_here"
      }
    }
  }
}
```

Key exposed MCP actions:
* `list_projects`: Fetch projects grouped by tags.
* `get_project`: Retrieve project asset scope and metadata.
* `list_tasks`: List active and completed scan runs.
* `list_scan_templates`: View available scanning workflows and module templates.
* `list_plugins`: Inspect installed scanner plugins and configurations.
