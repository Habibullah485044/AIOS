"""Seed lock: the security fields of every catalog entry are pinned (T-03419 finding C).

The property suite proves the catalog is never weaker than the *name rules*, but most entries are not covered by any
name rule: weakening one (dropping a grant, making it reversible, closing its world) would pass every property. Any
change to these fields must be made here, deliberately, in the same reviewed PR.

Fields: (effect, irreversible, requires_grant, scope_kind, open_world).
"""

from aiosh_mcp.tool_registry_data_model import default_catalog

LOCK = {
    "aios.agent_loop.abort": ("destructive", False, True, "none", False),
    "aios.agent_loop.complete": ("destructive", False, True, "none", False),
    "aios.agent_loop.config": ("read_only", False, False, "none", False),
    "aios.agent_loop.doc": ("read_only", False, False, "none", False),
    "aios.agent_loop.history": ("read_only", False, False, "none", False),
    "aios.agent_loop.init": ("additive", False, True, "none", False),
    "aios.agent_loop.list": ("read_only", False, False, "none", False),
    "aios.agent_loop.metrics": ("read_only", False, False, "none", False),
    "aios.agent_loop.recover": ("additive", False, True, "none", False),
    "aios.agent_loop.snapshot": ("read_only", False, False, "none", False),
    "aios.agent_loop.start": ("additive", False, True, "none", False),
    "aios.agent_loop.status": ("read_only", False, False, "none", False),
    "aios.agent_loop.step": ("additive", False, True, "none", False),
    "aios.agent_loop.validate": ("read_only", False, False, "none", False),
    "aios.anchor.create": ("additive", False, True, "none", False),
    "aios.anchor.verify": ("read_only", False, False, "none", False),
    "aios.audit.seen": ("read_only", False, False, "none", False),
    "aios.audit.segments": ("read_only", False, False, "none", False),
    "aios.audit.tail": ("read_only", False, False, "none", False),
    "aios.audit.verify": ("read_only", False, False, "none", False),
    "aios.backup.create": ("additive", True, True, "path", False),
    "aios.compliance": ("additive", False, False, "none", False),
    "aios.fs.read": ("read_only", False, True, "path", False),
    "aios.mcp.api.jsonrpc": ("additive", False, False, "none", False),
    "aios.mcp.api.ping": ("read_only", False, False, "none", False),
    "aios.mcp.config.get": ("read_only", False, False, "none", False),
    "aios.mcp.config.validate": ("read_only", False, False, "none", False),
    "aios.mcp.core.dispatch": ("additive", False, True, "none", False),
    "aios.mcp.core.list_tools": ("read_only", False, False, "none", False),
    "aios.mcp.core.status": ("read_only", False, False, "none", False),
    "aios.mcp.doc.lookup": ("read_only", False, False, "none", False),
    "aios.mcp.observability.snapshot": ("read_only", False, False, "none", False),
    "aios.mcp.policy.evaluate": ("read_only", False, False, "none", False),
    "aios.mcp.policy.status": ("read_only", False, False, "none", False),
    "aios.mcp.recovery.check": ("read_only", False, False, "path", False),
    "aios.mcp.recovery.repair": ("destructive", False, True, "path", False),
    "aios.mcp.test.run": ("read_only", False, False, "none", False),
    "aios.model.complete": ("additive", False, True, "none", True),
    "aios.model.doc.get": ("read_only", False, False, "none", False),
    "aios.model.doc.list": ("read_only", False, False, "none", False),
    "aios.model.doc.search": ("read_only", False, False, "none", False),
    "aios.model.endpoint.list": ("read_only", False, False, "none", False),
    "aios.model.endpoint.register": ("additive", False, True, "none", False),
    "aios.model.observability.snapshot": ("read_only", False, False, "none", False),
    "aios.model.recover_config": ("destructive", False, True, "path", False),
    "aios.model.service.health": ("read_only", False, False, "none", True),
    "aios.model.validate_config": ("read_only", False, False, "path", False),
    "aios.process.list": ("read_only", False, False, "none", False),
    "aios.release.generate": ("additive", True, True, "none", False),
    "aios.restraint.prove": ("additive", False, False, "none", False),
    "aios.restraint.verify": ("additive", False, False, "none", False),
    "aios.runbook": ("destructive", False, False, "none", False),
    "aios.scan": ("additive", False, False, "network", True),
    "aios.task": ("additive", False, False, "none", False),
    "aios.tool_registry.decide": ("read_only", False, False, "none", False),
    "aios.tool_registry.get": ("read_only", False, False, "none", False),
    "aios.tool_registry.list": ("read_only", False, False, "none", False),
    "aios.tool_registry.stats": ("read_only", False, False, "none", False),
    "audit.rotate": ("additive", False, True, "none", False),
    "fs.write": ("destructive", True, True, "path", False),
    "model_backend.complete": ("additive", False, True, "none", True),
    "model_backend.health": ("read_only", False, False, "none", True),
    "model_backend.list": ("read_only", False, False, "none", False),
    "model_backend.register": ("additive", False, True, "none", False),
    "model_backend.show": ("read_only", False, False, "none", False),
    "pentest.aircrack-ng": ("additive", True, True, "path", False),
    "pentest.nikto": ("additive", True, True, "network", True),
    "pentest.nmap": ("additive", True, True, "network", True),
    "pentest.sqlmap": ("destructive", True, True, "network", True),
    "pentest.tshark": ("additive", True, True, "path", False),
    "pep.capability.redeem": ("additive", False, True, "none", False),
    "system.reboot": ("destructive", True, True, "none", False),
    "system.shutdown": ("destructive", True, True, "none", False),
}


def test_every_entry_is_locked():
    entries = {e.canonical: e for e in default_catalog().entries()}
    assert set(entries) == set(LOCK), f"added: {sorted(set(entries) - set(LOCK))}, removed: {sorted(set(LOCK) - set(entries))}"


def test_security_fields_match_the_lock():
    changed = []
    for name, e in {e.canonical: e for e in default_catalog().entries()}.items():
        now = (e.effect.value, e.irreversible, e.requires_grant, e.scope_kind.value, e.open_world)
        if now != LOCK[name]:
            changed.append((name, LOCK[name], now))
    assert changed == [], f"security fields changed (locked, now): {changed}"
