"""Scaffold tests for Model Backend Adapters Security Policy (T-03225)."""

import pytest
from aiosh_mcp import model_backend_adapters_security_policy as modsec


def test_secpol_module_exports():
    assert hasattr(modsec, "PolicyVerdict")
    assert hasattr(modsec, "ModelSecurityPolicy")


def test_secpol_scaffold_structure():
    policy = modsec.ModelSecurityPolicy()
    assert hasattr(policy, "evaluate")
    assert hasattr(policy, "sanitize")
