"""Hardening tests for Model Backend Adapters Data Model (T-03170)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelMessage,
    ModelProviderType,
    validate_backend_id,
    validate_base_url,
    MAX_MESSAGE_BYTES,
    MODADAPT_ERR_BOUNDS,
)


def test_hardening_backend_id_traversal_rejection():
    """Verify directory traversal attempts in backend_id are rejected."""
    bad_ids = [
        "../bad_backend",
        "../../etc/passwd",
        "foo/bar",
        "foo\\bar",
        "foo\0bar",
        "backend/../evil",
    ]
    for bad in bad_ids:
        with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
            validate_backend_id(bad)


def test_hardening_backend_id_syntax_and_bounds():
    """Verify backend_id length and character restrictions."""
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_backend_id("")
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_backend_id("   ")
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_backend_id("a" * 65)
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_backend_id("invalid spaces in id")
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_backend_id("bad@id!")

    # Valid ids
    assert validate_backend_id("openai.gpt-4o") == "openai.gpt-4o"
    assert validate_backend_id("anthropic_claude-3-5") == "anthropic_claude-3-5"
    assert validate_backend_id("mock-v1") == "mock-v1"


def test_hardening_base_url_scheme_and_controls():
    """Verify base_url restricts scheme and forbids control characters."""
    bad_urls = [
        "file:///etc/passwd",
        "ftp://localhost:8080",
        "javascript:alert(1)",
        "gopher://evil.com",
        "https://api.openai.com\x00/v1",
        "https://api.openai.com\r\n/v1",
    ]
    for url in bad_urls:
        with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
            validate_base_url(url)

    # Valid urls
    assert validate_base_url("https://api.openai.com/v1") == "https://api.openai.com/v1"
    assert validate_base_url("http://localhost:11434") == "http://localhost:11434"
    assert validate_base_url(None) is None


def test_hardening_message_content_payload_limit():
    """Verify message content larger than 1 MiB is rejected."""
    valid_msg = ModelMessage(role="user", content="hello world")
    assert valid_msg.content == "hello world"

    huge_content = "x" * (MAX_MESSAGE_BYTES + 1)
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelMessage(role="user", content=huge_content)


def test_hardening_endpoint_config_validation():
    """Verify ModelEndpointConfig enforces hardened backend_id and base_url."""
    cfg = ModelEndpointConfig(
        backend_id="../../escaped",
        provider=ModelProviderType.MOCK,
        model_name="mock-model",
    )
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        cfg.validate()

    cfg_bad_url = ModelEndpointConfig(
        backend_id="valid-backend",
        provider=ModelProviderType.MOCK,
        model_name="mock-model",
        base_url="file:///local/path",
    )
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        cfg_bad_url.validate()
