"""Unit tests for AI Control Plane Model Backend Adapters Data Model (T-03167).

Comprehensive coverage of invariants MODADAPT-INV1 through MODADAPT-INV5.
"""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelMessage,
    ModelUsage,
    ModelRequest,
    ModelResponse,
    ModelProviderType,
    validate_role,
    validate_temperature,
    MODADAPT_ERR_INVALID_ROLE,
    MODADAPT_ERR_BOUNDS,
    MODADAPT_ERR_SECRET_LEAK,
)


def test_modadapt_inv1_role_canonicalization():
    # Valid canonical roles
    for r in ["system", "user", "assistant", "tool"]:
        assert validate_role(r) == r
        assert validate_role(r.upper()) == r

    # Invalid roles fail closed
    for bad in ["admin", "root", "developer", "function", "moderator", "", "  "]:
        with pytest.raises(ValueError, match=MODADAPT_ERR_INVALID_ROLE):
            validate_role(bad)


def test_modadapt_inv2_token_non_negativity_and_sum():
    # Valid usage
    u = ModelUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150)
    u.validate_invariants()

    # Zero tokens allowed
    u_zero = ModelUsage(prompt_tokens=0, completion_tokens=0, total_tokens=0)
    u_zero.validate_invariants()

    # Negative tokens fail
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelUsage(prompt_tokens=-1, completion_tokens=10, total_tokens=9).validate_invariants()

    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelUsage(prompt_tokens=10, completion_tokens=-5, total_tokens=5).validate_invariants()

    # Sum violation fails
    with pytest.raises(AssertionError, match="MODADAPT-INV2"):
        ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=25).validate_invariants()


def test_modadapt_inv3_secret_isolation():
    # Valid environment variable references
    valid = ModelEndpointConfig(
        backend_id="ep-1",
        provider=ModelProviderType.OPENAI_COMPATIBLE,
        model_name="gpt-4o",
        api_key_env="AIOS_OPENAI_KEY",
    )
    valid.validate()

    # Rejection of raw plaintext tokens / keys
    for raw_secret in ["sk-abcdef1234567890", "sk-proj-xyz", "ghp_1234567890abcdef", "a" * 65]:
        bad = ModelEndpointConfig(
            backend_id="ep-bad",
            provider=ModelProviderType.OPENAI_COMPATIBLE,
            model_name="gpt-4o",
            api_key_env=raw_secret,
        )
        with pytest.raises(ValueError, match=MODADAPT_ERR_SECRET_LEAK):
            bad.validate()


def test_modadapt_inv4_parameter_bounds():
    # Temperature bounds [0.0, 2.0]
    assert validate_temperature(0.0) == 0.0
    assert validate_temperature(1.0) == 1.0
    assert validate_temperature(2.0) == 2.0

    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_temperature(-0.1)

    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        validate_temperature(2.1)

    # Timeout bounds [1000, 300000]
    ep_min_timeout = ModelEndpointConfig(
        backend_id="min-t",
        provider=ModelProviderType.MOCK,
        model_name="mock",
        timeout_ms=1000,
    )
    ep_min_timeout.validate()

    ep_max_timeout = ModelEndpointConfig(
        backend_id="max-t",
        provider=ModelProviderType.MOCK,
        model_name="mock",
        timeout_ms=300000,
    )
    ep_max_timeout.validate()

    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelEndpointConfig(
            backend_id="low-t",
            provider=ModelProviderType.MOCK,
            model_name="mock",
            timeout_ms=999,
        ).validate()

    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelEndpointConfig(
            backend_id="high-t",
            provider=ModelProviderType.MOCK,
            model_name="mock",
            timeout_ms=300001,
        ).validate()

    # Max retries [0, 10]
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelEndpointConfig(
            backend_id="retries",
            provider=ModelProviderType.MOCK,
            model_name="mock",
            max_retries=11,
        ).validate()


def test_request_validation_boundaries():
    # Empty messages list rejected
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelRequest(model_id="mock", messages=[]).validate()

    # Empty model ID rejected
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelRequest(model_id="", messages=[ModelMessage(role="user", content="hi")]).validate()

    # Negative or zero max_tokens rejected
    with pytest.raises(ValueError, match=MODADAPT_ERR_BOUNDS):
        ModelRequest(
            model_id="mock",
            messages=[ModelMessage(role="user", content="hi")],
            max_tokens=0,
        ).validate()
