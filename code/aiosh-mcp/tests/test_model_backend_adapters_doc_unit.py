"""Comprehensive Unit Tests for Model Backend Adapters Documentation (T-03247)."""

import pytest
from aiosh_mcp.model_backend_adapters_doc import (
    ModelAdapterDocTopic,
    ModelAdapterDocCatalog,
    sanitize_doc_query,
    validate_topic_id,
    MAX_DOC_QUERY_LEN,
    MAX_DOC_SEARCH_RESULTS,
    MODDOC_ERR_INVALID_ID,
)


class TestTopicValidation:
    """Tests for validate_topic_id syntax and traversal enforcement."""

    @pytest.mark.parametrize("valid_id", [
        "model.overview",
        "model.providers",
        "model.fallback",
        "model.security",
        "model.observability",
        "custom-topic_v1.0",
        "A123",
        "a" * 64,
    ])
    def test_valid_ids(self, valid_id: str):
        validate_topic_id(valid_id)

    @pytest.mark.parametrize("invalid_id", [
        "",
        "   ",
        "../traversal",
        "..\\traversal",
        "/etc/passwd",
        "\\windows\\system32",
        "sub/topic",
        "topic with spaces",
        "topic$name",
        "topic;drop",
        "<script>",
        "topic\0null",
        "a" * 65,
    ])
    def test_invalid_ids_raise_value_error(self, invalid_id: str):
        with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
            validate_topic_id(invalid_id)


class TestQuerySanitizer:
    """Tests for sanitize_doc_query behavior."""

    def test_empty_and_whitespace(self):
        assert sanitize_doc_query("") == ""
        assert sanitize_doc_query("   ") == ""
        assert sanitize_doc_query(None) == ""

    def test_invisible_and_bidi_codepoints_stripped(self):
        # 0x200B (ZWSP), 0xFEFF (BOM), 0x202E (RLO)
        malicious = "hello\u200bworld\ufeff\u202eoverride"
        cleaned = sanitize_doc_query(malicious)
        assert cleaned == "helloworldoverride"

    def test_control_codes_stripped(self):
        query = "find\x00secret\x07tokens\x1b[31m"
        assert sanitize_doc_query(query) == "findsecrettokens[31m"

    def test_nfkc_normalization(self):
        # Ligature ﬁ (U+FB01) normalizes to 'fi'
        query = "deﬁne fallback"
        assert sanitize_doc_query(query) == "define fallback"

    def test_length_clamping(self):
        long_query = "word " * 50
        sanitized = sanitize_doc_query(long_query)
        assert len(sanitized) <= MAX_DOC_QUERY_LEN


class TestCatalogLookups:
    """Tests for ModelAdapterDocCatalog lookup and list APIs."""

    @pytest.fixture
    def catalog(self):
        return ModelAdapterDocCatalog()

    def test_get_topic_all_standard_topics(self, catalog):
        expected_ids = [
            "model.overview",
            "model.providers",
            "model.fallback",
            "model.security",
            "model.observability",
        ]
        for tid in expected_ids:
            topic = catalog.get_topic(tid)
            assert topic is not None
            assert topic.topic_id == tid
            assert len(topic.title) > 0
            assert len(topic.body) > 0
            assert len(topic.tags) > 0
            assert topic.updated_at == "2026-10-29"

    def test_get_topic_nonexistent(self, catalog):
        assert catalog.get_topic("nonexistent.topic") is None

    def test_get_topic_traversal_attack(self, catalog):
        with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
            catalog.get_topic("../../secret.env")

    def test_list_topics_sorted(self, catalog):
        topics = catalog.list_topics()
        assert len(topics) >= 5
        topic_ids = [t.topic_id for t in topics]
        assert topic_ids == sorted(topic_ids)

    def test_topic_to_dict_immutability(self, catalog):
        topic = catalog.get_topic("model.overview")
        d = topic.to_dict()
        assert isinstance(d, dict)
        assert d["topic_id"] == "model.overview"
        d["title"] = "Mutated"
        # Original topic object remains unmodified
        assert topic.title != "Mutated"


class TestCatalogSearch:
    """Tests for ModelAdapterDocCatalog keyword search and scoring."""

    @pytest.fixture
    def catalog(self):
        return ModelAdapterDocCatalog()

    def test_search_scoring_relevance(self, catalog):
        # Searching "circuit-breaker retry" should rank model.fallback first
        results = catalog.search("circuit-breaker retry")
        assert len(results) > 0
        assert results[0]["topic_id"] == "model.fallback"
        assert results[0]["category"] == "resilience"

    def test_search_tag_match(self, catalog):
        # Searching "ollama" should find model.providers
        results = catalog.search("ollama")
        assert len(results) > 0
        top = results[0]
        assert top["topic_id"] == "model.providers"

    def test_search_limit_clamping(self, catalog):
        # If user requests limit 100, clamped to MAX_DOC_SEARCH_RESULTS (10)
        results = catalog.search("model", limit=100)
        assert len(results) <= MAX_DOC_SEARCH_RESULTS

        # Limit 1 returns exactly 1
        results_one = catalog.search("model", limit=1)
        assert len(results_one) == 1

    def test_search_no_match(self, catalog):
        results = catalog.search("supercalifragilisticexpialidocious")
        assert results == []

    def test_search_sanitization_during_query(self, catalog):
        results = catalog.search("\x00\x07fallback\u200b")
        assert len(results) > 0
        assert results[0]["topic_id"] == "model.fallback"
