//! Unit Tests for Secrets Handling Documentation Subsystem (T-02685).

use aiosh_core::secret_doc::*;

#[test]
fn test_secret_doc_canonical_topics_present() {
    let repo = SecretDocRepository::new();
    let topics = repo.list_topics();

    assert_eq!(topics.len(), 6);
    let ids: Vec<&str> = topics.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"secrets-overview"));
    assert!(ids.contains(&"secrets-lifecycle"));
    assert!(ids.contains(&"secrets-policy"));
    assert!(ids.contains(&"secrets-observability"));
    assert!(ids.contains(&"secrets-security"));
    assert!(ids.contains(&"secrets-recovery"));
}

#[test]
fn test_secret_doc_get_topic() {
    let repo = SecretDocRepository::new();

    // Positive
    let topic = repo.get_topic("secrets-overview").expect("find secrets-overview");
    assert_eq!(topic.category, SecretDocCategory::Architecture);
    assert!(!topic.summary.is_empty());
    assert!(!topic.sections.is_empty());
    assert!(!topic.related_topics.is_empty());

    // Negative: Non-existent
    assert!(repo.get_topic("non-existent-topic").is_none());

    // Negative: Malformed or path traversal attempts
    assert!(repo.get_topic("../secrets-overview").is_none());
    assert!(repo.get_topic("   ").is_none());
    assert!(repo.get_topic("secrets\0overview").is_none());
}

#[test]
fn test_secret_doc_search_scoring_and_ranking() {
    let repo = SecretDocRepository::new();

    // 1. Search for "policy"
    let results = repo.search("policy").expect("search policy");
    assert!(!results.is_empty());
    assert_eq!(results[0].topic_id, "secrets-policy");
    assert!(results[0].score > 0);

    // 2. Search for "observability telemetry"
    let results2 = repo.search("observability telemetry").expect("search observability");
    assert!(!results2.is_empty());
    assert_eq!(results2[0].topic_id, "secrets-observability");

    // 3. Search for "rotation revocation"
    let results3 = repo.search("rotation revocation").expect("search lifecycle");
    assert!(!results3.is_empty());
    assert_eq!(results3[0].topic_id, "secrets-lifecycle");
}

#[test]
fn test_secret_doc_search_boundaries() {
    let repo = SecretDocRepository::new();

    // Empty query fails
    let err_empty = repo.search("   ").unwrap_err();
    assert!(err_empty.contains(SECDOC_ERR_QUERY_BOUNDS));

    // Oversized query fails
    let long_q = "a".repeat(MAX_SECRET_DOC_QUERY_LEN + 1);
    let err_long = repo.search(&long_q).unwrap_err();
    assert!(err_long.contains(SECDOC_ERR_QUERY_BOUNDS));

    // Control characters fail
    let err_ctrl = repo.search("search\x00term").unwrap_err();
    assert!(err_ctrl.contains(SECDOC_ERR_QUERY_BOUNDS));
}

#[test]
fn test_secret_doc_render_markdown() {
    let repo = SecretDocRepository::new();

    let md = repo.render_markdown("secrets-overview").expect("renders markdown");
    assert!(md.contains("# Secrets Vault Architecture"));
    assert!(md.contains("**Category:** `architecture`"));
    assert!(md.contains("## Summary"));
    assert!(md.contains("## Zero-Disclosure Model"));
    assert!(md.contains("**Related Topics:**"));

    // Render non-existent topic fails
    let err_missing = repo.render_markdown("missing-topic").unwrap_err();
    assert!(err_missing.contains(SECDOC_ERR_NOT_FOUND));
}

#[test]
fn test_secret_doc_hardening() {
    let repo = SecretDocRepository::new();

    // 1. Path characters and markup in get_topic
    assert!(repo.get_topic("<script>").is_none());
    assert!(repo.get_topic("secrets/overview").is_none());
    assert!(repo.get_topic("secrets\\overview").is_none());

    // 2. Markup injection in search queries rejected
    let err_tag = repo.search("<script>alert(1)</script>").unwrap_err();
    assert!(err_tag.contains(SECDOC_ERR_QUERY_BOUNDS));

    let err_gt = repo.search("test > dev").unwrap_err();
    assert!(err_gt.contains(SECDOC_ERR_QUERY_BOUNDS));
}
