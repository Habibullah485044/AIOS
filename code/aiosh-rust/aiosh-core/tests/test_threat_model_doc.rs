//! Unit Tests for Threat Model Documentation Subsystem (T-02785).

use aiosh_core::threat_model_doc::*;

#[test]
fn test_threat_doc_canonical_topics_present() {
    let repo = ThreatDocRepository::new();
    let topics = repo.list_topics();

    assert_eq!(topics.len(), 6);
    let ids: Vec<&str> = topics.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"threat.arch.stride"));
    assert!(ids.contains(&"threat.lifecycle.states"));
    assert!(ids.contains(&"threat.service.api"));
    assert!(ids.contains(&"threat.policy.gates"));
    assert!(ids.contains(&"threat.observability.metrics"));
    assert!(ids.contains(&"threat.recovery.backup"));
}

#[test]
fn test_threat_doc_get_topic() {
    let repo = ThreatDocRepository::new();

    // Positive
    let topic = repo.get_topic("threat.arch.stride").expect("find topic");
    assert_eq!(topic.category, ThreatDocCategory::Architecture);
    assert!(!topic.summary.is_empty());
    assert!(!topic.sections.is_empty());
    assert!(!topic.related_topics.is_empty());

    // Negative: Non-existent
    assert!(repo.get_topic("threat.nonexistent.fake").is_none());

    // Negative: Path traversal attempts and control characters
    assert!(repo.get_topic("../threat.arch.stride").is_none());
    assert!(repo.get_topic("threat/arch/stride").is_none());
    assert!(repo.get_topic("threat\\arch\\stride").is_none());
    assert!(repo.get_topic("<script>alert(1)</script>").is_none());
    assert!(repo.get_topic("threat\0stride").is_none());
    assert!(repo.get_topic("   ").is_none());
}

#[test]
fn test_threat_doc_search_scoring_and_ranking() {
    let repo = ThreatDocRepository::new();

    // 1. Search for "stride architecture"
    let results = repo.search("stride architecture").expect("search stride");
    assert!(!results.is_empty());
    assert_eq!(results[0].topic_id, "threat.arch.stride");
    assert!(results[0].score > 0);
    assert!(!results[0].snippet.is_empty());

    // 2. Search for "lifecycle state machine"
    let results2 = repo.search("lifecycle state machine").expect("search lifecycle");
    assert!(!results2.is_empty());
    assert_eq!(results2[0].topic_id, "threat.lifecycle.states");

    // 3. Search for "policy gates enforcing"
    let results3 = repo.search("policy gates enforcing").expect("search policy");
    assert!(!results3.is_empty());
    assert_eq!(results3[0].topic_id, "threat.policy.gates");

    // 4. Search for "observability metrics"
    let results4 = repo.search("observability metrics").expect("search metrics");
    assert!(!results4.is_empty());
    assert_eq!(results4[0].topic_id, "threat.observability.metrics");
}

#[test]
fn test_threat_doc_search_boundaries() {
    let repo = ThreatDocRepository::new();

    // Empty query fails
    let err_empty = repo.search("   ").unwrap_err();
    assert!(err_empty.contains(THREATDOC_ERR_QUERY_BOUNDS));

    // Oversized query fails
    let long_q = "a".repeat(MAX_THREAT_DOC_QUERY_LEN + 1);
    let err_long = repo.search(&long_q).unwrap_err();
    assert!(err_long.contains(THREATDOC_ERR_QUERY_BOUNDS));

    // Control characters fail
    let err_ctrl = repo.search("threat\x00search").unwrap_err();
    assert!(err_ctrl.contains(THREATDOC_ERR_QUERY_BOUNDS));
}

#[test]
fn test_threat_doc_render_markdown() {
    let repo = ThreatDocRepository::new();

    let md = repo.render_markdown("threat.arch.stride").expect("renders markdown");
    assert!(md.contains("# STRIDE Threat Modeling Architecture"));
    assert!(md.contains("**Category**: `architecture`"));
    assert!(md.contains("**ID**: `threat.arch.stride`"));
    assert!(md.contains("## STRIDE Classification Matrix"));
    assert!(md.contains("### Related Topics"));

    // Render non-existent topic fails
    let err_missing = repo.render_markdown("threat.missing").unwrap_err();
    assert!(err_missing.contains(THREATDOC_ERR_NOT_FOUND));
}

#[test]
fn test_threat_doc_list_by_category() {
    let repo = ThreatDocRepository::new();

    let arch_topics = repo.list_by_category(ThreatDocCategory::Architecture);
    assert_eq!(arch_topics.len(), 1);
    assert_eq!(arch_topics[0].id, "threat.arch.stride");

    let policy_topics = repo.list_by_category(ThreatDocCategory::Policy);
    assert_eq!(policy_topics.len(), 1);
    assert_eq!(policy_topics[0].id, "threat.policy.gates");
}
