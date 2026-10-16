//! Scaffold tests for Incident Response Runbooks Documentation Subsystem (T-03045).

use aiosh_core::incident_runbook_doc::{
    sanitize_doc_query, validate_topic_id, RunbookDocCategory, RunbookDocRepository,
    IRDOC_ERR_NOT_FOUND,
};

#[test]
fn test_doc_scaffold_default_initialization() {
    let repo = RunbookDocRepository::new();
    let topics = repo.list_topics();
    assert_eq!(topics.len(), 7);

    let arch_topics = repo.list_by_category(RunbookDocCategory::Architecture);
    assert!(!arch_topics.is_empty());

    let topic = repo.get_topic("runbook.arch.overview");
    assert!(topic.is_some());
    let t = topic.unwrap();
    assert_eq!(t.category, RunbookDocCategory::Architecture);
    assert!(!t.sections.is_empty());
    assert!(!t.to_markdown().is_empty());
}

#[test]
fn test_doc_scaffold_query_sanitization_and_validation() {
    assert_eq!(sanitize_doc_query("  malware   scan  "), "malware   scan");
    assert_eq!(sanitize_doc_query("test\u{200B}zero"), "testzero");

    assert!(validate_topic_id("runbook.arch.overview").is_ok());
    assert_eq!(validate_topic_id(""), Err(IRDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("../secret"), Err(IRDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id(".hidden"), Err(IRDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("invalid/path"), Err(IRDOC_ERR_NOT_FOUND));
}
