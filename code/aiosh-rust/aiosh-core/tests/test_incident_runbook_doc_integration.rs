//! Integration tests for Incident Response Runbooks Documentation Subsystem (T-03048).

use aiosh_core::incident_runbook_doc::{
    RunbookDocCategory, RunbookDocRepository,
};

#[test]
fn test_integration_doc_end_to_end_lifecycle() {
    let repo = RunbookDocRepository::new();
    let all_topics = repo.list_topics();
    assert_eq!(all_topics.len(), 7);

    // 1. Verify every topic has non-empty fields and valid markdown rendering
    for topic in all_topics {
        assert!(!topic.id.is_empty());
        assert!(!topic.title.is_empty());
        assert!(!topic.summary.is_empty());
        let md = topic.to_markdown();
        assert!(md.starts_with("# "));
        assert!(md.contains(&topic.id));
    }

    // 2. Cross-category search integration
    let search_res = repo.search("containment", None).expect("search succeeds");
    assert!(!search_res.is_empty());

    // 3. Category isolation check
    let pol_topics = repo.list_by_category(RunbookDocCategory::Policy);
    assert_eq!(pol_topics.len(), 1);
    assert_eq!(pol_topics[0].id, "runbook.policy.governance");
}
