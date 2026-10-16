//! Implementation tests for Incident Response Runbooks Documentation Subsystem (T-03046).

use aiosh_core::incident_runbook_doc::{
    RunbookDocCategory, RunbookDocRepository, RunbookDocSection, RunbookDocTopic,
    IRDOC_ERR_QUERY_BOUNDS, MAX_RUNBOOK_DOC_QUERY_LEN,
};

#[test]
fn test_doc_implementation_topics_retrieval_and_markdown() {
    let repo = RunbookDocRepository::new();
    let topic = repo.get_topic("runbook.arch.overview").expect("topic should exist");

    assert_eq!(topic.id, "runbook.arch.overview");
    assert_eq!(topic.category, RunbookDocCategory::Architecture);
    assert!(topic.sections.len() >= 2);
    assert!(!topic.related_topics.is_empty());

    let md = topic.to_markdown();
    assert!(md.contains("# Incident Response Runbooks Architecture"));
    assert!(md.contains("## Core Architecture"));
    assert!(md.contains("### Related Topics"));
}

#[test]
fn test_doc_implementation_add_topic_mutation() {
    let mut repo = RunbookDocRepository::new();
    let initial_count = repo.list_topics().len();

    let custom = RunbookDocTopic {
        id: "runbook.custom.test".to_string(),
        title: "Custom Runbook Topic".to_string(),
        category: RunbookDocCategory::DataModel,
        summary: "Custom topic summary".to_string(),
        sections: vec![RunbookDocSection {
            title: "Custom Section".to_string(),
            content: "Custom content".to_string(),
        }],
        related_topics: vec![],
    };

    repo.add_topic(custom);
    assert_eq!(repo.list_topics().len(), initial_count + 1);
    assert!(repo.get_topic("runbook.custom.test").is_some());
}

#[test]
fn test_doc_implementation_search_ranking_and_filtering() {
    let repo = RunbookDocRepository::new();

    // 1. Search for "architecture" returns top hit with high score
    let results = repo.search("architecture", None).expect("search should succeed");
    assert!(!results.is_empty());
    assert_eq!(results[0].topic_id, "runbook.arch.overview");
    assert!(results[0].score >= 10);

    // 2. Search with category filter
    let filtered = repo
        .search("runbook", Some(RunbookDocCategory::Observability))
        .expect("search should succeed");
    assert!(!filtered.is_empty());
    for res in &filtered {
        assert_eq!(res.category, RunbookDocCategory::Observability);
    }

    // 3. Search bounds error on empty or oversized
    assert_eq!(repo.search("   ", None), Err(IRDOC_ERR_QUERY_BOUNDS));
    let huge_query = "a".repeat(MAX_RUNBOOK_DOC_QUERY_LEN + 1);
    assert_eq!(repo.search(&huge_query, None), Err(IRDOC_ERR_QUERY_BOUNDS));
}
