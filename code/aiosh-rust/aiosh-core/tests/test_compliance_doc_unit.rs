//! Unit tests for Compliance Mapping Documentation Subsystem (T-02947).

use aiosh_core::compliance_doc::{
    sanitize_doc_query, validate_topic_id, ComplianceDocCategory, ComplianceDocRepository,
    ComplianceDocSection, ComplianceDocTopic, COMPLYDOC_ERR_NOT_FOUND, COMPLYDOC_ERR_QUERY_BOUNDS,
    MAX_COMPLIANCE_DOC_QUERY_LEN, MAX_COMPLIANCE_DOC_SEARCH_RESULTS,
    MAX_COMPLIANCE_DOC_SNIPPET_LEN,
};

#[test]
fn test_canonical_topics_enumeration() {
    let repo = ComplianceDocRepository::with_canonical_topics();
    let topics = repo.list_topics();
    assert_eq!(topics.len(), 7);

    let ids: Vec<&str> = topics.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"compliance.arch.overview"));
    assert!(ids.contains(&"compliance.frameworks.taxonomy"));
    assert!(ids.contains(&"compliance.lifecycle.states"));
    assert!(ids.contains(&"compliance.service.api"));
    assert!(ids.contains(&"compliance.policy.gates"));
    assert!(ids.contains(&"compliance.observability.telemetry"));
    assert!(ids.contains(&"compliance.recovery.backup"));
}

#[test]
fn test_get_topic_positive() {
    let repo = ComplianceDocRepository::with_canonical_topics();

    let arch = repo.get_topic("compliance.arch.overview").expect("found arch topic");
    assert_eq!(arch.category, ComplianceDocCategory::Architecture);
    assert!(arch.title.contains("Architecture"));
    assert!(!arch.sections.is_empty());
    assert!(arch.related_topics.contains(&"compliance.frameworks.taxonomy".to_string()));

    let fw = repo.get_topic("compliance.frameworks.taxonomy").expect("found frameworks topic");
    assert_eq!(fw.category, ComplianceDocCategory::Frameworks);
    assert!(fw.sections.iter().any(|s| s.title.contains("NIST SP 800-53")));
}

#[test]
fn test_get_topic_negative_and_validation() {
    let repo = ComplianceDocRepository::with_canonical_topics();

    // Non-existent ID
    let err = repo.get_topic("compliance.nonexistent").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_NOT_FOUND));

    // Empty ID
    let err = repo.get_topic("").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_NOT_FOUND));

    // Path traversal attempt
    let err = repo.get_topic("../etc/passwd").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_NOT_FOUND));

    // Directory separator attempt
    let err = repo.get_topic("compliance/arch/overview").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_NOT_FOUND));

    // Control characters attempt
    let err = repo.get_topic("compliance\x00arch").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_NOT_FOUND));

    assert_eq!(validate_topic_id("valid.id"), Ok(()));
    assert_eq!(validate_topic_id(".."), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id(""), Err(COMPLYDOC_ERR_NOT_FOUND));
}

#[test]
fn test_query_sanitization() {
    assert_eq!(sanitize_doc_query("  clean query  "), "clean query");
    assert_eq!(sanitize_doc_query("hello\x00world\x1b[31m"), "helloworld[31m");
}

#[test]
fn test_search_relevance_and_scoring() {
    let repo = ComplianceDocRepository::with_canonical_topics();

    // Exact ID match: high score (+50)
    let hits = repo.search("compliance.frameworks.taxonomy").expect("search succeeds");
    assert!(!hits.is_empty());
    assert_eq!(hits[0].topic_id, "compliance.frameworks.taxonomy");
    assert!(hits[0].score >= 50);

    // Title match: "Architecture"
    let hits = repo.search("Architecture").expect("search succeeds");
    assert!(!hits.is_empty());
    assert_eq!(hits[0].topic_id, "compliance.arch.overview");
    assert!(hits[0].score >= 25);

    // Summary keyword match: "telemetry"
    let hits = repo.search("telemetry").expect("search succeeds");
    assert!(!hits.is_empty());
    assert_eq!(hits[0].topic_id, "compliance.observability.telemetry");

    // Section keyword match: "NIST"
    let hits = repo.search("NIST").expect("search succeeds");
    assert!(!hits.is_empty());
    assert_eq!(hits[0].topic_id, "compliance.frameworks.taxonomy");
}

#[test]
fn test_search_bounds_and_errors() {
    let repo = ComplianceDocRepository::with_canonical_topics();

    // Empty query rejected
    let err = repo.search("").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_QUERY_BOUNDS));

    // Whitespace query rejected
    let err = repo.search("     ").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_QUERY_BOUNDS));

    // Oversized query rejected (> 128 characters)
    let long_query = "a".repeat(MAX_COMPLIANCE_DOC_QUERY_LEN + 1);
    let err = repo.search(&long_query).unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_QUERY_BOUNDS));

    // Boundary query (128 characters) accepted
    let max_query = "a".repeat(MAX_COMPLIANCE_DOC_QUERY_LEN);
    let res = repo.search(&max_query);
    assert!(res.is_ok());
    assert!(res.unwrap().len() <= MAX_COMPLIANCE_DOC_SEARCH_RESULTS);
    assert_eq!(MAX_COMPLIANCE_DOC_SNIPPET_LEN, 200);
}

#[test]
fn test_snippet_and_markdown() {
    let topic = ComplianceDocTopic {
        id: "test.topic".to_string(),
        title: "Test Topic Title".to_string(),
        category: ComplianceDocCategory::Observability,
        summary: "This is a summary of the test topic.".to_string(),
        sections: vec![
            ComplianceDocSection {
                title: "Introduction".to_string(),
                content: "Intro content".to_string(),
            },
            ComplianceDocSection {
                title: "Details".to_string(),
                content: "Detailed content".to_string(),
            },
        ],
        related_topics: vec!["other.topic".to_string()],
    };

    let md = topic.to_markdown();
    assert!(md.contains("# Test Topic Title"));
    assert!(md.contains("**Category**: `observability`"));
    assert!(md.contains("**ID**: `test.topic`"));
    assert!(md.contains("## Introduction\n\nIntro content"));
    assert!(md.contains("## Details\n\nDetailed content"));
    assert!(md.contains("### Related Topics\n\n- `other.topic`"));

    let repo = ComplianceDocRepository::new();
    assert_eq!(repo.list_topics().len(), 0);
}
