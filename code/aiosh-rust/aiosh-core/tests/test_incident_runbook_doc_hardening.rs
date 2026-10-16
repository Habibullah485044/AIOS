//! Hardening tests for Incident Response Runbooks Documentation Subsystem (T-03050).

use aiosh_core::incident_runbook_doc::{
    RunbookDocCategory, RunbookDocRepository, RunbookDocResultEnvelope, RunbookDocSection,
    RunbookDocTopic, IRDOC_ERR_CAPACITY_EXCEEDED, IRDOC_ERR_NOT_FOUND, IRDOC_ERR_QUERY_BOUNDS,
    MAX_RUNBOOK_DOC_QUERY_LEN, MAX_RUNBOOK_DOC_TEXT_LEN, MAX_RUNBOOK_DOC_TOPICS_COUNT,
};

#[test]
fn test_doc_envelope_success_and_failure() {
    let env_ok = RunbookDocResultEnvelope::success(42);
    assert!(env_ok.ok);
    assert_eq!(env_ok.data, Some(42));
    assert!(env_ok.error_code.is_none());
    assert!(!env_ok.audit_row_required);

    let env_err: RunbookDocResultEnvelope<()> =
        RunbookDocResultEnvelope::failure("ERR_CODE", "Something broke");
    assert!(!env_err.ok);
    assert!(env_err.data.is_none());
    assert_eq!(env_err.error_code.as_deref(), Some("ERR_CODE"));
    assert_eq!(env_err.error_message.as_deref(), Some("Something broke"));
    assert!(env_err.audit_row_required);
}

#[test]
fn test_get_topic_safe_hardening() {
    let repo = RunbookDocRepository::new();

    // Valid topic
    let res = repo.get_topic_safe("runbook.arch.overview");
    assert!(res.ok);
    assert_eq!(res.data.unwrap().id, "runbook.arch.overview");

    // Missing topic
    let res_missing = repo.get_topic_safe("runbook.nonexistent");
    assert!(!res_missing.ok);
    assert_eq!(res_missing.error_code.as_deref(), Some(IRDOC_ERR_NOT_FOUND));
    assert!(res_missing.audit_row_required);

    // Traversal / Malicious topic ID
    let res_malicious = repo.get_topic_safe("../../etc/passwd");
    assert!(!res_malicious.ok);
    assert_eq!(res_malicious.error_code.as_deref(), Some(IRDOC_ERR_NOT_FOUND));
    assert!(res_malicious.audit_row_required);
}

#[test]
fn test_search_safe_bounds_hardening() {
    let repo = RunbookDocRepository::new();

    // Valid query
    let ok_res = repo.search_safe("telemetry", None);
    assert!(ok_res.ok);
    assert!(!ok_res.data.unwrap().is_empty());

    // Empty query
    let empty_res = repo.search_safe("   ", None);
    assert!(!empty_res.ok);
    assert_eq!(empty_res.error_code.as_deref(), Some(IRDOC_ERR_QUERY_BOUNDS));

    // Oversized query
    let long_query = "x".repeat(MAX_RUNBOOK_DOC_QUERY_LEN + 10);
    let long_res = repo.search_safe(&long_query, None);
    assert!(!long_res.ok);
    assert_eq!(long_res.error_code.as_deref(), Some(IRDOC_ERR_QUERY_BOUNDS));

    // Control and bidi characters sanitized to empty
    let bidi_empty = repo.search_safe("\u{200B}\u{202E}\u{FEFF}", None);
    assert!(!bidi_empty.ok);
    assert_eq!(bidi_empty.error_code.as_deref(), Some(IRDOC_ERR_QUERY_BOUNDS));
}

#[test]
fn test_add_topic_safe_capacity_and_text_bounds() {
    let mut repo = RunbookDocRepository { topics: Vec::new() };

    // Fill to capacity
    for i in 0..MAX_RUNBOOK_DOC_TOPICS_COUNT {
        let topic = RunbookDocTopic {
            id: format!("topic.test.{}", i),
            title: format!("Test Topic {}", i),
            category: RunbookDocCategory::Architecture,
            summary: "Test summary".to_string(),
            sections: vec![],
            related_topics: vec![],
        };
        assert!(repo.add_topic_safe(topic).is_ok());
    }

    // Exceed capacity
    let overflow_topic = RunbookDocTopic {
        id: "topic.test.overflow".to_string(),
        title: "Overflow Topic".to_string(),
        category: RunbookDocCategory::Architecture,
        summary: "Overflow".to_string(),
        sections: vec![],
        related_topics: vec![],
    };
    let err = repo.add_topic_safe(overflow_topic);
    assert_eq!(err, Err(IRDOC_ERR_CAPACITY_EXCEEDED));

    // Updating existing topic at capacity succeeds
    let update_topic = RunbookDocTopic {
        id: "topic.test.0".to_string(),
        title: "Updated Topic 0".to_string(),
        category: RunbookDocCategory::Architecture,
        summary: "Updated".to_string(),
        sections: vec![],
        related_topics: vec![],
    };
    assert!(repo.add_topic_safe(update_topic).is_ok());

    // Text limit check on summary
    let huge_summary = RunbookDocTopic {
        id: "topic.test.huge".to_string(),
        title: "Huge Summary".to_string(),
        category: RunbookDocCategory::Architecture,
        summary: "x".repeat(MAX_RUNBOOK_DOC_TEXT_LEN + 1),
        sections: vec![],
        related_topics: vec![],
    };
    assert_eq!(repo.add_topic_safe(huge_summary), Err(IRDOC_ERR_QUERY_BOUNDS));

    // Text limit check on section content
    let huge_section = RunbookDocTopic {
        id: "topic.test.huge_sec".to_string(),
        title: "Huge Section".to_string(),
        category: RunbookDocCategory::Architecture,
        summary: "Normal summary".to_string(),
        sections: vec![RunbookDocSection {
            title: "Sec".to_string(),
            content: "y".repeat(MAX_RUNBOOK_DOC_TEXT_LEN + 1),
        }],
        related_topics: vec![],
    };
    assert_eq!(repo.add_topic_safe(huge_section), Err(IRDOC_ERR_QUERY_BOUNDS));
}
