//! Unit tests for Incident Response Runbooks Documentation Subsystem (T-03047).

use aiosh_core::incident_runbook_doc::{
    RunbookDocCategory, RunbookDocRepository, IRDOC_ERR_QUERY_BOUNDS,
    MAX_RUNBOOK_DOC_QUERY_LEN,
};

#[test]
fn test_unit_case1_valid_input_lookup_and_search() {
    let repo = RunbookDocRepository::new();
    let topic = repo.get_topic("runbook.tools.scanning");
    assert!(topic.is_some());
    let t = topic.unwrap();
    assert_eq!(t.category, RunbookDocCategory::SecurityTools);
    assert!(t.summary.contains("aiosh scan"));

    let hits = repo.search("RustSec", None).expect("valid search");
    assert!(!hits.is_empty());
}

#[test]
fn test_unit_case2_invalid_input_path_traversal_and_delimiters() {
    let repo = RunbookDocRepository::new();

    assert!(repo.get_topic("").is_none());
    assert!(repo.get_topic("../secrets").is_none());
    assert!(repo.get_topic("/etc/passwd").is_none());
    assert!(repo.get_topic("topic\\nested").is_none());
    assert!(repo.get_topic("topic\0null").is_none());
    assert!(repo.get_topic(".leading_dot").is_none());
    assert!(repo.get_topic("-leading_hyphen").is_none());
}

#[test]
fn test_unit_case3_boundary_values_query_length() {
    let repo = RunbookDocRepository::new();

    // Query of length exactly 128 chars is allowed
    let valid_exact_128 = "a".repeat(MAX_RUNBOOK_DOC_QUERY_LEN);
    let res = repo.search(&valid_exact_128, None);
    assert!(res.is_ok());

    // Query of length 129 chars exceeds boundary
    let invalid_129 = "a".repeat(MAX_RUNBOOK_DOC_QUERY_LEN + 1);
    let err = repo.search(&invalid_129, None);
    assert_eq!(err, Err(IRDOC_ERR_QUERY_BOUNDS));

    // Whitespace only or empty
    assert_eq!(repo.search("", None), Err(IRDOC_ERR_QUERY_BOUNDS));
    assert_eq!(repo.search("   ", None), Err(IRDOC_ERR_QUERY_BOUNDS));
}

#[test]
fn test_unit_case4_primary_failure_mode_unicode_and_not_found() {
    let repo = RunbookDocRepository::new();

    // Query composed purely of zero-width and invisible chars sanitizes to empty
    let invisible_only = "\u{200B}\u{200C}\u{FEFF}\u{202A}";
    assert_eq!(repo.search(invisible_only, None), Err(IRDOC_ERR_QUERY_BOUNDS));

    // Non-existent topic returns None
    assert!(repo.get_topic("runbook.nonexistent.entry").is_none());
}
