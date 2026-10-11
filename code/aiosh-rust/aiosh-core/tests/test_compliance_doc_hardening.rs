//! Hardening verification tests for Compliance Mapping Documentation Subsystem (T-02950).

use aiosh_core::compliance_doc::{
    is_bidi_or_invisible, sanitize_doc_query, validate_topic_id, ComplianceDocRepository,
    COMPLYDOC_ERR_NOT_FOUND, COMPLYDOC_ERR_QUERY_BOUNDS,
};

#[test]
fn test_hardening_bidi_and_invisible_filtering() {
    assert!(is_bidi_or_invisible('\u{200B}')); // zero-width space
    assert!(is_bidi_or_invisible('\u{202E}')); // right-to-left override
    assert!(is_bidi_or_invisible('\u{FEFF}')); // BOM
    assert!(!is_bidi_or_invisible('a'));

    let injected = "search\u{202E}query\u{200B}with\u{FEFF}hidden";
    let cleaned = sanitize_doc_query(injected);
    assert_eq!(cleaned, "searchquerywithhidden");
}

#[test]
fn test_hardening_topic_id_boundary_rules() {
    // Valid IDs
    assert_eq!(validate_topic_id("compliance.arch.overview"), Ok(()));
    assert_eq!(validate_topic_id("my_custom-topic.1"), Ok(()));

    // Boundary dots / hyphens rejected
    assert_eq!(validate_topic_id(".compliance.arch"), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("compliance.arch."), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("-compliance.arch"), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("compliance.arch-"), Err(COMPLYDOC_ERR_NOT_FOUND));

    // Forbidden characters rejected
    assert_eq!(validate_topic_id("compliance$arch"), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("compliance@arch"), Err(COMPLYDOC_ERR_NOT_FOUND));
    assert_eq!(validate_topic_id("compliance arch"), Err(COMPLYDOC_ERR_NOT_FOUND));
}

#[test]
fn test_hardening_search_bounds_and_empty_clean_query() {
    let repo = ComplianceDocRepository::with_canonical_topics();

    // Query that consists purely of control and invisible characters becomes empty
    let purely_invisible = "\u{200B}\u{202E}\x00\x1b";
    let err = repo.search(purely_invisible).unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_QUERY_BOUNDS));

    // Excessive repeated spaces become empty
    let err = repo.search("     \t\r\n     ").unwrap_err();
    assert!(err.contains(COMPLYDOC_ERR_QUERY_BOUNDS));
}
