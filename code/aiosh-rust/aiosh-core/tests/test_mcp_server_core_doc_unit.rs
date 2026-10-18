//! Focused unit tests for Rust MCP Server Core Documentation Subsystem (MCPDOC-INV1..MCPDOC-INV5).

use aiosh_core::mcp_server_core_doc::{
    build_default_doc_catalog, sanitize_doc_query, validate_topic_id, McpDocError,
    MAX_MCP_DOC_QUERY_LEN, MAX_MCP_DOC_SEARCH_RESULTS,
};

#[test]
fn test_mcpdoc_inv1_rust_query_bounds() {
    let long_query = "word ".repeat(40);
    let sanitized = sanitize_doc_query(&long_query);
    assert!(sanitized.chars().count() <= MAX_MCP_DOC_QUERY_LEN);

    let dirty = "security\0\x1f\u{200b}\u{feff}policy";
    let clean = sanitize_doc_query(dirty);
    assert_eq!(clean, "securitypolicy");
}

#[test]
fn test_mcpdoc_inv2_rust_catalog_and_clamping() {
    let catalog = build_default_doc_catalog();
    let topics = catalog.list_topics();
    assert_eq!(topics.len(), 7);

    let results = catalog.search("fastmcp");
    assert!(!results.is_empty());
    assert!(results.len() <= MAX_MCP_DOC_SEARCH_RESULTS);
    assert_eq!(results[0].topic_id, "core.overview");
}

#[test]
fn test_mcpdoc_inv3_rust_topic_validation() {
    assert!(validate_topic_id("core.overview").is_ok());
    assert!(validate_topic_id("valid-topic_99").is_ok());

    assert!(matches!(
        validate_topic_id("../traversal"),
        Err(McpDocError::InvalidId(_))
    ));
    assert!(matches!(
        validate_topic_id(""),
        Err(McpDocError::InvalidId(_))
    ));
    assert!(matches!(
        validate_topic_id("topic/with/slash"),
        Err(McpDocError::InvalidId(_))
    ));
}
