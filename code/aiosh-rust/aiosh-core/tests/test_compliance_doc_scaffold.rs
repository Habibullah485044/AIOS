//! Scaffold verification test for Compliance Mapping Documentation Subsystem (T-02945).

use aiosh_core::compliance_doc::{
    ComplianceDocCategory, ComplianceDocRepository, ComplianceDocSection, ComplianceDocTopic,
    COMPLYDOC_ERR_NOT_FOUND, COMPLYDOC_ERR_QUERY_BOUNDS, MAX_COMPLIANCE_DOC_QUERY_LEN,
    MAX_COMPLIANCE_DOC_SEARCH_RESULTS, MAX_COMPLIANCE_DOC_SNIPPET_LEN,
};

#[test]
fn test_compliance_doc_scaffold_constants_and_types() {
    assert_eq!(MAX_COMPLIANCE_DOC_QUERY_LEN, 128);
    assert_eq!(MAX_COMPLIANCE_DOC_SEARCH_RESULTS, 10);
    assert_eq!(MAX_COMPLIANCE_DOC_SNIPPET_LEN, 200);

    assert_eq!(COMPLYDOC_ERR_NOT_FOUND, "COMPLYDOC_ERR_NOT_FOUND");
    assert_eq!(COMPLYDOC_ERR_QUERY_BOUNDS, "COMPLYDOC_ERR_QUERY_BOUNDS");

    assert_eq!(ComplianceDocCategory::Architecture.as_str(), "architecture");
    assert_eq!(ComplianceDocCategory::Frameworks.as_str(), "frameworks");
    assert_eq!(ComplianceDocCategory::Lifecycle.as_str(), "lifecycle");
    assert_eq!(ComplianceDocCategory::Service.as_str(), "service");
    assert_eq!(ComplianceDocCategory::Policy.as_str(), "policy");
    assert_eq!(ComplianceDocCategory::Observability.as_str(), "observability");
    assert_eq!(ComplianceDocCategory::Recovery.as_str(), "recovery");

    let sec = ComplianceDocSection {
        title: "Test Section".to_string(),
        content: "Section content".to_string(),
    };
    assert_eq!(sec.title, "Test Section");

    let topic = ComplianceDocTopic {
        id: "comply-test".to_string(),
        title: "Test Topic".to_string(),
        category: ComplianceDocCategory::Architecture,
        summary: "A test topic summary".to_string(),
        sections: vec![sec],
        related_topics: vec!["comply-other".to_string()],
    };
    let md = topic.to_markdown();
    assert!(md.contains("# Test Topic"));
    assert!(md.contains("**Category**: `architecture`"));
    assert!(md.contains("## Test Section"));
}

#[test]
fn test_compliance_doc_scaffold_loud_failure_stubs() {
    let repo = ComplianceDocRepository::new();
    assert_eq!(repo.list_topics().len(), 0);

    let get_res = repo.get_topic("comply-test");
    assert!(get_res.is_err());
    assert!(get_res.unwrap_err().contains("not implemented"));

    let search_res = repo.search("test");
    assert!(search_res.is_err());
    assert!(search_res.unwrap_err().contains("not implemented"));
}
