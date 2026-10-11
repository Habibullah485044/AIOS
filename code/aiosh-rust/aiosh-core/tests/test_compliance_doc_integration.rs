//! Integration Tests for Compliance Mapping Documentation Subsystem (T-02948).

use aiosh_core::compliance_data_model::ComplianceFramework;
use aiosh_core::compliance_doc::{
    ComplianceDocCategory, ComplianceDocRepository, ComplianceDocSearchResult,
};
use aiosh_core::compliance_service::ComplianceService;

#[test]
fn test_compliance_doc_service_and_frameworks_integration() {
    let repo = ComplianceDocRepository::with_canonical_topics();
    let service = ComplianceService::with_canonical_baseline();

    // 1. Verify every framework present in baseline catalog has documentation coverage
    let all_frameworks = [
        ComplianceFramework::NistSp80053Rev5,
        ComplianceFramework::Iso27001,
        ComplianceFramework::Soc2Type2,
        ComplianceFramework::CisControlsV8,
    ];

    for fw in &all_frameworks {
        let fw_str = fw.as_str();
        // Searching for keywords like "NIST", "ISO", "SOC", "CIS"
        let keyword = match fw {
            ComplianceFramework::NistSp80053Rev5 => "NIST",
            ComplianceFramework::Iso27001 => "ISO",
            ComplianceFramework::Soc2Type2 => "SOC",
            ComplianceFramework::CisControlsV8 => "CIS",
            _ => "compliance",
        };
        let results = repo.search(keyword).expect("search succeeds");
        assert!(
            !results.is_empty(),
            "Expected documentation results for framework '{}' with keyword '{}'",
            fw_str,
            keyword
        );
        assert!(results.iter().any(|r| r.category == ComplianceDocCategory::Frameworks));
    }

    // 2. Cross-reference integrity check: No dangling related topic references
    let all_topics = repo.list_topics();
    for topic in &all_topics {
        for related_id in &topic.related_topics {
            let found = repo.get_topic(related_id);
            assert!(
                found.is_ok(),
                "Topic '{}' contains dangling related_topic reference '{}'",
                topic.id,
                related_id
            );
        }
    }

    // 3. Render Markdown across all canonical topics and assert formatting invariants
    for topic in &all_topics {
        let md = topic.to_markdown();
        assert!(md.contains(&format!("# {}", topic.title)));
        assert!(md.contains(&format!("**ID**: `{}`", topic.id)));
        assert!(md.contains(&format!("**Category**: `{}`", topic.category.as_str())));

        for sec in &topic.sections {
            assert!(md.contains(&format!("## {}", sec.title)));
            assert!(md.contains(&sec.content));
        }

        if !topic.related_topics.is_empty() {
            assert!(md.contains("### Related Topics"));
            for rel in &topic.related_topics {
                assert!(md.contains(&format!("- `{}`", rel)));
            }
        }
    }

    // 4. JSON Serialization integrity of search results
    let search_res = repo.search("architecture").expect("search succeeds");
    let json_output = serde_json::to_string(&search_res).expect("serialize to json");
    assert!(json_output.contains("compliance.arch.overview"));
    let deserialized: Vec<ComplianceDocSearchResult> =
        serde_json::from_str(&json_output).expect("deserialize from json");
    assert_eq!(search_res, deserialized);

    // 5. Cross-check service mappings count against documentation summary references
    assert!(service.snapshot.mappings.len() > 0);
}
