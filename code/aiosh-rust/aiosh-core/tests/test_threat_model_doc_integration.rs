//! Integration Tests for Threat Model Documentation Subsystem (T-02786).

use aiosh_core::threat_model_doc::{ThreatDocCategory, ThreatDocRepository};
use aiosh_core::threat_model_service::ThreatModelService;

#[test]
fn test_threat_doc_service_and_stride_taxonomy_integration() {
    let repo = ThreatDocRepository::new();
    let service = ThreatModelService::with_canonical_threats();

    // 1. Verify every canonical threat category has corresponding documentation coverage
    for threat in service.list_threats() {
        let cat_str = threat.category.as_str();
        let results = repo.search(cat_str).expect("search succeeds");
        assert!(
            !results.is_empty(),
            "Expected documentation results for threat category '{}'",
            cat_str
        );

        // At least one result must be Architecture or Lifecycle or Service or Policy
        let matched = results.iter().any(|r| {
            matches!(
                r.category,
                ThreatDocCategory::Architecture
                    | ThreatDocCategory::Lifecycle
                    | ThreatDocCategory::Service
                    | ThreatDocCategory::Policy
                    | ThreatDocCategory::Observability
                    | ThreatDocCategory::Recovery
            )
        });
        assert!(matched, "Expected valid category for threat query '{}'", cat_str);
    }

    // 2. Cross-reference integrity check: No dangling related topic references
    let all_topics = repo.list_topics();
    for topic in all_topics {
        for related_id in &topic.related_topics {
            let found = repo.get_topic(related_id);
            assert!(
                found.is_some(),
                "Topic '{}' contains dangling related_topic reference '{}'",
                topic.id,
                related_id
            );
        }
    }

    // 3. Render Markdown across all canonical topics and assert formatting invariants
    for topic in all_topics {
        let md = repo.render_markdown(&topic.id).expect("render succeeds");
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
    let search_res = repo.search("stride").expect("search succeeds");
    let json_output = serde_json::to_string(&search_res).expect("serialize to json");
    assert!(json_output.contains("threat.arch.stride"));
    let deserialized: Vec<aiosh_core::threat_model_doc::ThreatDocSearchResult> =
        serde_json::from_str(&json_output).expect("deserialize from json");
    assert_eq!(search_res, deserialized);
}
