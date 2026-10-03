//! AIOS core library — the Rust rewrite of the aiosh userspace stack.
//!
//! This crate replaces the previous dual-substrate implementation
//! (`code/aiosh-cli` in TypeScript + `code/aiosh-mcp` in Python) with a
//! single Rust implementation. All invariants that used to be enforced
//! by a TS↔Python cross-substrate test now live here as Rust unit and
//! integration tests:
//!
//!   - canonical JSON (byte-identical to the old Python `json.dumps(
//!     sort_keys=True, separators=(",",":"))` and TS `canonicalJson`)
//!   - SHA-256 hash-chained append-only audit ring (SQLite WAL)
//!   - Constitution rule-pack classifier (R-01..R-12)
//!   - PEP grant store and gate
//!   - Sprint-3 retention (checkpointed segment rotation + bloom filter)
//!   - Pillar-A pentest wrappers with safe defaults
//!   - Landlock + seccomp-bpf sandbox for `aiosh run`
//!   - Sprint-2 agent loop (Ollama + deterministic stub)
//!   - Task Ledger Control data model (T-00014 port of
//!     `tools/task_ledger.py`: atomic state, event log, no-skip law)

pub mod agent;
pub mod audit;
pub mod audit_chain_ext;
pub mod audit_chain_service;
pub mod audit_chain_config;
pub mod audit_chain_policy;
pub mod audit_chain_observability;
pub mod audit_chain_doc;
pub mod audit_chain_recovery;
pub mod base_image;
pub mod base_image_config;
pub mod base_image_observability;
pub mod base_image_policy;
pub mod base_image_recovery;
pub mod base_image_service;
pub mod canonical;
pub mod capability;
pub mod capability_config;
pub mod capability_service;
pub mod capability_policy;
pub mod capability_observability;
pub mod capability_doc;
pub mod capability_recovery;
pub mod ci;
pub mod ci_config;
pub mod classifier;
pub mod dispatch;
pub mod distro;
pub mod distro_config;
pub mod distro_observability;
pub mod distro_policy;
pub mod distro_recovery;
pub mod distro_service;
pub mod doc_index;
pub mod doc_index_config;
pub mod doc_index_service;
pub mod evidence;
pub mod evidence_config;
pub mod evidence_service;
pub mod fs_layout;
pub mod fs_layout_service;
pub mod fs_layout_service_key {
    //! Residue-grouping keys shared with `fs_layout_service` (kept beside `pep` so both
    //! the policy matcher and the residue cap resolve spelling aliases through one
    //! implementation of "what is this path's physical identity").
    pub use super::pep::{canonical_store_key, staged_file_destination};
}

pub mod handoff;

pub mod handoff_config;
pub mod handoff_service;
pub mod hardware;
pub mod hardware_config;
pub mod hardware_doc;
pub mod hardware_observability;
pub mod hardware_policy;
pub mod hardware_recovery;
pub mod hardware_service;
pub mod kernel_module;
pub mod kernel_module_config;
pub mod kernel_module_doc;
pub mod kernel_module_observability;
pub mod kernel_module_policy;
pub mod kernel_module_recovery;
pub mod kernel_module_service;
pub mod ledger;
pub mod ledger_config;
pub mod network;
pub mod network_config;
pub mod network_doc;
pub mod network_observability;
pub mod network_policy;
pub mod network_recovery;
pub mod network_service;
pub mod package;
pub mod package_config;
pub mod package_observability;
pub mod package_policy;
pub mod package_recovery;
pub mod package_service;
pub mod pentest;
pub mod pep;
pub mod pep_decision;
pub mod pep_decision_service;
pub mod pep_config;
pub mod pep_security_policy;
pub mod pep_observability;
pub mod pep_doc;
pub mod pep_recovery;
pub mod pep_grant;
pub mod pep_grant_service;
pub mod pep_grant_config;
pub mod pep_grant_security_policy;
pub mod pep_grant_observability;
pub mod pep_grant_doc;
pub mod pep_grant_recovery;
pub mod privilege_data_model;
pub mod privilege_service;
pub mod privilege_config;
pub mod privilege_policy;
pub mod privilege_observability;
pub mod privilege_doc;
pub mod privilege_recovery;
pub mod secret_data_model;
pub mod secret_service;
pub mod secret_config;
pub mod secret_policy;
pub mod secret_observability;
pub mod secret_doc;
pub mod secret_recovery;
pub mod release;
pub mod release_config;
pub mod repo_health;
pub mod repo_health_config;
pub mod repo_health_service;
pub mod retention;
#[allow(dead_code)]
pub mod sandbox;
pub mod sandbox_config;
pub mod sandbox_data_model;
pub mod sandbox_service;
pub mod sandbox_policy;
pub mod sandbox_observability;
pub mod sandbox_doc;
pub mod sandbox_recovery;
pub mod secrets;
pub mod secrets_config;
pub mod secrets_service;
pub mod service;
pub mod service_config;
pub mod service_observability;
pub mod service_policy;
pub mod service_recovery;
pub mod service_service;
pub mod session;
pub mod session_config;
pub mod session_observability;
pub mod session_policy;
pub mod session_recovery;
pub mod session_service;
pub mod system_update;
pub mod system_update_config;
pub mod system_update_doc;
pub mod system_update_observability;
pub mod system_update_policy;
pub mod system_update_recovery;
pub mod system_update_service;
pub mod task_service;
pub mod threat_model_data_model;
pub mod toolchain_config;
pub mod toolchain_service;
pub mod triage;
pub mod triage_config;
pub mod triage_service;
pub mod types;

pub use audit::{AuditRing, OpenOptions};
pub use classifier::classify;
pub use distro::{ArchTarget, CLibrary, DistroEvaluation, DistroFamily, DistroProfile, InitSystem};
pub use distro_service::DistroStore;
pub use fs_layout::{
    validate_directory_spec, validate_filesystem_layout, validate_mount_point,
    validate_partition_spec, DirectorySpec, FilesystemLayoutSpec, FsType, MountPointSpec,
    PartitionSpec, PartitionType,
};
pub use fs_layout_service::{
    FilesystemLayoutService, FilesystemLayoutStore, LayoutDiff, MountDiffItem, PartitionDiffItem,
    TargetEvaluation,
};
pub use handoff::{HandoffPriority, HandoffRecord, HandoffReport, HandoffStatus};
pub use handoff_service::HandoffStore;
pub use package::{
    PackageAction, PackageActionType, PackageDependency, PackageFormat, PackageQuery, PackageSpec,
    PackageState, PackageTransaction,
};
pub use package_recovery::{
    load_or_recover, recover_package_store_with_backup, validate_package_store,
    PackageValidationReport,
};
pub use package_service::{PackageStore, TransactionReport};
pub use pep::PepStore;
pub use service::{
    validate_service_name, validate_service_spec, validate_service_status, ServiceAction,
    ServiceDependency, ServiceDependencyType, ServiceHealth, ServiceQuery, ServiceRestartPolicy,
    ServiceSpec, ServiceStartupMode, ServiceState, ServiceStatus, ServiceType,
};
pub use service_config::ServiceConfig;
pub use service_observability::ServiceObservabilityReport;
pub use service_policy::{
    ServicePolicyMode, ServicePolicyVerdict, ServicePolicyViolation, ServiceSecurityPolicy,
};
pub use service_recovery::{ServiceRecoveryAction, ServiceValidationReport};
pub use service_service::{ServiceActionReport, ServiceStore};
pub use session::{
    transition_session_state, validate_session_id, validate_user_session_spec,
    validate_user_session_status, validate_username, SessionClass, SessionScope, SessionState,
    SessionType, UserSessionAction, UserSessionQuery, UserSessionSpec, UserSessionStatus,
    UserSessionStore,
};
pub use session_config::SessionConfig;
pub use session_observability::SessionObservabilityReport;
pub use session_policy::{
    SessionPolicyMode, SessionPolicyVerdict, SessionPolicyViolation, UserSessionSecurityPolicy,
};
pub use session_recovery::{SessionRecoveryAction, SessionValidationReport};
pub use session_service::{UserSessionActionReport, UserSessionService};
pub use hardware::{
    validate_hardware_inventory, DeviceClass, HardwareDevice, HardwareInventory,
    MAX_ATTRIBUTES_PER_DEVICE, MAX_ATTRIBUTE_KEY_LEN, MAX_ATTRIBUTE_VAL_LEN, MAX_DEVICES,
    MAX_DEVICE_ID_LEN, MAX_DEVICE_NAME_LEN, MAX_JSON_PAYLOAD_SIZE, MAX_PATH_LEN,
};
pub use hardware_config::HardwareConfig;
pub use hardware_policy::{
    HardwarePolicyMode, HardwarePolicyReport, HardwarePolicyViolation, HardwareSecurityPolicy,
};
pub use hardware_recovery::{
    check_inventory_file, recover_inventory_file, recover_inventory_in_memory, validate_inventory,
    HardwareRecoveryAction, HardwareRecoveryReport, HardwareValidationReport,
};
pub use hardware_service::{HardwareScanOptions, HardwareService};
pub use network::{
    validate_interface_name, validate_ip_address, validate_mac_address, validate_mtu,
    validate_network_interface, validate_network_state, validate_route, DnsConfig, InterfaceType,
    IpAddress, IpFamily, NetworkInterface, NetworkState, OperState, Route, MAX_IFACE_NAME_LEN,
    MAX_INTERFACES, MAX_MTU, MAX_ROUTES, MIN_MTU,
};
pub use network_service::NetworkService;
pub use network_config::NetworkConfig;
pub use network_policy::{
    validate_policy_path as validate_network_policy_path, NetworkPolicyMode, NetworkPolicyReport,
    NetworkPolicyViolation, NetworkSecurityPolicy, MAX_POLICY_FILE_BYTES as MAX_NETWORK_POLICY_FILE_BYTES,
};
pub use network_recovery::{
    check_network_file, recover_network_file, recover_network_state_in_memory,
    save_recovered_state_to_path, validate_network_state as validate_network_state_integrity,
    validate_network_store_path, NetworkRecoveryAction, NetworkRecoveryReport,
    NetworkValidationReport, MAX_NETWORK_STORE_SIZE,
};
pub use types::GENESIS_HASH;
pub use system_update::{
    PartitionTarget, SystemSlotStatus, SystemUpdateStatus, UpdateArtifact,
    UpdateChannel, UpdateManifest, UpdateSlot, UpdateState,
    MAX_ARTIFACTS_PER_MANIFEST, MAX_ARTIFACT_FILENAME_LEN,
    MAX_UPDATE_ID_LEN, MAX_UPDATE_PAYLOAD_SIZE, MAX_UPDATE_VERSION_LEN,
    UPD_DIGEST_ERROR, UPD_SLOT_ERROR, UPD_STATE_ERROR, UPD_VALIDATION_ERROR,
};
pub use system_update_service::{SystemUpdateService, SystemUpdateServiceConfig};
pub use system_update_config::{
    SystemUpdateConfig, DEFAULT_UPDATE_CONFIG_PATH, DEFAULT_UPDATE_STAGING_DIR,
    DEFAULT_UPDATE_STATE_DIR, MAX_UPDATE_CONFIG_FILE_BYTES, UCONF_VALIDATION_ERROR,
};
pub use system_update_policy::{
    SystemUpdateSecurityPolicy, UpdatePolicyMode, UpdatePolicyReport, UpdatePolicyViolation,
    MAX_POLICY_FILE_BYTES, UPOL_IO_ERROR, UPOL_PARSE_ERROR, UPOL_PATH_ERROR, UPOL_VALIDATION_ERROR,
    validate_policy_path,
};
pub use system_update_observability::{
    SystemUpdateObservabilityReport, sanitize_telemetry_text,
};
pub use system_update_doc::{
    SystemUpdateDocCategory, SystemUpdateDocIndex, SystemUpdateDocSearchResult,
    SystemUpdateDocTopic,
};
pub use system_update_recovery::{
    check_update_files, recover_update_files_with_backup, recover_update_state_in_memory,
    validate_update_state, validate_update_store_path, SystemUpdateRecoveryAction,
    SystemUpdateRecoveryReport, SystemUpdateValidationReport, MAX_UPDATE_STORE_SIZE,
};
pub use capability::{
    Capability, CapabilityConstraints, CapabilityError, CapabilityRight, CapabilityScope,
    MAX_ACTIONS_PER_SCOPE, MAX_CAPABILITY_ID_LEN, MAX_ISSUER_LEN, MAX_RESOURCE_URI_LEN,
    MAX_SUBJECT_LEN, CAP_ERROR_ATTENUATION, CAP_ERROR_EXPIRED, CAP_ERROR_NOT_YET_VALID,
    CAP_ERROR_QUOTA_BYTES, CAP_ERROR_QUOTA_INVOCATIONS, CAP_ERROR_REVOKED, CAP_ERROR_RIGHT,
    CAP_ERROR_SCOPE, CAP_ERROR_VALIDATION,
};
pub use capability_service::{
    CapabilityService, CSERV_IO_ERROR, CSERV_NOT_FOUND, CSERV_VALIDATION_ERROR,
    MAX_CAPABILITY_STORE_SIZE,
};
pub use pep_config::{
    PepConfig, DEFAULT_PEP_STORE_PATH, MAX_CONFIG_BYTES as MAX_PEP_CONFIG_BYTES,
    MAX_STORE_BYTES as MAX_PEP_STORE_BYTES, MIN_STORE_BYTES as MIN_PEP_STORE_BYTES,
    DEFAULT_MAX_STORE_BYTES as DEFAULT_PEP_MAX_STORE_BYTES,
    DEFAULT_MAX_RULES as DEFAULT_PEP_MAX_RULES, MAX_RULES_COUNT as MAX_PEP_RULES_COUNT,
    MIN_RULES_COUNT as MIN_PEP_RULES_COUNT,
    PEPCONF_ERR_BOUNDS, PEPCONF_ERR_IO, PEPCONF_ERR_PARSE, PEPCONF_ERR_VALIDATION,
};
pub use pep_security_policy::{
    PepEnforcementMode, PepObligationCriticality, PepSecurityPolicy,
    MAX_PEP_POLICY_DESC_LEN, MAX_PEP_POLICY_VERSION_LEN, MAX_PEP_SECURITY_POLICY_BYTES,
    MAX_PREFIX_LEN, MAX_RESTRICTED_PREFIXES,
    PEPPOL_ERR_IO, PEPPOL_ERR_PRIVILEGE, PEPPOL_ERR_TEMPORAL, PEPPOL_ERR_VALIDATION,
    validate_policy_path as validate_pep_security_policy_path,
};
pub use pep_observability::{
    PepObservabilityReport, PEPOBS_ERR_VALIDATION, PEP_HEALTH_UTILIZATION_THRESHOLD,
    sanitize_telemetry_text as sanitize_pep_telemetry_text,
};
pub use pep_doc::{
    extract_utf8_snippet as extract_pep_doc_utf8_snippet, PepDocCategory, PepDocIndex,
    PepDocSearchResult, PepDocSection, PepDocTopic, MAX_DOC_QUERY_LEN as MAX_PEP_DOC_QUERY_LEN,
    MAX_DOC_SEARCH_RESULTS as MAX_PEP_DOC_SEARCH_RESULTS,
    MAX_SNIPPET_LEN as MAX_PEP_DOC_SNIPPET_LEN, MAX_TOPIC_ID_LEN as MAX_PEP_DOC_TOPIC_ID_LEN,
};
pub use pep_recovery::{
    PepIssueSeverity, PepRecoveryManager, PepRecoveryResult, PepRecoveryStrategy,
    PepStoreValidator, PepValidationIssue, PepValidationReport,
    PEPRECV_ERR_CAPACITY, PEPRECV_ERR_CHECKSUM, PEPRECV_ERR_DUPLICATE_ID,
    PEPRECV_ERR_FILE_SIZE, PEPRECV_ERR_IO, PEPRECV_ERR_PARSE,
    PEPRECV_ERR_PATH_TRAVERSAL, PEPRECV_ERR_RULE_SYNTAX,
};
pub use pep_grant_config::{
    PepGrantConfig, DEFAULT_PEP_GRANT_STORE_PATH,
    MAX_CONFIG_BYTES as MAX_PEP_GRANT_CONFIG_BYTES,
    MAX_STORE_BYTES as MAX_PEP_GRANT_STORE_BYTES,
    MIN_STORE_BYTES as MIN_PEP_GRANT_STORE_BYTES,
    DEFAULT_MAX_STORE_BYTES as DEFAULT_PEP_GRANT_MAX_STORE_BYTES,
    DEFAULT_MAX_GRANTS as DEFAULT_PEP_GRANT_MAX_GRANTS,
    MAX_GRANTS_COUNT as MAX_PEP_GRANT_MAX_GRANTS_COUNT,
    MIN_GRANTS_COUNT as MIN_PEP_GRANT_MIN_GRANTS_COUNT,
    DEFAULT_MAX_DELEGATION_DEPTH, MAX_DELEGATION_DEPTH, MIN_DELEGATION_DEPTH,
    GRANTCONF_ERR_BOUNDS, GRANTCONF_ERR_IO, GRANTCONF_ERR_PARSE, GRANTCONF_ERR_VALIDATION,
};
pub use pep_grant_security_policy::{
    PepGrantEnforcementMode, PepGrantSecurityPolicy,
    DEFAULT_MAX_GRANT_DURATION_SECS, DEFAULT_MAX_POLICY_DELEGATION_DEPTH,
    GRANTPOL_ERR_DELEGATION_REJECTED, GRANTPOL_ERR_IO, GRANTPOL_ERR_LIFETIME_EXCEEDED,
    GRANTPOL_ERR_POLICY_VIOLATION, GRANTPOL_ERR_VALIDATION, MAX_GRANT_POLICY_BYTES,
    MAX_PERMISSIBLE_DURATION_SECS,
};
pub use pep_grant_observability::{
    PepGrantObservabilityReport, PEPOBS_GRANT_ERR_VALIDATION, PEP_GRANT_HEALTH_UTILIZATION_THRESHOLD,
    sanitize_grant_telemetry_text,
};
pub use pep_grant_doc::{
    PepGrantDocCategory, PepGrantDocIndex, PepGrantDocSearchResult, PepGrantDocSection, PepGrantDocTopic,
    GRANTDOC_ERR_NOT_FOUND, GRANTDOC_ERR_QUERY_BOUNDS, MAX_GRANT_DOC_QUERY_LEN,
    MAX_GRANT_DOC_SEARCH_RESULTS, MAX_GRANT_DOC_SNIPPET_LEN,
};
pub use pep_grant_recovery::{
    PepGrantIssueCode, PepGrantIssueSeverity, PepGrantRecoveryManager, PepGrantRecoveryResult,
    PepGrantRepairAction, PepGrantValidationIssue, PepGrantValidationReport,
    PEPGRANTRECV_ERR_CORRUPT, PEPGRANTRECV_ERR_FILE_SIZE, PEPGRANTRECV_ERR_IO,
    PEPGRANTRECV_ERR_PARSE, PEPGRANTRECV_ERR_PATH_TRAVERSAL, PEPGRANTRECV_ERR_VALIDATION,
};
pub use audit_chain_ext::{
    AuditCausalLink, AuditProvenance, AuditSignature, ExtendedAuditRow,
    AUDIT_EXT_ERR_BOUNDS, AUDIT_EXT_ERR_HASH, AUDIT_EXT_ERR_SIGNATURE, AUDIT_EXT_ERR_VALIDATION,
    MAX_CAUSAL_LINKS, MAX_EXTENSION_ENTRIES, MAX_EXTENSION_PAYLOAD_BYTES, MAX_SESSION_ID_LEN,
    MAX_TRACE_ID_LEN,
};
pub use sandbox_data_model::{
    EnvironmentPolicy, FilesystemPolicy, IsolationLevel, NetworkIsolationMode,
    ResourceLimits, SandboxComponentStatus, SandboxExecutionRequest, SandboxExecutionResult,
    SandboxExecutionStatus, SandboxProfile, SandboxProfileBuilder, SandboxProfileType, SyscallAction, SyscallPolicy,
    ERR_SANDBOX_BOUNDS_EXCEEDED, ERR_SANDBOX_EMPTY_COMMAND, ERR_SANDBOX_INVALID_LIMIT, ERR_SANDBOX_INVALID_PATH,
    ERR_SANDBOX_POLICY_CONFLICT,
};
pub use sandbox_config::{
    SandboxConfig, DEFAULT_MAX_OUTPUT_CAPTURE_BYTES as CONFIG_DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_MAX_PROFILES, DEFAULT_SANDBOX_CONFIG_PATH, DEFAULT_TIMEOUT_SECONDS,
    MAX_CONFIG_FILE_BYTES as SANDBOX_MAX_CONFIG_FILE_BYTES, MAX_MAX_PROFILES,
    MAX_OUTPUT_CAPTURE_BYTES_HARD_CAP, MAX_TIMEOUT_SECONDS, MIN_MAX_PROFILES,
    MIN_OUTPUT_CAPTURE_BYTES, MIN_TIMEOUT_SECONDS, SANDBOXCONF_ERR_BOUNDS,
    SANDBOXCONF_ERR_IO, SANDBOXCONF_ERR_PARSE, SANDBOXCONF_ERR_VALIDATION,
};
pub use sandbox_service::{
    HostSandboxCapabilities, SandboxService, DEFAULT_MAX_OUTPUT_CAPTURE_BYTES,
    ERR_SANDBOX_CANNOT_DELETE_DEFAULT, ERR_SANDBOX_CAPACITY_EXCEEDED, ERR_SANDBOX_EXEC_FAILED,
    ERR_SANDBOX_PEP_UNAUTHORIZED, ERR_SANDBOX_PROFILE_EXISTS, ERR_SANDBOX_PROFILE_NOT_FOUND,
    MAX_PROFILES_IN_SERVICE,
};
pub use sandbox_policy::{
    SandboxPolicyMode, SandboxPolicyVerdict, SandboxSecurityPolicy,
    MAX_PEP_MANDATED_PROFILES, MAX_PROHIBITED_COMMANDS, MAX_PROHIBITED_ENV_VARS,
    MAX_SANDBOX_POLICY_VERSION_LEN, MAX_SANDBOX_SECURITY_POLICY_BYTES,
    SANDBOXPOL_ERR_DENIED, SANDBOXPOL_ERR_IO, SANDBOXPOL_ERR_PARSE, SANDBOXPOL_ERR_VALIDATION,
};
pub use sandbox_observability::{
    SandboxObservabilityReport, MAX_OUTCOME_DISTRIBUTION_ENTRIES as SANDBOX_MAX_OUTCOME_DISTRIBUTION_ENTRIES,
    MAX_TELEMETRY_TEXT_LEN as SANDBOX_MAX_TELEMETRY_TEXT_LEN, SANDBOXOBS_ERR_QUERY,
    SANDBOXOBS_ERR_VALIDATION, sanitize_telemetry_text as sanitize_sandbox_telemetry_text,
};
pub use sandbox_doc::{
    SandboxDocCategory, SandboxDocIndex, SandboxDocSearchResult, SandboxDocSection,
    SandboxDocTopic, SandboxDocTopicSummary, MAX_DOC_QUERY_LEN as SANDBOX_MAX_DOC_QUERY_LEN,
    SANDBOXDOC_ERR_EMPTY_QUERY, SANDBOXDOC_ERR_NOT_FOUND,
};
pub use sandbox_recovery::{
    SandboxRecoveryManager, SandboxRecoveryResult, SandboxRecoveryStrategy,
    SandboxValidationIssue, SandboxValidationReport, SandboxValidationSeverity,
    MAX_PROFILE_FILE_BYTES, SANDBOXRECV_ERR_CORRUPT, SANDBOXRECV_ERR_IO,
    SANDBOXRECV_ERR_LIMIT_BOUNDS, SANDBOXRECV_ERR_MISSING_FACTORY,
    SANDBOXRECV_ERR_TRAVERSAL,
};
pub use privilege_data_model::{
    PrivilegeCapability, PrivilegeContext, PrivilegeEscalationVerdict, PrivilegeLevel,
    PrivilegeTransitionRequest, MAX_ACTOR_ID_LEN as PRIVESC_MAX_ACTOR_ID_LEN,
    MAX_CAPABILITIES_COUNT as PRIVESC_MAX_CAPABILITIES_COUNT,
    MAX_GRANT_ID_LEN as PRIVESC_MAX_GRANT_ID_LEN, PRIVESC_ERR_CAPABILITY_OVERFLOW,
    PRIVESC_ERR_CAPABILITY_UNAUTHORIZED, PRIVESC_ERR_INVALID_ACTOR,
    PRIVESC_ERR_INVALID_GRANT, PRIVESC_ERR_KERNEL_TIER_IMMUTABLE,
    PRIVESC_ERR_UNAUTHORIZED_ELEVATION,
};
pub use privilege_service::{
    PrivilegeService, DEFAULT_MAX_ACTIVE_CONTEXTS as PRIVESC_DEFAULT_MAX_ACTIVE_CONTEXTS,
    MAX_MAX_ACTIVE_CONTEXTS as PRIVESC_MAX_MAX_ACTIVE_CONTEXTS,
    MIN_MAX_ACTIVE_CONTEXTS as PRIVESC_MIN_MAX_ACTIVE_CONTEXTS,
    PRIVESC_ERR_ACTOR_NOT_FOUND, PRIVESC_ERR_CAPACITY_EXCEEDED, PRIVESC_ERR_CONTEXT_EXISTS,
};
pub use privilege_config::{
    PrivilegeConfig, DEFAULT_PRIVILEGE_CONFIG_PATH, DEFAULT_PRIVILEGE_STORE_PATH,
    PRIVESCCONF_ERR_BOUNDS, PRIVESCCONF_ERR_IO, PRIVESCCONF_ERR_PARSE, PRIVESCCONF_ERR_VALIDATION,
};
pub use privilege_policy::{
    PrivilegePolicyMode, PrivilegePolicyVerdict, PrivilegeSecurityPolicy,
    MAX_PRIVILEGE_POLICY_VERSION_LEN, MAX_PRIVILEGE_SECURITY_POLICY_BYTES,
    PRIVESCPOL_ERR_DENIED, PRIVESCPOL_ERR_IO, PRIVESCPOL_ERR_PARSE, PRIVESCPOL_ERR_VALIDATION,
};
pub use privilege_observability::{
    sanitize_telemetry_text as sanitize_privilege_telemetry_text,
    PrivilegeObservabilityReport, MAX_OUTCOME_DISTRIBUTION_ENTRIES as PRIVILEGE_MAX_OUTCOME_DISTRIBUTION_ENTRIES,
    MAX_TELEMETRY_TEXT_LEN as PRIVILEGE_MAX_TELEMETRY_TEXT_LEN, PRIVESCOBS_ERR_VALIDATION,
};
pub use privilege_doc::{
    PrivilegeDocCategory, PrivilegeDocIndex, PrivilegeDocSearchResult, PrivilegeDocSection,
    PrivilegeDocTopic, MAX_PRIVILEGE_DOC_QUERY_LEN, MAX_PRIVILEGE_DOC_SEARCH_RESULTS,
    MAX_PRIVILEGE_DOC_SNIPPET_LEN, PRIVDOC_ERR_NOT_FOUND, PRIVDOC_ERR_QUERY_BOUNDS,
};
pub use privilege_recovery::{
    PrivilegeIssueCode, PrivilegeIssueSeverity, PrivilegeRecoveryManager,
    PrivilegeRecoveryResult, PrivilegeRepairAction, PrivilegeValidationIssue,
    PrivilegeValidationReport, MAX_PRIVILEGE_STORE_SIZE, PRIVRECV_ERR_FILE_SIZE,
    PRIVRECV_ERR_IO, PRIVRECV_ERR_PARSE, PRIVRECV_ERR_PATH_TRAVERSAL, PRIVRECV_ERR_VALIDATION,
};
pub use secret_data_model::{
    SecretEntry, SecretKind, SecretMetadata, SecretScope, SecretState, SecretValue,
    MAX_SECRET_ID_LEN, MAX_SECRET_LABELS_COUNT, MAX_SECRET_LABEL_KEY_LEN,
    MAX_SECRET_LABEL_VAL_LEN, MAX_SECRET_NAME_LEN, MAX_SECRET_PAYLOAD_SIZE,
    SECDATA_ERR_EMPTY_ID, SECDATA_ERR_EMPTY_NAME, SECDATA_ERR_INVALID_ID,
    SECDATA_ERR_INVALID_SCOPE, SECDATA_ERR_INVALID_STATE, SECDATA_ERR_LABEL_BOUNDS,
    SECDATA_ERR_NAME_TOO_LONG, SECDATA_ERR_PAYLOAD_TOO_LARGE, SECDATA_ERR_STATE_TRANSITION,
};
pub use secret_service::{
    SecretService, StoredSecretRecord, VaultPayload, hex_decode, hex_encode,
    DEFAULT_SECRETS_VAULT_PATH, MAX_SECRETS_STORE_SIZE, MAX_SECRETS_VAULT_CAPACITY,
    SECSVC_ERR_ACCESS_DENIED, SECSVC_ERR_CAPACITY_EXCEEDED, SECSVC_ERR_FILE_SIZE,
    SECSVC_ERR_INACCESSIBLE, SECSVC_ERR_IO, SECSVC_ERR_NOT_FOUND, SECSVC_ERR_PARSE,
    SECSVC_ERR_PATH_TRAVERSAL,
};
pub use secret_config::{
    SecretConfig, DEFAULT_SECRETS_CONFIG_PATH, DEFAULT_SECRETS_STORE_PATH,
    DEFAULT_MAX_SECRETS_CAPACITY, MIN_MAX_SECRETS_CAPACITY, MAX_MAX_SECRETS_CAPACITY,
    DEFAULT_MAX_PAYLOAD_BYTES, MIN_MAX_PAYLOAD_BYTES, MAX_MAX_PAYLOAD_BYTES,
    DEFAULT_MAX_STORE_FILE_BYTES, MIN_MAX_STORE_FILE_BYTES, MAX_MAX_STORE_FILE_BYTES,
    MAX_CONFIG_FILE_BYTES, SECCONF_ERR_BOUNDS, SECCONF_ERR_IO, SECCONF_ERR_PARSE,
    SECCONF_ERR_VALIDATION,
};
pub use secret_policy::{
    SecretPolicyMode, SecretPolicyVerdict, SecretSecurityPolicy,
    SECPOL_ERR_DENIED, SECPOL_ERR_EXPOSE_REQUIRED, SECPOL_ERR_GLOBAL_DISALLOWED,
    SECPOL_ERR_IO, SECPOL_ERR_KIND_PROHIBITED, SECPOL_ERR_PARSE,
    SECPOL_ERR_PAYLOAD_TOO_LARGE, SECPOL_ERR_VALIDATION,
    MAX_SECRET_POLICY_VERSION_LEN, MAX_SECRET_SECURITY_POLICY_BYTES,
};










