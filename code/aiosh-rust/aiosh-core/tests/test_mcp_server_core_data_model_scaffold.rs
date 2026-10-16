//! Scaffold test for MCP Server Core data model (T-03065).

use aiosh_core::mcp_server_core_data_model::*;

#[test]
fn test_mcp_data_model_scaffold_types() {
    let req = McpJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: McpRequestId::Number(42),
        method: "tools/list".to_string(),
        params: None,
    };
    assert_eq!(req.validate_scaffold(), Ok(()));

    let caps = McpServerCapabilities::default();
    assert!(caps.tools);
    assert!(caps.logging);

    let err = McpJsonRpcError {
        code: ERR_METHOD_NOT_FOUND,
        message: "method not found".to_string(),
        data: None,
    };
    assert_eq!(err.code, -32601);
}
