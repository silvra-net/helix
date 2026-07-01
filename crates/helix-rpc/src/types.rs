use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum RpcError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Invalid parameter: {0}")]
    InvalidParam(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcRequest {
    pub method: String,
    pub params: serde_json::Value,
    pub id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        RpcResponse { id, result: Some(result), error: None }
    }

    pub fn err(id: u64, error: RpcError) -> Self {
        RpcResponse { id, result: None, error: Some(error) }
    }
}
