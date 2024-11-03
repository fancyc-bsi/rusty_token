
// src/types/claims.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}