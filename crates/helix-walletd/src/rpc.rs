//! The JSON-RPC envelope as Bitcoin Core speaks it: `{"method", "params", "id"}` in, `{"result",
//! "error", "id"}` out, positional or named parameters, batches as arrays, and Bitcoin Core's error
//! codes — so an exchange's existing client talks to this service unchanged.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// Bitcoin Core's error codes, the ones this service answers with.
pub mod code {
    pub const MISC: i32 = -1;
    pub const TYPE: i32 = -3;
    pub const WALLET: i32 = -4;
    pub const INVALID_ADDRESS: i32 = -5;
    pub const INSUFFICIENT_FUNDS: i32 = -6;
    pub const INVALID_PARAMETER: i32 = -8;
    pub const NOT_CONNECTED: i32 = -9;
    pub const IN_INITIAL_DOWNLOAD: i32 = -10;
    pub const KEYPOOL_RAN_OUT: i32 = -12;
    pub const UNLOCK_NEEDED: i32 = -13;
    pub const PASSPHRASE_INCORRECT: i32 = -14;
    pub const WRONG_ENC_STATE: i32 = -15;
    pub const VERIFY_REJECTED: i32 = -26;
    pub const IN_WARMUP: i32 = -28;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const PARSE_ERROR: i32 = -32700;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        RpcError { code, message: message.into() }
    }
}

pub type RpcResult = Result<Box<RawValue>, RpcError>;

/// Serialize a result for the envelope. Never through `serde_json::Value`: amounts are raw
/// literals (`crate::amount::Hlx`) and a `Value` would read them back through a double.
pub fn result<T: Serialize>(value: &T) -> RpcResult {
    let text = serde_json::to_string(value).map_err(|e| RpcError::new(code::MISC, e.to_string()))?;
    RawValue::from_string(text).map_err(|e| RpcError::new(code::MISC, e.to_string()))
}

/// A call's parameters, positional (`[..]`) or named (`{..}`).
pub enum Params {
    Positional(Vec<Box<RawValue>>),
    Named(Vec<(String, Box<RawValue>)>),
}

impl Params {
    pub fn parse(raw: Option<&RawValue>) -> Result<Self, RpcError> {
        let Some(raw) = raw else { return Ok(Params::Positional(Vec::new())) };
        let text = raw.get().trim();
        if text == "null" {
            return Ok(Params::Positional(Vec::new()));
        }
        if text.starts_with('[') {
            let list: Vec<Box<RawValue>> = serde_json::from_str(text)
                .map_err(|e| RpcError::new(code::INVALID_REQUEST, format!("params: {e}")))?;
            return Ok(Params::Positional(list));
        }
        if text.starts_with('{') {
            // Each value raw, so amounts keep their digits.
            let named: std::collections::BTreeMap<String, Box<RawValue>> = serde_json::from_str(text)
                .map_err(|e| RpcError::new(code::INVALID_REQUEST, format!("params: {e}")))?;
            return Ok(Params::Named(named.into_iter().collect()));
        }
        Err(RpcError::new(code::INVALID_REQUEST, "params must be an array or an object"))
    }

    /// The parameter at `index`, or named `name`. `null` counts as absent, as in Bitcoin Core.
    pub fn get(&self, index: usize, name: &str) -> Option<&RawValue> {
        let found = match self {
            Params::Positional(list) => list.get(index).map(|b| b.as_ref()),
            Params::Named(map) => map.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_ref()),
        };
        found.filter(|v| v.get().trim() != "null")
    }

    pub fn string(&self, index: usize, name: &str) -> Result<Option<String>, RpcError> {
        self.get(index, name)
            .map(|raw| {
                serde_json::from_str::<String>(raw.get())
                    .map_err(|_| RpcError::new(code::TYPE, format!("{name} must be a string")))
            })
            .transpose()
    }

    pub fn required_string(&self, index: usize, name: &str) -> Result<String, RpcError> {
        self.string(index, name)?
            .ok_or_else(|| RpcError::new(code::INVALID_PARAMETER, format!("{name} is required")))
    }

    pub fn u64(&self, index: usize, name: &str) -> Result<Option<u64>, RpcError> {
        self.get(index, name)
            .map(|raw| {
                serde_json::from_str::<u64>(raw.get()).map_err(|_| {
                    RpcError::new(code::TYPE, format!("{name} must be a non-negative integer"))
                })
            })
            .transpose()
    }

    pub fn bool(&self, index: usize, name: &str) -> Result<Option<bool>, RpcError> {
        self.get(index, name)
            .map(|raw| {
                serde_json::from_str::<bool>(raw.get())
                    .map_err(|_| RpcError::new(code::TYPE, format!("{name} must be true or false")))
            })
            .transpose()
    }
}

#[derive(Deserialize)]
pub struct Request<'a> {
    #[serde(borrow, default)]
    pub id: Option<&'a RawValue>,
    pub method: String,
    #[serde(borrow, default)]
    pub params: Option<&'a RawValue>,
}

/// One answer, written by hand so `result` and `id` stay raw.
pub fn envelope(id: Option<&RawValue>, answer: &RpcResult) -> String {
    let id = id.map(|i| i.get()).unwrap_or("null");
    match answer {
        Ok(result) => format!(r#"{{"result":{},"error":null,"id":{id}}}"#, result.get()),
        Err(error) => format!(
            r#"{{"result":null,"error":{},"id":{id}}}"#,
            serde_json::to_string(error).expect("an error serializes")
        ),
    }
}

/// The HTTP status Bitcoin Core sends with a single answer: 200 with a result, 404 for an unknown
/// method, 400 for a request it could not read, 500 for every other error. (Batches are always
/// 200.) Clients read the body either way; some check the status first.
pub fn status_of(answer: &RpcResult) -> u16 {
    match answer {
        Ok(_) => 200,
        Err(e) if e.code == code::METHOD_NOT_FOUND => 404,
        Err(e) if e.code == code::INVALID_REQUEST || e.code == code::PARSE_ERROR => 400,
        Err(_) => 500,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(text: &str) -> Params {
        let raw = RawValue::from_string(text.to_string()).unwrap();
        Params::parse(Some(&raw)).unwrap()
    }

    #[test]
    fn positional_and_named_parameters_read_the_same() {
        for p in [params(r#"["hlxabc", 1.5]"#), params(r#"{"address": "hlxabc", "amount": 1.5}"#)] {
            assert_eq!(p.required_string(0, "address").unwrap(), "hlxabc");
            // Raw, so the digits survive.
            assert_eq!(p.get(1, "amount").unwrap().get(), "1.5");
        }
        let p = params(r#"["x", null]"#);
        assert!(p.get(1, "amount").is_none(), "null is absent");
        assert!(params("null").get(0, "a").is_none());
    }

    #[test]
    fn the_envelope_keeps_result_and_id_raw() {
        let id = RawValue::from_string("\"42\"".into()).unwrap();
        let answer = result(&crate::amount::Hlx::exact(1)).unwrap();
        assert_eq!(
            envelope(Some(&id), &Ok(answer)),
            r#"{"result":0.000000001,"error":null,"id":"42"}"#
        );
        let err = Err(RpcError::new(code::METHOD_NOT_FOUND, "Method not found"));
        assert_eq!(
            envelope(None, &err),
            r#"{"result":null,"error":{"code":-32601,"message":"Method not found"},"id":null}"#
        );
        assert_eq!(status_of(&err), 404);
    }

    #[test]
    fn a_wrongly_typed_parameter_says_which_one() {
        let p = params(r#"[5]"#);
        assert_eq!(p.string(0, "address").unwrap_err().code, code::TYPE);
        let p = params(r#"["a", -1]"#);
        assert_eq!(p.u64(1, "count").unwrap_err().code, code::TYPE);
    }
}
