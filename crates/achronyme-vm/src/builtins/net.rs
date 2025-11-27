//! Network/HTTP built-in functions

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::value::VmFuture;
use reqwest::Url;
use std::collections::HashMap;

/// http_get(url) -> Future<String>
/// Performs an HTTP GET request and returns the body as a string.
pub fn vm_http_get(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "http_get() expects 1 argument, got {}",
            args.len()
        )));
    }

    let url = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "http_get".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let future = async move {
        match reqwest::get(&url).await {
            Ok(response) => {
                if response.status().is_success() {
                    match response.text().await {
                        Ok(text) => Value::String(text),
                        Err(e) => Value::Error {
                            message: format!("Failed to read response body: {}", e),
                            kind: Some("NetworkError".into()),
                            source: None,
                        },
                    }
                } else {
                    Value::Error {
                        message: format!("HTTP request failed with status: {}", response.status()),
                        kind: Some("HttpError".into()),
                        source: None,
                    }
                }
            }
            Err(e) => Value::Error {
                message: format!("Network request failed: {}", e),
                kind: Some("NetworkError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

/// http_post(url, body, headers?) -> Future<String>
/// Performs an HTTP POST request.
pub fn vm_http_post(_vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "http_post() expects 2 or 3 arguments, got {}",
            args.len()
        )));
    }

    let url = match &args[0] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "http_post".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            })
        }
    };

    let url_parsed = match Url::parse(&url) {
        Ok(u) => u,
        Err(e) => return Err(VmError::Runtime(format!("Invalid URL format: {}", e))),
    };

    let body = match &args[1] {
        Value::String(s) => s.to_string(),
        _ => {
            return Err(VmError::TypeError {
                operation: "http_post".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let headers = if args.len() > 2 {
        match &args[2] {
            Value::Record(r) => {
                let r = r.read();
                let mut h = HashMap::new();
                for (k, v) in r.iter() {
                    if let Value::String(s) = v {
                        h.insert(k.clone(), s.clone());
                    }
                }
                Some(h)
            }
            Value::Null => None,
            _ => {
                return Err(VmError::TypeError {
                    operation: "http_post".to_string(),
                    expected: "Record".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        None
    };

    let future = async move {
        let client = reqwest::Client::new();
        let mut request = client.post(url_parsed).body(body);

        if let Some(h_map) = headers {
            for (k, v) in h_map {
                request = request.header(&k, &v);
            }
        } else {
            // Default to JSON if not specified? No, let user specify.
            // But we can default content-type to application/json if it looks like json?
            // Ideally user sets it.
            request = request.header("Content-Type", "application/json");
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                match response.text().await {
                    Ok(text) => {
                        if status.is_success() {
                            Value::String(text)
                        } else {
                            // Devolvemos el cuerpo del error en el mensaje
                            // para que tu script .soc pueda imprimirlo

                            Value::Error {
                                message: format!("HTTP {} - Body: {}", status, text),
                                kind: Some("HttpError".into()),
                                source: None,
                            }
                        }
                    }
                    Err(e) => Value::Error {
                        message: format!("Failed to read response body: {}", e),
                        kind: Some("NetworkError".into()),
                        source: None,
                    },
                }
            }
            Err(e) => Value::Error {
                message: format!("Network request failed: {}", e),
                kind: Some("NetworkError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}
