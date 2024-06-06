#![cfg_attr(
    feature = "lunahsm",
    no_std,
    feature(alloc_error_handler, fmt_internals, lang_items),
    allow(internal_features)
)]
mod api;
#[cfg(feature = "lunahsm")]
mod lunahsm_handlers;

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
    vec,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::p11;

#[derive(Debug, Serialize, Deserialize)]
struct Reason {
    name: String,
    code: u64,
}

macro_rules! get_or_error {
    ($request:expr, $field:expr, $type:ty) => {
        match $request.get($field) {
            Some(value) => match serde_json::from_value::<$type>(value.clone()) {
                Ok(valid_value) => valid_value,
                Err(_) => return get_error_response(&format!("Invalid {}", $field)),
            },
            None => return get_error_response(&format!("Missing {}", $field)),
        }
    };
    ($request:expr, $field:expr, Vec<$type:ty>) => {
        match $request.get($field) {
            Some(value) => value
                .as_array()
                .unwrap_or_else(|| {
                    return get_error_response(&format!("{} is not an array", $field));
                })
                .iter()
                .map(|v| {
                    serde_json::from_value::<$type>(v.clone()).unwrap_or_else(|_| {
                        return get_error_response(&format!("Invalid {}", $field));
                    })
                })
                .collect::<Vec<$type>>(),
            None => return get_error_response(&format!("Missing {}", $field)),
        }
    };
}

pub fn dispatch(session: p11::CK_SESSION_HANDLE, request_json: Value) -> Value {
    let mut request_json = request_json;

    // Extract function_name from the JSON
    let function_name = match request_json["function_name"].as_str() {
        Some(name) => name.to_string(),
        None => {
            return get_error_response("Missing function_name");
        }
    };

    // Remove function_name from the request
    request_json
        .as_object_mut()
        .unwrap()
        .remove("function_name");

    // Handle the request based on the function_name
    match function_name.as_str() {
        "get_random" => {
            let size = get_or_error!(request_json, "size", u8);
            match api::get_random(session, size) {
                Ok(random) => get_ok_response(json!({ "random": random })),
                Err(e) => get_error_response(&e),
            }
        }
        _ => get_error_response("Unsupported function"),
    }
}

pub fn get_error_response(message: &str) -> Value {
    json!({ "status": "error", "reason": message })
}

fn get_ok_response(response_json: Value) -> Value {
    let mut response_json = response_json;
    response_json
        .as_object_mut()
        .unwrap()
        .insert("status".to_string(), json!("ok"));
    response_json
}
