#![cfg_attr(
    feature = "lunahsm",
    no_std,
    feature(alloc_error_handler, fmt_internals, lang_items),
    allow(internal_features)
)]
extern crate alloc;
use alloc::format;

mod api;
#[cfg(feature = "lunahsm")]
mod lunahsm_handlers;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use api::*;
use core::{ptr, slice};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const FM_MAX_BUFFER_SIZE: usize = 1024 * 64;

pub fn handler(in_buf: *mut u8, in_len: u32, out_buf: *mut u8, out_len: &mut u32) -> u32 {
    let serialized_response = if in_len as usize > FM_MAX_BUFFER_SIZE {
        get_error_response(&format!(
            "HSM buffer size limit is {} but serialized request size is {}",
            FM_MAX_BUFFER_SIZE, in_len
        ))
    } else {
        let in_buf = unsafe { slice::from_raw_parts(in_buf, in_len as usize) };
        let serialized_request = in_buf.to_vec();

        let serialized_response = dispatcher(serialized_request);

        if serialized_response.len() > FM_MAX_BUFFER_SIZE {
            get_error_response(&format!(
                "HSM buffer size limit is {} but serialized response size is {}",
                FM_MAX_BUFFER_SIZE,
                serialized_response.len()
            ))
        } else {
            serialized_response
        }
    };

    unsafe {
        ptr::copy(
            serialized_response.as_ptr(),
            out_buf,
            serialized_response.len(),
        );
    }
    *out_len = serialized_response.len() as u32;

    0
}

fn get_error_response(message: &str) -> Vec<u8> {
    let error_response = json!({ "error": message });
    serde_json::to_vec(&error_response).unwrap()
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

pub fn dispatcher(data: Vec<u8>) -> Vec<u8> {
    // Deserialize the JSON data into a Value
    let mut request: Value = match serde_json::from_slice(&data) {
        Ok(req) => req,
        Err(e) => {
            return get_error_response(&format!("Failed to deserialize request: {}", e));
        }
    };

    // Extract function_name from the JSON
    let function_name = match request["function_name"].as_str() {
        Some(name) => name.to_string(),
        None => {
            return get_error_response("Missing function_name");
        }
    };

    // Remove function_name from the request
    request.as_object_mut().unwrap().remove("function_name");

    // Handle the request based on the function_name
    let response = match function_name.as_str() {
        "AddVault" => {
            let label = get_or_error!(request, "label", String);
            let id = get_or_error!(request, "id", u64);
            add_vault(label, id)
        }
        "RemoveVault" => {
            let label = get_or_error!(request, "label", String);
            let reasons = get_or_error!(request, "reasons", Vec<Reason>);
            let code = get_or_error!(request, "code", u64);
            remove_vault(label, reasons, code)
        }
        _ => Err("Unsupported function".to_string()),
    };

    // Convert the response to JSON and serialize it
    match response {
        Ok(msg) => {
            let response_json = json!({ "message": msg });
            serde_json::to_vec(&response_json).unwrap()
        }
        Err(e) => get_error_response(&e),
    }
}
