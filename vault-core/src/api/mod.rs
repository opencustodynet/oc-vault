use super::*;
use core::ffi::c_ulong;

mod get_random;
use get_random::get_random;
mod utils;

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

pub fn dispatcher(serialized_request: Vec<u8>) -> Vec<u8> {
    // Extract slot_id from the serialized_request
    let mut serialized_request = serialized_request;
    let slot_id = match serialized_request.get(0..8) {
        Some(slot_id_bytes) => u64::from_be_bytes(match slot_id_bytes.try_into() {
            Ok(slot_id_bytes) => slot_id_bytes,
            Err(_) => {
                return get_error_response("Invalid slot_id");
            }
        }),
        None => {
            return get_error_response("Missing slot_id");
        }
    };

    #[cfg(feature = "lunahsm")]
    let slot_id: p11::CK_SLOT_ID = match slot_id.try_into() {
        Ok(slot_id) => slot_id,
        Err(_) => {
            return get_error_response("Invalid slot_id");
        }
    };

    // Remove the slot_id from serialized_request
    serialized_request.drain(0..8);

    let mut session: p11::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        p11::C_OpenSession(
            slot_id,
            p11::CKF_SERIAL_SESSION | p11::CKF_RW_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        )
    };
    if rv != p11::CKR_OK {
        return get_error_response(&format!("C_OpenSession failed with error code: {}", rv));
    }

    // Deserialize the JSON data into a Value
    let mut request: Value = match serde_json::from_slice(&serialized_request) {
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
        "get_random" => {
            let size = get_or_error!(request, "size", u8);
            get_random(session, size)
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
