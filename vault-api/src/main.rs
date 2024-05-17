#[macro_use]
extern crate rocket;
use core::slice;
use rocket::serde::json::Json;
use serde_json::{json, Value};

pub const FM_MAX_BUFFER_SIZE: usize = 1024 * 64;

#[post("/<function_name>", format = "json", data = "<request>")]
fn dynamic_handler(function_name: String, request: Json<Value>) -> String {
    let mut request_with_function_name = request.into_inner();
    request_with_function_name["function_name"] = json!(function_name);

    // Serialize the modified request to JSON
    let mut serialized_request = match serde_json::to_vec(&request_with_function_name) {
        Ok(data) => data,
        Err(e) => return format!("Error serializing request: {}", e),
    };

    // Send this serialized data to the HSM
    if serialized_request.len() > FM_MAX_BUFFER_SIZE {
        return format!(
            "HSM buffer size limit is {} but serialized request size is {}",
            FM_MAX_BUFFER_SIZE,
            serialized_request.len()
        );
    }

    let mut out_buf: [u8; FM_MAX_BUFFER_SIZE] = [0; FM_MAX_BUFFER_SIZE];
    let mut out_len: u32 = 0;

    let _rv = vault_core::handler(
        serialized_request.as_mut_ptr(),
        serialized_request.len() as u32,
        out_buf.as_mut_ptr(),
        &mut out_len,
    );

    if out_len as usize > FM_MAX_BUFFER_SIZE {
        return format!(
            "HSM buffer size limit is {} but serialized response size is {}",
            FM_MAX_BUFFER_SIZE, out_len
        );
    }

    let out_buf_slice = unsafe { slice::from_raw_parts(out_buf.as_ptr(), out_len as usize) };
    let response_bytes = out_buf_slice.to_vec();

    // Deserialize the response bytes to JSON
    match String::from_utf8(response_bytes) {
        Ok(response_str) => response_str,
        Err(_) => "Invalid UTF-8 response".to_string(),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![dynamic_handler])
}
