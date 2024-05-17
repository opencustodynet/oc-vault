#[macro_use]
extern crate rocket;

use rocket::serde::json::Json;
use serde_json::{json, Value};

mod core_mock;

#[post("/<function_name>", format = "json", data = "<request>")]
fn dynamic_handler(function_name: String, request: Json<Value>) -> String {
    let mut modified_request = request.into_inner();
    modified_request["function_name"] = json!(function_name);

    // Serialize the modified request to JSON
    let serialized_request = match serde_json::to_vec(&modified_request) {
        Ok(data) => data,
        Err(e) => return format!("Error serializing request: {}", e),
    };

    // Send this serialized data to the HSM
    let response_bytes = core_mock::send_to_hsm(serialized_request);

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
