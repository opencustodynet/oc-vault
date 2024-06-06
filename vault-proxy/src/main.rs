#[macro_use]
extern crate rocket;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use serde_json::{json, Value};
use shared::p11;

mod hsm;

#[cfg(test)]
mod tests;

#[post("/<function_name>", format = "json", data = "<request>")]
fn dynamic_handler(
    function_name: String,
    request: Json<Value>,
    hsm_connection: &rocket::State<hsm::HsmConnection>,
) -> Result<String, status::Custom<String>> {
    let mut request = request.into_inner();
    request["function_name"] = json!(function_name);

    let response_json = hsm_connection.send(request);
    // Check if the JSON value is error
    if let Some(status) = response_json.get("status") {
        if status == "error" {
            return Err(status::Custom(
                Status::InternalServerError,
                response_json.to_string(),
            ));
        } else {
            return Ok(response_json.to_string());
        }
    } else {
        Err(status::Custom(
            Status::InternalServerError,
            hsm::get_error_response("no status field in response from HSM".to_string()).to_string(),
        ))
    }
}

#[launch]
fn rocket() -> _ {
    let token_label = "opencustody_slot";
    let token_pin = "12345678";
    let user_type = p11::CKU_USER;

    let hsm_connection;
    let r = hsm::HsmConnection::open(token_label, token_pin, user_type);
    if r.is_err() {
        eprintln!("Error opening HSM connection: {}", r.err().unwrap());
        std::process::exit(1);
    } else {
        hsm_connection = r.unwrap();
    }

    rocket::build()
        .manage(hsm_connection)
        .mount("/", routes![dynamic_handler])
}
