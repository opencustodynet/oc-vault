#[macro_use]
extern crate rocket;
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use serde_json::{json, Value};

mod hsm;

#[cfg(test)]
mod tests;

#[post("/<function_name>", format = "json", data = "<request>")]
fn dynamic_handler(
    function_name: String,
    request: Json<Value>,
    hsm_connection: &rocket::State<hsm::HsmConnection>,
) -> Result<String, status::Custom<String>> {
    let mut request_with_function_name = request.into_inner();
    request_with_function_name["function_name"] = json!(function_name);

    // Serialize the modified request to JSON
    let serialized_request = match serde_json::to_vec(&request_with_function_name) {
        Ok(data) => data,
        Err(e) => {
            return Err(get_error_response(format!(
                "Error serializing request: {}",
                e
            )))
        }
    };

    match hsm_connection.send(serialized_request) {
        Err(e) => Err(get_error_response(format!(
            "Error sending request to HSM: {}",
            e
        ))),
        Ok(serialized_response_str) => {
            // Parse the response string into a JSON value
            let response_json: Value = match serde_json::from_str(&serialized_response_str) {
                Ok(json) => json,
                Err(e) => {
                    return Err(get_error_response(format!(
                        "Error parsing response from HSM: {}",
                        e
                    )));
                }
            };

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
                Err(get_error_response(
                    "no status field in response from HSM".to_string(),
                ))
            }
        }
    }
}

fn get_error_response(message: String) -> status::Custom<String> {
    status::Custom(
        Status::InternalServerError,
        json!({ "status": "error", "reason": message }).to_string(),
    )
}

#[launch]
fn rocket() -> _ {
    let token_label = "opencustody_slot";
    let token_pin = "12345678";
    let user_type = hsm::UserType::NU;

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
