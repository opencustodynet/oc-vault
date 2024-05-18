#[macro_use]
extern crate rocket;
use rocket::serde::json::Json;
use serde_json::{json, Value};

mod hsm;

#[post("/<function_name>", format = "json", data = "<request>")]
fn dynamic_handler(
    function_name: String,
    request: Json<Value>,
    hsm_connection: &rocket::State<hsm::HsmConnection>,
) -> String {
    let mut request_with_function_name = request.into_inner();
    request_with_function_name["function_name"] = json!(function_name);

    // Serialize the modified request to JSON
    let serialized_request = match serde_json::to_vec(&request_with_function_name) {
        Ok(data) => data,
        Err(e) => return format!("Error serializing request: {}", e),
    };

    match hsm_connection.send(serialized_request) {
        Ok(serialized_response_str) => serialized_response_str,
        Err(e) => format!("Error sending request to HSM: {}", e),
    }
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
