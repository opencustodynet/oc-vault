use serde_json::{json, Value};

macro_rules! get_or_error {
    ($request:expr, $field:expr, $type:ty) => {
        match $request.get($field) {
            Some(value) => match serde_json::from_value::<$type>(value.clone()) {
                Ok(valid_value) => valid_value,
                Err(_) => return serde_json::to_vec(&serde_json::json!({ "error": format!("Invalid {}", $field) })).unwrap(),
            },
            None => return serde_json::to_vec(&serde_json::json!({ "error": format!("Missing {}", $field) })).unwrap(),
        }
    };
    ($request:expr, $field:expr, Vec<$type:ty>) => {
        match $request.get($field) {
            Some(value) => value.as_array()
                .unwrap_or_else(|| return serde_json::to_vec(&serde_json::json!({ "error": format!("{} is not an array", $field) })).unwrap())
                .iter()
                .map(|v| serde_json::from_value::<$type>(v.clone()).unwrap_or_else(|_| return serde_json::to_vec(&serde_json::json!({ "error": format!("Invalid {}", $field) })).unwrap()))
                .collect::<Vec<$type>>(),
            None => return serde_json::to_vec(&serde_json::json!({ "error": format!("Missing {}", $field) })).unwrap(),
        }
    };
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Reason {
    name: String,
    code: u64,
}

pub fn send_to_hsm(data: Vec<u8>) -> Vec<u8> {
    // Deserialize the JSON data into a Value
    let mut request: Value = match serde_json::from_slice(&data) {
        Ok(req) => req,
        Err(e) => {
            let error_response =
                json!({ "error": format!("Failed to deserialize request: {}", e) });
            return serde_json::to_vec(&error_response).unwrap();
        }
    };

    // Extract function_name from the JSON
    let function_name = match request["function_name"].as_str() {
        Some(name) => name.to_string(),
        None => {
            let error_response = json!({ "error": "Missing function_name".to_string() });
            return serde_json::to_vec(&error_response).unwrap();
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
        Err(e) => {
            let error_response = json!({ "error": e });
            serde_json::to_vec(&error_response).unwrap()
        }
    }
}

fn add_vault(label: String, id: u64) -> Result<String, String> {
    let message = format!("Added vault '{}' with ID {}", label, id);
    Ok(message)
}

fn remove_vault(label: String, _reasons: Vec<Reason>, _code: u64) -> Result<String, String> {
    let message = format!("Removed vault '{}'", label);
    Ok(message)
}
