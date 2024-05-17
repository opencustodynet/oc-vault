use super::*;

mod add_vault;
use add_vault::add_vault;
mod remove_vault;
use remove_vault::remove_vault;

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
