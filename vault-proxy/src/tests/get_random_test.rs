use super::*;

#[test]
fn get_random_test() {
    let rocket = rocket();
    let client = Client::tracked(rocket).expect("No valid rocket instance");
    let response = client
        .post("/get_random")
        .header(ContentType::JSON)
        .body(r#"{"size": 10}"#)
        .dispatch();

    let response_status = response.status();
    let response_body = response.into_string().expect("No response body");
    let response_json: Value =
        serde_json::from_str(&response_body).expect("Failed to parse response body as JSON");

    assert_eq!(
        response_status,
        Status::Ok,
        "{}",
        response_json["reason"]
            .as_str()
            .unwrap_or("No reason field")
    );
}
