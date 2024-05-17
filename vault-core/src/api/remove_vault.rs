use super::*;

pub fn remove_vault(label: String, _reasons: Vec<Reason>, _code: u64) -> Result<String, String> {
    let message = format!("Removed vault '{}'", label);
    Ok(message)
}
