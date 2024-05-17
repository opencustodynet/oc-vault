use super::*;

pub fn add_vault(label: String, id: u64) -> Result<String, String> {
    let message = format!("Added vault '{}' with ID {}", label, id);
    Ok(message)
}
