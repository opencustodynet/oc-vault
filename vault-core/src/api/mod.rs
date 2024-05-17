use super::*;

mod add_vault;
pub use add_vault::add_vault;
mod remove_vault;
pub use remove_vault::remove_vault;

#[derive(Debug, Serialize, Deserialize)]
pub struct Reason {
    name: String,
    code: u64,
}
