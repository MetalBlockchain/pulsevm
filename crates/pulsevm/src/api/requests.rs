use pulsevm_core::name::Name;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GetTableRowsParams {
    pub code: Name,
    pub scope: String,
    pub table: Name,
    pub json: bool,
    pub limit: u32,
    pub lower_bound: String,
    pub upper_bound: String,
    pub key_type: String,
    pub index_position: String,
    pub reverse: Option<bool>,
    pub show_payer: Option<bool>,
}
