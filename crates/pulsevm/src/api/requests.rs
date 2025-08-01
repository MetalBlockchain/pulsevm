use serde::Deserialize;

use crate::chain::Name;

#[derive(Deserialize)]
pub struct GetTableRowsParams {
    pub code: Name,
    pub scope: String,
    pub table: Name,
    pub json: bool,
    pub limit: u32,
    pub lower_bound: String,
    pub upper_bound: String,
    pub index_position: String,
    pub reverse: Option<bool>,
    pub show_payer: Option<bool>,
}
