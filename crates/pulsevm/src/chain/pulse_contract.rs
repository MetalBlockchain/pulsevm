use super::{apply_context::ApplyContext, error::ChainError};

pub fn newaccount(apply_context: &mut ApplyContext) -> Result<(), ChainError> {
    println!("Executing newaccount action");
    Ok(())
}
