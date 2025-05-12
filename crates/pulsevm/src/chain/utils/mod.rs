use super::error::ChainError;

pub fn assert_or_err(condition: bool, error: ChainError) -> Result<(), ChainError> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}
