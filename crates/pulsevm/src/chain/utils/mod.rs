use super::error::ChainError;

pub fn pulse_assert(condition: bool, error: ChainError) -> Result<(), ChainError> {
    if condition {
        Ok(())
    } else {
        return Err(error);
    }
}
