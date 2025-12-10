use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChainbaseError {
    #[error("item not found")]
    NotFound,
    #[error("item already exists")]
    AlreadyExists,
    #[error("invalid data provided")]
    InvalidData,
    #[error("error reading data")]
    ReadError,
    #[error("internal error: {0}")]
    InternalError(String),
}

impl From<ChainbaseError> for ErrorObjectOwned {
    fn from(e: ChainbaseError) -> Self {
        match e {
            ChainbaseError::NotFound => ErrorObjectOwned::owned::<&str>(404, "not_found", None),
            ChainbaseError::AlreadyExists => {
                ErrorObjectOwned::owned::<&str>(409, "already_exists", None)
            }
            ChainbaseError::InvalidData => {
                ErrorObjectOwned::owned::<&str>(400, "invalid_data", None)
            }
            ChainbaseError::ReadError => ErrorObjectOwned::owned::<&str>(500, "read_error", None),
            ChainbaseError::InternalError(msg) => {
                ErrorObjectOwned::owned::<&str>(500, "internal_error", Some(&msg))
            }
        }
    }
}
