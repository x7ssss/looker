use thiserror::Error;

#[derive(Error, Debug)]
pub enum GeoError {
    #[error("MaxMind DB error: {0}")]
    Db(#[from] maxminddb::MaxMindDbError),

    #[error("I/O error reading database: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database file not found: {0}")]
    NotFound(String),
}
