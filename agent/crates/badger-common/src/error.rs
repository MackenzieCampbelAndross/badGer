use thiserror::Error;

#[derive(Error, Debug)]
pub enum BadgerError {
    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Policy invalid or expired: {0}")]
    PolicyInvalid(String),

    #[error("Sandbox isolation error: {0}")]
    Sandbox(String),

    #[error("Sensor failure: {0}")]
    Sensor(String),

    #[error("Detection error: {0}")]
    Detection(String),

    #[error("Containment failed: {0}")]
    Containment(String),

    #[error("Network enforcement error: {0}")]
    Network(String),

    #[error("Audit log error: {0}")]
    Audit(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type BadgerResult<T> = Result<T, BadgerError>;
