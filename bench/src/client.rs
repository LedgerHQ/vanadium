use sdk::vanadium_client::{VAppExecutionError, VAppTransport};

#[derive(Debug)]
pub enum BenchClientError {
    VAppExecutionError(VAppExecutionError),
    VAppDidNotExit,
    GenericError(&'static str),
}

impl From<VAppExecutionError> for BenchClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<&'static str> for BenchClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for BenchClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            BenchClientError::VAppDidNotExit => write!(f, "VAppDidNotExit"),
            BenchClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for BenchClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BenchClientError::VAppExecutionError(e) => Some(e),
            BenchClientError::GenericError(_) => None,
            BenchClientError::VAppDidNotExit => None,
        }
    }
}

// This is the client for all the benchmark test V-Apps.
// Each V-App expects a single message containing a big-endiang u64 number
// which is the number of repetitions to run.
// The V-App will perform the computation for the given number of repetitions,
// then immediately exit.
pub struct BenchClient {
    app_transport: Box<dyn VAppTransport + Send + Sync>,
}

impl BenchClient {
    pub fn new(app_transport: Box<dyn VAppTransport + Send + Sync>) -> Self {
        Self { app_transport }
    }

    pub async fn run_and_exit(&mut self, repetitions: u64) -> Result<(), BenchClientError> {
        match self
            .app_transport
            .send_message(&repetitions.to_be_bytes())
            .await
        {
            Ok(_) => Err(BenchClientError::VAppDidNotExit),
            Err(e) => match e {
                VAppExecutionError::AppExited(_) => Ok(()),
                _ => Err(BenchClientError::VAppExecutionError(e)),
            },
        }
    }
}
