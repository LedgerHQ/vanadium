use sdk::{
    comm::{self, send_message, SendMessageError},
    vanadium_client::{VAppExecutionError, VAppTransport},
};

pub struct DemoClient {
    app_transport: Box<dyn VAppTransport + Send>,
}

impl DemoClient {
    pub fn new(app_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { app_transport }
    }

    pub async fn echo(&mut self, data: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        Ok(comm::send_message(&mut self.app_transport, &data).await?)
    }

    pub async fn exit(&mut self) -> Result<i32, &'static str> {
        match send_message(&mut self.app_transport, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!"),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error"),
        }
    }
}
