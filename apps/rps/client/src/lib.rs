use sdk::{
    comm::{send_message, SendMessageError},
    vanadium_client::{VAppExecutionError, VAppTransport},
};
use serde::{Deserialize, Serialize};

pub struct RPSClient {
    app_transport: Box<dyn VAppTransport + Send>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    Commit { c_a: [u8; 32] },
    Reveal { m_a: u8, r_a: [u8; 32] },
}

impl RPSClient {
    pub fn new(app_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { app_transport }
    }

    pub async fn commit(&mut self, c_a: [u8; 32]) -> Result<u8, Box<dyn core::error::Error>> {
        let command = Command::Commit { c_a };
        let msg = postcard::to_allocvec(&command).map_err(|_| "Serialization failed")?;
        let response = send_message(&mut self.app_transport, &msg).await?;
        if response.len() != 1 || response[0] > 2 {
            return Err("Invalid response from the app".into());
        }
        Ok(response[0])
    }

    pub async fn reveal(
        &mut self,
        m_a: u8,
        r_a: [u8; 32],
    ) -> Result<u8, Box<dyn core::error::Error>> {
        let command = Command::Reveal { m_a, r_a };
        let msg = postcard::to_allocvec(&command).map_err(|_| "Serialization failed")?;
        let response = send_message(&mut self.app_transport, &msg).await?;
        if response.len() != 1 || response[0] > 2 {
            return Err("Invalid response from the app".into());
        }
        Ok(response[0])
    }

    pub async fn exit(&mut self) -> Result<i32, Box<dyn core::error::Error>> {
        match send_message(&mut self.app_transport, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!".into()),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error".into()),
        }
    }
}
