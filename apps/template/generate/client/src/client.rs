use crate::Command;

use alloc::vec::Vec;
use sdk::{
    comm::{send_message, SendMessageError},
    vanadium_client::{VAppExecutionError, VAppTransport},
};

pub struct Client {
    vapp_transport: Box<dyn VAppTransport + Send>,
}

impl Client {
    pub fn new(vapp_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { vapp_transport }
    }

    pub async fn sign_message(
        &mut self,
        msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
        let command = Command::SignMessage { msg: msg.to_vec() };
        let msg = postcard::to_allocvec(&command).map_err(|_| "Serialization failed")?;
        let response = send_message(&mut self.vapp_transport, &msg).await?;
        Ok(response)
    }

    pub async fn exit(&mut self) -> Result<i32, Box<dyn core::error::Error>> {
        match send_message(&mut self.vapp_transport, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!".into()),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error".into()),
        }
    }
}
