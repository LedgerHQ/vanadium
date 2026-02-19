use common::{BigIntOperator, Command, Curve, HashId};
use sdk::{
    comm::{send_message, SendMessageError},
    vanadium_client::{VAppExecutionError, VAppTransport},
};

#[derive(Debug)]
pub enum SadikClientError {
    VAppExecutionError(VAppExecutionError),
    GenericError(&'static str),
}

impl From<VAppExecutionError> for SadikClientError {
    fn from(e: VAppExecutionError) -> Self {
        Self::VAppExecutionError(e)
    }
}

impl From<&'static str> for SadikClientError {
    fn from(e: &'static str) -> Self {
        Self::GenericError(e)
    }
}

impl std::fmt::Display for SadikClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SadikClientError::VAppExecutionError(e) => write!(f, "VAppExecutionError: {}", e),
            SadikClientError::GenericError(e) => write!(f, "GenericError: {}", e),
        }
    }
}

impl std::error::Error for SadikClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SadikClientError::VAppExecutionError(e) => Some(e),
            SadikClientError::GenericError(_) => None,
        }
    }
}

pub struct SadikClient {
    vapp_transport: Box<dyn VAppTransport + Send>,
}

impl SadikClient {
    pub fn new(vapp_transport: Box<dyn VAppTransport + Send>) -> Self {
        Self { vapp_transport }
    }

    pub async fn hash(
        &mut self,
        hash_id: HashId,
        data: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::Hash {
            hash_id: hash_id.into(),
            msg: data.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn bignum_operation(
        &mut self,
        operator: BigIntOperator,
        a: &[u8],
        b: &[u8],
        modular: bool,
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::BigIntOperation {
            operator,
            a: a.to_vec(),
            b: b.to_vec(),
            modular,
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn bignum_modinv(&mut self, a: &[u8]) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::BigIntOperation {
            operator: BigIntOperator::Inv,
            a: a.to_vec(),
            b: Vec::new(),
            modular: true,
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn derive_hd_node(
        &mut self,
        curve: Curve,
        path: Vec<u32>,
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::DeriveHdNode { curve, path };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn get_master_fingerprint(
        &mut self,
        curve: Curve,
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::GetMasterFingerprint { curve };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }
    pub async fn get_slip21_key(&mut self, labels: &[&[u8]]) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::DeriveSlip21Key {
            labels: labels.iter().map(|s| s.to_vec()).collect(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn ecpoint_add(
        &mut self,
        curve: Curve,
        p: &[u8],
        q: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::ECPointOperation {
            curve,
            operation: common::ECPointOperation::Add(p.to_vec(), q.to_vec()),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn ecpoint_scalarmult(
        &mut self,
        curve: Curve,
        p: &[u8],
        k: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::ECPointOperation {
            curve,
            operation: common::ECPointOperation::ScalarMult(p.to_vec(), k.to_vec()),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn ecdsa_sign(
        &mut self,
        curve: Curve,
        privkey: &[u8],
        msg_hash: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::EcdsaSign {
            curve,
            privkey: privkey.to_vec(),
            msg_hash: msg_hash.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn ecdsa_verify(
        &mut self,
        curve: Curve,
        pubkey: &[u8],
        msg_hash: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::EcdsaVerify {
            curve,
            pubkey: pubkey.to_vec(),
            msg_hash: msg_hash.to_vec(),
            signature: signature.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn schnorr_sign(
        &mut self,
        curve: Curve,
        privkey: &[u8],
        msg: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::SchnorrSign {
            curve,
            privkey: privkey.to_vec(),
            msg: msg.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn schnorr_verify(
        &mut self,
        curve: Curve,
        pubkey: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::SchnorrVerify {
            curve,
            pubkey: pubkey.to_vec(),
            msg: msg.to_vec(),
            signature: signature.to_vec(),
        };

        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn sleep(&mut self, n_ticks: u32) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::Sleep { n_ticks };
        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn write_storage(
        &mut self,
        slot: u32,
        data: &[u8],
    ) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::WriteStorage {
            slot,
            data: data.to_vec(),
        };
        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn read_storage(&mut self, slot: u32) -> Result<Vec<u8>, SadikClientError> {
        let cmd = Command::ReadStorage { slot };
        let msg = postcard::to_allocvec(&cmd).expect("Serialization failed");
        Ok(send_message(&mut self.vapp_transport, &msg)
            .await
            .expect("Error sending message"))
    }

    pub async fn exit(&mut self) -> Result<i32, &'static str> {
        match send_message(&mut self.vapp_transport, &[]).await {
            Ok(_) => Err("Exit message shouldn't return!"),
            Err(SendMessageError::VAppExecutionError(VAppExecutionError::AppExited(code))) => {
                Ok(code)
            }
            Err(_) => Err("Unexpected error"),
        }
    }
}
