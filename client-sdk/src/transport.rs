use std::convert::TryFrom;
use std::error::Error;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;

use crate::transport_native_hid::TransportNativeHID;
use ledger_apdu::APDUAnswer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::apdu::{APDUCommand, StatusWord};

/// Generic trait to abstract the communication layer between the host and a Ledger device.
#[async_trait]
pub trait Transport: Send + Sync {
    type Error: Debug + Send + Sync;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error>;
}

/// Transport with the Ledger device.
pub struct TransportHID(TransportNativeHID);

impl TransportHID {
    pub fn new(t: TransportNativeHID) -> Self {
        Self(t)
    }
}

#[async_trait]
impl Transport for TransportHID {
    type Error = Box<dyn Error + Send + Sync>;
    async fn exchange(&self, cmd: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0
            .exchange(&APDUCommand {
                ins: cmd.ins,
                cla: cmd.cla,
                p1: cmd.p1,
                p2: cmd.p2,
                data: cmd.data.clone(),
            })
            .map(|answer| {
                (
                    StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
                    answer.data().to_vec(),
                )
            })
            .map_err(|e| e.into())
    }
}

/// Transport to communicate with the Ledger Speculos simulator.
pub struct TransportTcp {
    connection: Mutex<TcpStream>,
    total_exchanges: AtomicU64,
    total_sent: AtomicU64,
    total_received: AtomicU64,
}

impl TransportTcp {
    /// Create a new TCP transport connecting to the provided socket address.
    pub async fn new(addr: SocketAddr) -> Result<Self, Box<dyn Error>> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Self {
            connection: Mutex::new(stream),
            total_exchanges: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
        })
    }

    /// Create a new TCP transport using the default Speculos address 127.0.0.1:9999.
    pub async fn new_default() -> Result<Self, Box<dyn Error>> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        Self::new(addr).await
    }

    // Number of exchanges made with this instance. An exchange includes
    // both sending an APDU and receiving a response.
    pub fn total_exchanges(&self) -> u64 {
        self.total_exchanges.load(Ordering::Relaxed)
    }

    // Total bytes sent
    pub fn total_sent(&self) -> u64 {
        self.total_sent.load(Ordering::Relaxed)
    }

    // Total bytes received
    pub fn total_received(&self) -> u64 {
        self.total_received.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl Transport for TransportTcp {
    type Error = Box<dyn Error + Send + Sync>;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        // Count every call to exchange.
        self.total_exchanges.fetch_add(1, Ordering::Relaxed);

        let mut stream = self.connection.lock().await;
        let command_bytes = command.encode();

        let mut req = vec![0u8; command_bytes.len() + 4];
        req[..4].copy_from_slice(&(command_bytes.len() as u32).to_be_bytes());
        req[4..].copy_from_slice(&command_bytes);

        stream.write_all(&req).await?;
        stream.flush().await?;
        self.total_sent
            .fetch_add(req.len() as u64, Ordering::Relaxed);

        let mut buff = [0u8; 4];
        stream.read_exact(&mut buff).await?;
        let len = u32::from_be_bytes(buff);
        self.total_received.fetch_add(4, Ordering::Relaxed); // length header

        let mut resp = vec![0u8; len as usize + 2];
        stream.read_exact(&mut resp).await?;
        self.total_received
            .fetch_add(resp.len() as u64, Ordering::Relaxed);

        let answer = APDUAnswer::from_answer(resp).map_err(|_| "Invalid Answer")?;
        Ok((
            StatusWord::try_from(answer.retcode()).unwrap_or(StatusWord::Unknown),
            answer.data().to_vec(),
        ))
    }
}

/// Wrapper to handle both hid and tcp transport.
pub struct TransportWrapper(Arc<dyn Transport<Error = Box<dyn Error + Send + Sync>> + Sync + Send>);

impl TransportWrapper {
    pub fn new(t: Arc<dyn Transport<Error = Box<dyn Error + Send + Sync>> + Sync + Send>) -> Self {
        Self(t)
    }
}

#[async_trait]
impl Transport for TransportWrapper {
    type Error = Box<dyn Error + Send + Sync>;
    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), Self::Error> {
        self.0.exchange(command).await
    }
}
