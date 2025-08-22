#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusWord {
    /// Rejected by user
    Deny = 0x6985,
    /// Incorrect Data
    IncorrectData = 0x6A80,
    /// Not Supported
    NotSupported = 0x6A82,
    /// Wrong P1P2
    WrongP1P2 = 0x6A86,
    /// Wrong DataLength
    WrongDataLength = 0x6A87,
    /// Ins not supported
    InsNotSupported = 0x6D00,
    /// Cla not supported
    ClaNotSupported = 0x6E00,
    /// Bad state
    BadState = 0xB007,
    /// Signature fail
    SignatureFail = 0xB008,
    /// Success
    OK = 0x9000,
    /// The command is interrupted, and requires the client's response
    InterruptedExecution = 0xEEEE,

    /// Unexpected error in the VM while executing the V-App
    VMRuntimeError = 0xB020,

    /// The V-App panicked
    VAppPanic = 0xB021,

    /// Unknown
    Unknown,
}

impl TryFrom<u16> for StatusWord {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x6985 => Ok(StatusWord::Deny),
            0x6A80 => Ok(StatusWord::IncorrectData),
            0x6A82 => Ok(StatusWord::NotSupported),
            0x6A86 => Ok(StatusWord::WrongP1P2),
            0x6A87 => Ok(StatusWord::WrongDataLength),
            0x6D00 => Ok(StatusWord::InsNotSupported),
            0x6E00 => Ok(StatusWord::ClaNotSupported),
            0xB007 => Ok(StatusWord::BadState),
            0xB008 => Ok(StatusWord::SignatureFail),
            0xB020 => Ok(StatusWord::VMRuntimeError),
            0xB021 => Ok(StatusWord::VAppPanic),
            0x9000 => Ok(StatusWord::OK),
            0xEEEE => Ok(StatusWord::InterruptedExecution),
            _ => Err(()),
        }
    }
}

#[derive(Clone)]
pub struct APDUCommand {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl APDUCommand {
    pub fn encode(&self) -> Vec<u8> {
        if self.data.len() <= 255 {
            let mut vec = vec![self.cla, self.ins, self.p1, self.p2, self.data.len() as u8];
            vec.extend(self.data.iter());
            vec
        } else {
            let len_lo = (self.data.len() as u16 & 0xFF) as u8;
            let len_hi = ((self.data.len() as u16 >> 8) & 0xFF) as u8;
            let mut vec = vec![self.cla, self.ins, self.p1, self.p2, 0, len_lo, len_hi];
            vec.extend(self.data.iter());
            vec
        }
    }
}

pub fn apdu_continue(data: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0xE0,
        ins: 0xff,
        p1: 0,
        p2: 0,
        data,
    }
}

pub fn apdu_continue_with_p1(data: Vec<u8>, p1: u8) -> APDUCommand {
    APDUCommand {
        cla: 0xE0,
        ins: 0xff,
        p1,
        p2: 0,
        data,
    }
}

pub fn apdu_register_vapp(serialized_manifest: Vec<u8>) -> APDUCommand {
    APDUCommand {
        cla: 0xE0,
        ins: 2,
        p1: 0,
        p2: 0,
        data: serialized_manifest,
    }
}

pub fn apdu_run_vapp(serialized_manifest: Vec<u8>, app_hmac: [u8; 32]) -> APDUCommand {
    let mut data = serialized_manifest;
    data.extend_from_slice(&app_hmac);
    APDUCommand {
        cla: 0xE0,
        ins: 3,
        p1: 0,
        p2: 0,
        data,
    }
}
