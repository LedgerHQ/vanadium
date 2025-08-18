// Duplicated for simplicity with the corresponding module in the client crate.
// Make sure to keep them in sync.

#[derive(Debug)]
pub enum Command {
    Reverse,
    AddNumbers,
    Base58Encode,
    Sha256,
    CountPrimes,
    ShowUxScreen = 0x80,
    DeviceProp = 0x81,
    Print = 0xfe,
    Panic = 0xff,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x00 => Ok(Command::Reverse),
            0x01 => Ok(Command::AddNumbers),
            0x02 => Ok(Command::Base58Encode),
            0x03 => Ok(Command::Sha256),
            0x04 => Ok(Command::CountPrimes),
            0x80 => Ok(Command::ShowUxScreen),
            0x81 => Ok(Command::DeviceProp),
            0xfe => Ok(Command::Print),
            0xff => Ok(Command::Panic),
            _ => Err(()),
        }
    }
}
