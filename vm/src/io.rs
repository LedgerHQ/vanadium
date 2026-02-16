use core::fmt;

use ledger_device_sdk::io;

use crate::{AppSW, Instruction};

/// Error returned by the [`interrupt`] function when the host does not
/// respond with the expected `Continue` command.
#[derive(Debug)]
pub enum InterruptError {
    /// The APDU response could not be decoded.
    InvalidResponse,
    /// The received instruction was not `Continue`.
    UnsupportedInstruction,
    /// P1/P2 parameters were not the expected values.
    WrongParameters,
}

impl InterruptError {
    /// Returns a static string description of the error.
    pub fn as_str(&self) -> &'static str {
        match self {
            InterruptError::InvalidResponse => "Invalid response",
            InterruptError::UnsupportedInstruction => "INS not supported",
            InterruptError::WrongParameters => "Wrong P1/P2",
        }
    }
}

impl fmt::Display for InterruptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Helper function to send the InterruptedExecution response, and make sure the next command is 'Continue'
pub fn interrupt<'a, const N: usize>(
    response: io::CommandResponse<'a, N>,
) -> Result<io::Command<'a, N>, InterruptError> {
    let comm = response.send(AppSW::InterruptedExecution).unwrap();
    let command = comm.next_command();

    let ins = command
        .decode::<Instruction>()
        .map_err(|_: io::Reply| InterruptError::InvalidResponse)?;

    let Instruction::Continue(p1, p2) = ins else {
        // expected "Continue"
        return Err(InterruptError::UnsupportedInstruction);
    };
    if (p1, p2) != (0, 0) {
        return Err(InterruptError::WrongParameters);
    }

    Ok(command)
}
