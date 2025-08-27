use ledger_device_sdk::io_new as io;

use crate::{AppSW, Instruction};

// Helper function to send the InterruptedExecution response, and make sure the next command is 'Continue'
pub fn interrupt<'a, const N: usize>(
    tx: io::Tx<'a, N>,
) -> Result<io::Command<'a, N>, common::vm::MemoryError> {
    let comm = tx.send(AppSW::InterruptedExecution).unwrap();
    let command = comm.next_command();

    let ins = command
        .decode::<Instruction>()
        .map_err(|_: io::Reply| common::vm::MemoryError::GenericError("Invalid response"))?;

    let Instruction::Continue(p1, p2) = ins else {
        // expected "Continue"
        return Err(common::vm::MemoryError::GenericError("INS not supported"));
    };
    if (p1, p2) != (0, 0) {
        return Err(common::vm::MemoryError::GenericError("Wrong P1/P2"));
    }

    Ok(command)
}
