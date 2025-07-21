use common::client_commands::Message;

pub mod ecall;
pub mod io;
pub mod outsourced_mem;
pub mod vapp;

trait SerializeToComm {
    fn serialize_to_comm(&self, comm: &mut ledger_device_sdk::io::Comm);
}

impl<'a, T: Message<'a>> SerializeToComm for T {
    fn serialize_to_comm(&self, comm: &mut ledger_device_sdk::io::Comm) {
        self.serialize_with(|data| comm.append(data));
    }
}
