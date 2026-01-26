use common::client_commands::Message;

pub mod ecall;
pub mod evict;
pub mod outsourced_mem;

trait SerializeToComm<const N: usize> {
    fn serialize_to_comm(&self, response: &mut ledger_device_sdk::io::CommandResponse<'_, N>);
}

impl<'a, T: Message<'a>, const N: usize> SerializeToComm<N> for T {
    fn serialize_to_comm(&self, response: &mut ledger_device_sdk::io::CommandResponse<'_, N>) {
        self.serialize_with(|data| {
            response.append(data).unwrap();
        });
    }
}
