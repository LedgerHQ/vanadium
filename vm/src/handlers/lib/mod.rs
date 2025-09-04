use common::client_commands::Message;

pub mod ecall;
pub mod evict;
pub mod outsourced_mem;
pub mod vapp;

trait SerializeToComm<const N: usize> {
    fn serialize_to_comm(&self, tx: &mut ledger_device_sdk::io_new::Tx<'_, N>);
}

impl<'a, T: Message<'a>, const N: usize> SerializeToComm<N> for T {
    fn serialize_to_comm(&self, tx: &mut ledger_device_sdk::io_new::Tx<'_, N>) {
        self.serialize_with(|data| {
            tx.append(data).unwrap();
        });
    }
}
