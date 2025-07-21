use ledger_device_sdk::io;

// Sends an APDU, and receives the reply, without processing other events in between.
// Similar to io_exchange fron the C sdk.
// Using the normal SDK functionalities (Comm::reply and Comm::next_command) was causing
// messages to be throttled by 0.1s.
// TODO: refactor after the io revamp in the SDK.
pub fn io_exchange<R, T>(comm: &mut io::Comm, reply: R) -> T
where
    R: Into<io::Reply>,
    T: TryFrom<io::ApduHeader>,
    io::Reply: From<<T as TryFrom<io::ApduHeader>>::Error>,
{
    use ledger_secure_sdk_sys::seph as sys_seph;
    #[cfg(any(target_os = "nanox", target_os = "stax", target_os = "flex"))]
    use ledger_secure_sdk_sys::APDU_BLE;
    use ledger_secure_sdk_sys::{
        io_usb_send_apdu_data, G_io_app, APDU_IDLE, APDU_RAW, APDU_USB_HID, IO_APDU_MEDIA_NONE,
    };

    let sw = reply.into().0;
    // Append status word
    comm.apdu_buffer[comm.tx] = (sw >> 8) as u8;
    comm.apdu_buffer[comm.tx + 1] = sw as u8;
    comm.tx += 2;

    // apdu_send
    let mut spi_buffer = [0u8; 256];
    match unsafe { G_io_app.apdu_state } {
        APDU_USB_HID => unsafe {
            ledger_secure_sdk_sys::io_usb_hid_send(
                Some(io_usb_send_apdu_data),
                comm.tx as u16,
                comm.apdu_buffer.as_mut_ptr(),
            );
        },
        APDU_RAW => {
            let len = (comm.tx as u16).to_be_bytes();
            sys_seph::seph_send(&[sys_seph::SephTags::RawAPDU as u8, len[0], len[1]]);
            sys_seph::seph_send(&comm.apdu_buffer[..comm.tx]);
        }
        #[cfg(any(target_os = "nanox", target_os = "stax", target_os = "flex"))]
        APDU_BLE => {
            ledger_device_sdk::ble::send(&comm.apdu_buffer[..comm.tx]);
        }
        _ => (),
    }
    comm.tx = 0;
    comm.rx = 0;

    loop {
        unsafe {
            G_io_app.apdu_state = APDU_IDLE;
            G_io_app.apdu_media = IO_APDU_MEDIA_NONE;
            G_io_app.apdu_length = 0;
        }

        let res = loop {
            // Signal end of command stream from SE to MCU
            // And prepare reception
            if !sys_seph::is_status_sent() {
                sys_seph::send_general_status();
            }

            // Fetch the next message from the MCU
            let _rx = sys_seph::seph_recv(&mut spi_buffer, 0);

            if let Some(value) = comm.decode_event(&mut spi_buffer) {
                break value;
            }
        };

        if let io::Event::Command(ins) = res {
            return ins;
        }
    }
}
