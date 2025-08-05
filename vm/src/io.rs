use ledger_device_sdk::io;

// This trait encapsulates some customized functions that the Ledger Vanadium app
// implements on top of the io::Comm
pub trait CommExt {
    fn reply_fast<T: Into<io::Reply>>(&mut self, reply: T);

    fn io_exchange<R, T>(&mut self, reply: R) -> T
    where
        R: Into<io::Reply>,
        T: TryFrom<io::ApduHeader>,
        io::Reply: From<<T as TryFrom<io::ApduHeader>>::Error>;
}

impl CommExt for io::Comm {
    fn reply_fast<T: Into<io::Reply>>(&mut self, reply: T) {
        let sw = reply.into().0;
        self.io_buffer[self.tx_length] = (sw >> 8) as u8;
        self.io_buffer[self.tx_length + 1] = sw as u8;
        self.tx_length += 2;

        if self.tx != 0 {
            ledger_secure_sdk_sys::seph::io_tx(self.apdu_type, &self.apdu_buffer, self.tx);
            self.tx = 0;
        } else {
            ledger_secure_sdk_sys::seph::io_tx(self.apdu_type, &self.io_buffer, self.tx_length);
        }
        self.tx_length = 0;
        self.rx_length = 0;
    }

    fn io_exchange<R, T>(&mut self, reply: R) -> T
    where
        R: Into<io::Reply>,
        T: TryFrom<io::ApduHeader>,
        io::Reply: From<<T as TryFrom<io::ApduHeader>>::Error>,
    {
        self.reply_fast(reply);
        self.next_command()
    }
}
