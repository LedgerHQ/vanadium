mod get_address;
mod get_extended_pubkey;
mod get_master_fingerprint;
mod register_account;
mod sign_psbt;

pub use get_address::handle_get_address;
pub use get_extended_pubkey::handle_get_extended_pubkey;
pub use get_master_fingerprint::handle_get_master_fingerprint;
pub use register_account::handle_register_account;
pub use sign_psbt::handle_sign_psbt;
