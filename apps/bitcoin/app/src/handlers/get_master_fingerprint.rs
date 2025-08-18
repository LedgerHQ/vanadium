use common::message::Response;
use sdk::curve::Curve;

pub fn handle_get_master_fingerprint(
    _app: &mut sdk::App,
) -> Result<Response, common::errors::Error> {
    Ok(Response::MasterFingerprint(
        sdk::curve::Secp256k1::get_master_fingerprint(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_get_master_fingerprint() {
        let response = handle_get_master_fingerprint(&mut sdk::App::singleton()).unwrap();
        assert_eq!(response, Response::MasterFingerprint(0xf5acc2fdu32));
    }
}
