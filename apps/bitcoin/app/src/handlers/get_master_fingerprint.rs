use crate::bip32::KeyTree;
use common::message::Response;

pub fn handle_get_master_fingerprint(
    _app: &mut sdk::App,
    tree: KeyTree,
) -> Result<Response, common::errors::Error> {
    let fpr = crate::bip32::master_fingerprint(tree)?;
    Ok(Response::MasterFingerprint(fpr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_get_master_fingerprint_standard() {
        let response =
            handle_get_master_fingerprint(&mut sdk::App::singleton(), KeyTree::Standard).unwrap();
        assert_eq!(response, Response::MasterFingerprint(0xf5acc2fdu32));
    }

    #[test]
    fn test_handle_get_master_fingerprint_resident() {
        let response =
            handle_get_master_fingerprint(&mut sdk::App::singleton(), KeyTree::Resident).unwrap();
        assert_eq!(response, Response::MasterFingerprint(0xad85d955));
    }
}
