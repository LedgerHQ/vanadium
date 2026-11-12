use common::message::Response;

/// The version of the app.
pub fn handle_get_version() -> Response {
    Response::Version {
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_get_version() {
        assert_eq!(
            handle_get_version(),
            Response::Version {
                version: env!("CARGO_PKG_VERSION").into()
            }
        );
    }
}
