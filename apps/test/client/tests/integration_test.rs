#![cfg(feature = "speculos-tests")]

use hex_literal::hex;

use sdk::test_utils::{setup_test, TestSetup};

use vnd_test_client::TestClient;

pub async fn setup() -> TestSetup<TestClient> {
    let vanadium_binary = std::env::var("VANADIUM_BINARY")
        .unwrap_or_else(|_| "../../../vm/target/flex/release/app-vanadium".to_string());
    let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
        "../app/target/riscv32imc-unknown-none-elf/release/vnd-test".to_string()
    });
    setup_test(&vanadium_binary, &vapp_binary, |transport| {
        TestClient::new(transport)
    })
    .await
}

#[tokio::test]
async fn test_reverse() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("1122334455").to_vec(), hex!("5544332211").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(setup.client.reverse(&input).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn test_add_numbers() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(u32, u64)> = vec![
        (0, 0),
        (1, 1),
        (100, 5050),
    ];

    for (input, expected) in testcases {
        assert_eq!(setup.client.add_numbers(input).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn test_b58enc() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(&str, &str)> = vec![
        ("Hello World!", "2NEpo7TZRRrLZSi2U"),
        ("The quick brown fox jumps over the lazy dog.", "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z"),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.b58enc(&input.as_bytes()).await.unwrap(),
            expected.as_bytes().to_vec()
        );
    }
}

#[tokio::test]
async fn test_sha256() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(&str, Vec<u8>)> = vec![
        ("", hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.sha256(&input.as_bytes()).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_nprimes() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(u32, u32)> = vec![
        (0, 0),
        (5, 3),
        (100, 25),
        (1000, 168),
    ];

    for (input, expected) in testcases {
        assert_eq!(setup.client.nprimes(input).await.unwrap(), expected);
    }
}

#[tokio::test]
async fn test_deviceprop() {
    let mut setup = setup().await;

    let device_id = setup.client.device_props(1).await.unwrap();
    assert_eq!(device_id >> 16, 0x2C97); // Ledger vendor_id
    assert!(device_id & 0xFFFF > 0); // product_id, different for each device
    let screen_size = setup.client.device_props(2).await.unwrap();
    let width = screen_size >> 16;
    let height = screen_size & 0xFFFF;
    assert!(width > 0 && height > 0);
}
