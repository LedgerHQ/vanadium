#![cfg(feature = "speculos-tests")]
use common::{BigIntOperator, HashId};
use hex_literal::hex;
use sha2::Digest;

use sdk::test_utils::{setup_test, TestSetup};

use vnd_sadik_client::SadikClient;

pub async fn setup() -> TestSetup<SadikClient> {
    let vanadium_binary = std::env::var("VANADIUM_BINARY")
        .unwrap_or_else(|_| "../../../vm/target/flex/release/app-vanadium".to_string());
    let vapp_binary = std::env::var("VAPP_BINARY").unwrap_or_else(|_| {
        "../app/target/riscv32imc-unknown-none-elf/release/vnd-sadik".to_string()
    });
    setup_test(&vanadium_binary, &vapp_binary, |transport| {
        SadikClient::new(transport)
    })
    .await
}

#[tokio::test]
#[rustfmt::skip]
async fn test_big_num() {
    let mut setup = setup().await;

    let zero_large = [0u8; 64].to_vec();
    let minus_one_large = [0xffu8; 64].to_vec();
    let one_large = {
        let mut one = [0u8; 64];
        one[63] = 1;
        one.to_vec()
    };

    // additions
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("77989873"), &hex!("a4589234"), false).await.unwrap(),
        hex!("1bf12aa7")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("47989873"), &hex!("a4589234"), false).await.unwrap(),
        hex!("ebf12aa7")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("ffffffff"), &hex!("00000001"), false).await.unwrap(),
        hex!("00000000")
    );

    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &minus_one_large, &one_large, false).await.unwrap(),
        zero_large
    );

    // subtractions
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("a4589234"), &hex!("77989873"), false).await.unwrap(),
        hex!("2cbff9c1")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("77989873"), &hex!("a4589234"), false).await.unwrap(),
        hex!("d340063f")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("00000000"), &hex!("00000001"), false).await.unwrap(),
        hex!("ffffffff")
    );

    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &zero_large, &one_large, false).await.unwrap(),
        minus_one_large
    );
}

#[tokio::test]
#[rustfmt::skip]
async fn test_big_num_mod() {
    let mut setup = setup().await;

    // all operations are modulo 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    // (curve order of Secp256k1)

    let M: Vec<u8> = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f").to_vec();
    let M2: Vec<u8> = hex!("3d4b0f9e4e4d5b6e5e5d6e7e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9e8e8d9e9d").to_vec();

    let zero: Vec<u8> = hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec();
    let one: Vec<u8> = hex!("0000000000000000000000000000000000000000000000000000000000000001").to_vec();

    // addition
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Add, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), true).await.unwrap(),
        hex!("15d7f1c4cab897b32c12c8a1b638879f478e7db6dd583a4d18c97cc5d77fd167")
    );

    // subtraction
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), true).await.unwrap(),
        hex!("2eb6c1439a7770b1fc00388eb1d77f8afdd55575799fb6185776d4c060ae0062")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Sub, &hex!("7390984098209380980948098230840982340294098092384092834923840923"), &hex!("a247598432980432940980983408039480095809832048509809580984320985"), true).await.unwrap(),
        hex!("d1493ebc65888f4e03ffc7714e288073bcd9877135a8ea23685b89cc6f8840df")
    );

    // multiplication
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &zero, true).await.unwrap(),
        zero
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &one, true).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Mul, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("7390984098209380980948098230840982340294098092384092834923840923"), true).await.unwrap(),
        hex!("1657a819aad617cac89f35ff9d4890c66cc5675c70f2b66e974bc243b2e69116")
    );

    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("00"), true).await.unwrap(),
        one
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &zero, true).await.unwrap(),
        one
    );

    // powers: 1
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &one, true).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("01"), true).await.unwrap(),
        hex!("a247598432980432940980983408039480095809832048509809580984320985")
    );

    // powers: 2
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("02"), true).await.unwrap(),
        hex!("4b3820d9706f0a26b136ea1c3df40a4836663a11be453dcbe1a7f8230e7dbe0e")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("00000002"), true).await.unwrap(),
        hex!("4b3820d9706f0a26b136ea1c3df40a4836663a11be453dcbe1a7f8230e7dbe0e")
    );
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("0000000000000000000000000000000000000000000000000000000000000002"), true).await.unwrap(),
        hex!("4b3820d9706f0a26b136ea1c3df40a4836663a11be453dcbe1a7f8230e7dbe0e")
    );

    // powers: large
    assert_eq!(
        setup.client.bignum_operation(BigIntOperator::Pow, &hex!("a247598432980432940980983408039480095809832048509809580984320985"), &hex!("22e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd722e0b80916f2f35efab04d6d61155f9d1aa9f8f0dff2a2b656cdee1bb7b6dcd7"), true).await.unwrap(),
        hex!("8d72fea89e5500398d2034bd3058cf82ebeec06c61a8ff83e7fbf2cbf5c9b647")
    );
}

#[tokio::test]
async fn test_big_num_mod_inv() {
    let mut setup = setup().await;

    // all operations are modulo 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
    // (curve order of Secp256k1)

    let one: Vec<u8> = hex!("0000000000000000000000000000000000000000000000000000000000000001").to_vec();

    // inv(1) == 1
    assert_eq!(
        setup.client.bignum_modinv(&one).await.unwrap(),
        one
    );

    // a * inv(a) == 1 (for a small value)
    let a = hex!("0000000000000000000000000000000000000000000000000000000000000007");
    let a_inv = setup.client.bignum_modinv(&a).await.unwrap();
    let product = setup.client.bignum_operation(BigIntOperator::Mul, &a, &a_inv, true).await.unwrap();
    assert_eq!(product, one);

    // a * inv(a) == 1 (for a larger value)
    let b = hex!("a247598432980432940980983408039480095809832048509809580984320985");
    let b_inv = setup.client.bignum_modinv(&b).await.unwrap();
    let product = setup.client.bignum_operation(BigIntOperator::Mul, &b, &b_inv, true).await.unwrap();
    assert_eq!(product, one);
}

#[tokio::test]
async fn test_ripemd160() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("9c1185a5c5e9fc54612808977ee8f548b2258d31").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("37f332f68db77bd9d7edd4969571ad671cf9dd3b").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Ripemd160, &input).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_sha256() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Sha256, &input).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_sha512() {
    let mut setup = setup().await;

    #[rustfmt::skip]
    let testcases: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (hex!("").to_vec(), hex!("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").to_vec()),
        (hex!("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67").to_vec(), hex!("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6").to_vec()),
    ];

    for (input, expected) in testcases {
        assert_eq!(
            setup.client.hash(HashId::Sha512, &input).await.unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_secp256k1_get_master_fingerprint() {
    let mut setup = setup().await;

    assert_eq!(
        setup
            .client
            .get_master_fingerprint(common::Curve::Secp256k1)
            .await
            .unwrap(),
        hex!("f5acc2fd").to_vec()
    );
}

#[tokio::test]
async fn test_secp256k1_derive_hd_node() {
    let mut setup = setup().await;

    let test_cases: Vec<(Vec<u32>, ([u8; 32], [u8; 32]))> = vec![
        (
            vec![],
            (
                hex!("eb473a0fa0af5031f14db9fe7c37bb8416a4ff01bb69dae9966dc83b5e5bf921"),
                hex!("34ac5d784ebb4df4727bcddf6a6743f5d5d46d83dd74aa825866390c694f2938"),
            ),
        ),
        (
            vec![0x8000002c, 0x80000000, 0x80000001, 0, 3],
            (
                hex!("6da5f32f47232b3b9b2d6b59b802e2b313afa7cbda242f73da607139d8e04989"),
                hex!("239841e64103fd024b01283e752a213fee1a8969f6825204ee3617a45c5e4a91"),
            ),
        ),
    ];

    for (path, (exp_chaincode, exp_privkey)) in test_cases {
        let res = setup
            .client
            .derive_hd_node(common::Curve::Secp256k1, path)
            .await
            .unwrap();

        assert_eq!(res.len(), exp_chaincode.len() + exp_privkey.len());
        let chaincode = &res[0..exp_chaincode.len()];
        let privkey = &res[exp_chaincode.len()..];

        assert_eq!(exp_chaincode, chaincode);
        assert_eq!(exp_privkey, privkey);
    }
}

#[tokio::test]
async fn test_derive_slip21_key() {
    let mut setup = setup().await;
    let client = &mut setup.client;

    let label1 = b"Vanadium".to_vec();

    // m/b'Vanadium'
    let key1 = client.get_slip21_key(&[&label1]).await.unwrap();
    let expected1 = hex!("ba0ff8c27d6a0c9f7cb3346394b7c57306c5922a2f54a7d51352b9c511e155e0");
    assert_eq!(key1, expected1.to_vec());

    // m/b'Vanadium'/b'Risc-V'
    let label2 = b"Risc-V".to_vec();
    let key2 = client.get_slip21_key(&[&label1, &label2]).await.unwrap();
    let expected2 = hex!("234bbecf423f05569b6de6cbb56cd73cb9c29dec8c6599551a1a5a85bc445e5f");
    assert_eq!(key2, expected2.to_vec());
}

#[tokio::test]
async fn test_secp256k1_point_add() {
    let mut setup = setup().await;

    let p = hex!("04c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee51ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a");
    let q = hex!("04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672");

    let res = setup
        .client
        .ecpoint_add(common::Curve::Secp256k1, &p, &q)
        .await
        .unwrap();

    assert_eq!(
        res,
        hex!("042f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4d8ac222636e5e3d6d4dba9dda6c9c426f788271bab0d6840dca87d3aa6ac62d6")
    );
}

#[tokio::test]
async fn test_secp256k1_point_scalarmul() {
    let mut setup = setup().await;

    let p = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let k = hex!("22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011");

    let res = setup
        .client
        .ecpoint_scalarmult(common::Curve::Secp256k1, &p, &k)
        .await
        .unwrap();

    assert_eq!(
        res,
        hex!("042748bce8ffc3f815e69e594ae974be5e9a3be69a233d5557ea9c92b71d69367b747206115143153c85f3e8bb94d392bd955d36f1f0204921e6dd7684e81bdaab")
    );
}

#[tokio::test]
async fn test_secp256k1_point_add_with_identity() {
    let mut setup = setup().await;

    // Point at infinity (identity element) - 65 bytes of 0x00
    let identity = [0u8; 65];

    let p = hex!("042748bce8ffc3f815e69e594ae974be5e9a3be69a233d5557ea9c92b71d69367b747206115143153c85f3e8bb94d392bd955d36f1f0204921e6dd7684e81bdaab");

    // P + O = P
    let res = setup
        .client
        .ecpoint_add(common::Curve::Secp256k1, &p, &identity)
        .await
        .unwrap();
    assert_eq!(res, p);

    // O + P = P
    let res = setup
        .client
        .ecpoint_add(common::Curve::Secp256k1, &identity, &p)
        .await
        .unwrap();
    assert_eq!(res, p);

    // O + O = O
    let res = setup
        .client
        .ecpoint_add(common::Curve::Secp256k1, &identity, &identity)
        .await
        .unwrap();
    assert_eq!(res, identity);
}

//speculos does not implement correctly the detection of the point at infinity in point addition
// #[tokio::test]
// async fn test_secp256k1_point_add_inverse() {
//     let mut setup = setup().await;

//     // Point at infinity (identity element)
//     let identity = [0u8; 65];

//     // A point P
//         let p = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

//     // Negation of P (flip the y-coordinate)
//     let p_neg = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"); 

//     // P + (-P) = O
//     let res = setup
//         .client
//         .ecpoint_add(common::Curve::Secp256k1, &p, &p_neg)
//         .await
//         .unwrap();
//     assert_eq!(res, identity);
// }

#[tokio::test]
async fn test_secp256k1_scalarmul_by_zero() {
    let mut setup = setup().await;

    // Point at infinity (identity element)
    let identity = [0u8; 65];

    let p = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let zero = hex!("0000000000000000000000000000000000000000000000000000000000000000");

    // P * 0 = O
    let res = setup
        .client
        .ecpoint_scalarmult(common::Curve::Secp256k1, &p, &zero)
        .await
        .unwrap();
    assert_eq!(res, identity);
}

#[tokio::test]
async fn test_secp256k1_scalarmul_by_one() {
    let mut setup = setup().await;

    let p = hex!("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
    let one = hex!("0000000000000000000000000000000000000000000000000000000000000001");

    // P * 1 = P
    let res = setup
        .client
        .ecpoint_scalarmult(common::Curve::Secp256k1, &p, &one)
        .await
        .unwrap();
    assert_eq!(res, p);
}

#[tokio::test]
async fn test_secp256k1_scalarmul_identity() {
    let mut setup = setup().await;

    // Point at infinity (identity element)
    let identity = [0u8; 65];

    let k = hex!("22445566778899aabbccddeeff0011223344556677889900aabbccddeeff0011");

    // O * k = O
    let res = setup
        .client
        .ecpoint_scalarmult(common::Curve::Secp256k1, &identity, &k)
        .await
        .unwrap();
    assert_eq!(res, identity);
}

#[tokio::test]
async fn test_secp256k1_ecdsa_sign() {
    let mut setup = setup().await;
    let msg =
        "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";

    // compute the sha256 hash using the sha2 crate
    let msg_hash = sha2::Sha256::digest(msg.as_bytes()).to_vec();

    let privkey = hex!("4242424242424242424242424242424242424242424242424242424242424242");

    let result = setup
        .client
        .ecdsa_sign(common::Curve::Secp256k1, &privkey, &msg_hash)
        .await
        .unwrap();

    let expected_signature = hex!("304402201bbd5947e4a9cdf85d6efb0aeecdfa8c179480a1b972a3dd8b277a78a409dcdf022064c812320ad4f0ae5a3fa1ef5d66ef70c78922bd9d9e30b224d1b38671a3291b");

    // signature is deterministic per RFC6979
    assert_eq!(result, expected_signature);
}

#[tokio::test]
async fn test_secp256k1_ecdsa_verify() {
    let mut setup = setup().await;
    let msg =
        "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";

    // compute the sha256 hash using the sha2 crate
    let msg_hash = sha2::Sha256::digest(msg.as_bytes()).to_vec();

    let pubkey = hex!("0424653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c119fc5009a032aa9fe47f5e149bb8442f71f884ccb516590686d8ff6ab91c613");
    let signature = hex!("304402201bbd5947e4a9cdf85d6efb0aeecdfa8c179480a1b972a3dd8b277a78a409dcdf022064c812320ad4f0ae5a3fa1ef5d66ef70c78922bd9d9e30b224d1b38671a3291b");

    let result = setup
        .client
        .ecdsa_verify(common::Curve::Secp256k1, &pubkey, &msg_hash, &signature)
        .await
        .unwrap();

    assert_eq!(result, vec![1]);

    let sig_wrong = {
        let mut sig = signature.clone();
        sig[16] ^= 0x01;
        sig
    };

    let result = setup
        .client
        .ecdsa_verify(common::Curve::Secp256k1, &pubkey, &msg_hash, &sig_wrong)
        .await
        .unwrap();

    assert_eq!(result, vec![0]);
}

#[tokio::test]
async fn test_secp256k1_schnorr_sign() {
    let mut setup = setup().await;
    let msg =
        "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";

    let privkey = hex!("4242424242424242424242424242424242424242424242424242424242424242");

    let result = setup
        .client
        .schnorr_sign(common::Curve::Secp256k1, &privkey, &msg.as_bytes())
        .await
        .unwrap();

    // Schnorr signature using BIP340 is not deterministic. Check that the returned signature is valid instead
    assert_eq!(result.len(), 64);

    println!("Signature: {:?}", result);

    let signature = k256::schnorr::Signature::try_from(result.as_slice()).unwrap();

    // verify that the signature is valid using the k256 crate
    let pubkey = k256::schnorr::VerifyingKey::from_bytes(&hex!(
        "24653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"
    ))
    .unwrap();

    // verify_raw uses unhashed messages; normally one wouldn't reaaly use this
    pubkey.verify_raw(msg.as_bytes(), &signature).unwrap();
}

#[tokio::test]
async fn test_secp256k1_schnorr_verify() {
    let mut setup = setup().await;
    let msg =
        "If you don't believe me or don't get it, I don't have time to try to convince you, sorry.";

    let pubkey = hex!("0424653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1cee603aff65fcd55601b80a1eb6447bbd08e077b334ae9a6f97927008546e361c");
    let signature = hex!("54a2a499ce77edc2599c3fdb99b66d461230165776abf6efebe3a86cb6b3a88e8bf4a388ff3fe1e424a907974826a991b2bb497691d055da66b1b5ba12bb67cc");

    let result = setup
        .client
        .schnorr_verify(
            common::Curve::Secp256k1,
            &pubkey,
            &msg.as_bytes(),
            &signature,
        )
        .await
        .unwrap();

    assert_eq!(result, vec![1]);

    let sig_wrong = {
        let mut sig = signature.clone();
        sig[16] ^= 0x01;
        sig
    };

    let result = setup
        .client
        .schnorr_verify(
            common::Curve::Secp256k1,
            &pubkey,
            &msg.as_bytes(),
            &sig_wrong,
        )
        .await
        .unwrap();

    assert_eq!(result, vec![0]);
}

#[tokio::test]
async fn test_ticker() {
    // a simple test that verifies that ticker events are indeed received.
    let mut setup = setup().await;
    let result = setup.client.sleep(10).await.expect("Should not fail");
    assert_eq!(result, Vec::<u8>::new());
}

#[tokio::test]
async fn test_storage_read_uninitialized() {
    // Reading an uninitialized storage slot should return zeros
    let mut setup = setup().await;
    
    for slot in 0..4 {
        let result = setup.client.read_storage(slot).await.unwrap();
        // Storage slots should be initialized to all zeros
        assert_eq!(result, vec![0u8; 32], "Uninitialized slot {} should contain zeros", slot);
    }
}

#[tokio::test]
async fn test_storage_write_and_read() {
    // Writing to a storage slot and then reading it should return the same value
    let mut setup = setup().await;
    
    let test_data = hex!("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    
    // Write to slot 0
    setup.client.write_storage(0, &test_data).await.unwrap();
    
    // Read back from slot 0
    let result = setup.client.read_storage(0).await.unwrap();
    assert_eq!(result, test_data.to_vec(), "Read data should match written data");
}

#[tokio::test]
async fn test_storage_multiple_slots() {
    // Test writing to multiple different slots
    let mut setup = setup().await;
    
    let data0 = hex!("1111111111111111111111111111111111111111111111111111111111111111");
    let data1 = hex!("2222222222222222222222222222222222222222222222222222222222222222");
    let data2 = hex!("3333333333333333333333333333333333333333333333333333333333333333");
    let data3 = hex!("4444444444444444444444444444444444444444444444444444444444444444");
    
    // Write to all 4 slots
    setup.client.write_storage(0, &data0).await.unwrap();
    setup.client.write_storage(1, &data1).await.unwrap();
    setup.client.write_storage(2, &data2).await.unwrap();
    setup.client.write_storage(3, &data3).await.unwrap();
    
    // Read back and verify all slots
    assert_eq!(setup.client.read_storage(0).await.unwrap(), data0.to_vec());
    assert_eq!(setup.client.read_storage(1).await.unwrap(), data1.to_vec());
    assert_eq!(setup.client.read_storage(2).await.unwrap(), data2.to_vec());
    assert_eq!(setup.client.read_storage(3).await.unwrap(), data3.to_vec());
}
