use std::str::FromStr;

use secp256k1::{hashes::sha256, rand, Keypair, Message, PublicKey, Secp256k1, SecretKey};

#[test]
fn test_key_drive() {
    let sk =
        SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let known_pk = PublicKey::from_str("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
    assert_eq!(pk, known_pk)
}

#[test]
#[allow(non_snake_case)]
fn test_sign() {
    let mut rng = rand::thread_rng();
    let secp = Secp256k1::new();
    //  Create a random private key
    let sk = SecretKey::new(&mut rng);
    let key_pair = Keypair::from_secret_key(&secp, &sk);

    let m = Message::from_hashed_data::<sha256::Hash>("hello schnorr".as_bytes());

    let s = secp.sign_schnorr(&m, &key_pair);

    assert!(secp
        .verify_schnorr(&s, &m, &key_pair.x_only_public_key().0)
        .is_ok());

    // wrong m
    let m1 = Message::from_hashed_data::<sha256::Hash>("hello schnorr!".as_bytes());
    assert!(secp
        .verify_schnorr(&s, &m1, &key_pair.x_only_public_key().0)
        .is_err());

    //  wrong pk
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from_secret_key(&secp, &sk);
    assert!(secp
        .verify_schnorr(&s, &m, &pk.x_only_public_key().0)
        .is_err());
}
