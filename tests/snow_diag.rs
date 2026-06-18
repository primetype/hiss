//! Primitive-level diagnostics verifying that our crypto primitives
//! produce identical results to snow's dependencies.
//!
//! These tests are independent of the handshake framework — they
//! exercise the raw BLAKE2b, HMAC, ECDH, and ChaCha20-Poly1305
//! implementations directly.

use hiss::curve::p256::P256r1PublicKey;
use hiss::noise::Blake2b;
use hiss::noise::hash::Hash;

/// Verify our HMAC-BLAKE2b matches a manual ipad/opad implementation
/// (the same algorithm snow uses internally).
#[test]
fn hmac_blake2b_matches_manual_ipad_opad() {
    let key = b"test-key-for-hmac";
    let data = b"test-data-for-hmac";

    let our_hmac = Blake2b::hmac(key, data);

    // Manual HMAC using ipad/opad (same algorithm as snow)
    let block_len = 128;
    let mut ipad = vec![0x36u8; block_len];
    let mut opad = vec![0x5cu8; block_len];
    for i in 0..key.len() {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = Blake2b::hash_two(&ipad, data);
    let manual_hmac = Blake2b::hash_two(&opad, &inner);

    assert_eq!(our_hmac, manual_hmac);
}

/// Verify eccoxide ECDH against NIST ECCCDH P-256 test vector (Count=0).
#[test]
fn eccoxide_dh_matches_nist_vector() {
    use eccoxide::curve::sec2::p256r1::{FieldElement, Point, PointAffine, Scalar};

    let qcavs_x =
        hex::decode("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287").unwrap();
    let qcavs_y =
        hex::decode("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac").unwrap();
    let diut =
        hex::decode("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534").unwrap();
    let ziut =
        hex::decode("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b").unwrap();

    let x = FieldElement::from_slice(&qcavs_x).unwrap();
    let y = FieldElement::from_slice(&qcavs_y).unwrap();
    let peer = Point::from(&PointAffine::from_coordinate(&x, &y).unwrap());
    let scalar = Scalar::from_slice(&diut).unwrap();

    let shared = (&scalar * &peer).to_affine().unwrap();
    let (shared_x, _) = shared.to_coordinate();

    assert_eq!(shared_x.to_bytes().as_slice(), ziut.as_slice());
}

/// Verify eccoxide public key derivation matches snow's p256 crate
/// when using the same raw scalar bytes.
#[test]
fn eccoxide_pubkey_matches_snow_p256() {
    use eccoxide::curve::sec2::p256r1::{Point, Scalar};

    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let kp = snow_builder.generate_keypair().unwrap();

    let scalar = Scalar::from_slice(&kp.private).unwrap();
    let derived = (&scalar * &Point::generator()).to_affine().unwrap();
    let (dx, dy) = derived.to_coordinate();
    let mut derived_bytes = [0u8; 65];
    derived_bytes[0] = 0x04;
    derived_bytes[1..33].copy_from_slice(&dx.to_bytes());
    derived_bytes[33..65].copy_from_slice(&dy.to_bytes());

    assert_eq!(derived_bytes.as_slice(), kp.public.as_slice());
}

/// Manually replay the Noise N handshake (including the empty
/// prologue mix_hash) and verify the result matches snow.
#[tokio::test]
async fn manual_n_replay_matches_snow() {
    use hiss::curve::{CryptoKeys, CryptoProviderAsync};
    use hiss::curve::p256::SoftwareCryptoProvider;

    let provider = SoftwareCryptoProvider;

    let our_static = provider.generate_static_key().await.unwrap();
    let our_static_pub = provider.public_key(&our_static).unwrap();
    let rs_bytes = our_static_pub.to_bytes();

    // Snow N initiator
    let mut snow_init = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap())
        .remote_public_key(rs_bytes)
        .unwrap()
        .build_initiator()
        .unwrap();

    let mut msg1 = [0u8; 256];
    let msg1_len = snow_init.write_message(&[], &mut msg1).unwrap();
    let msg1 = &msg1[..msg1_len];
    assert_eq!(msg1_len, 81);

    let snow_e_pub = &msg1[..65];
    let snow_tag = &msg1[65..81];

    // Manual responder replay
    let protocol_name = "Noise_N_P256_ChaChaPoly_BLAKE2b";

    // Initialize
    let mut h = vec![0u8; 64];
    h[..protocol_name.len()].copy_from_slice(protocol_name.as_bytes());
    let mut ck = h.clone();

    // mix_hash(prologue) — even an empty prologue must be mixed in
    h = Blake2b::hash_two(&h, &[]);

    // Pre-message <- s: mix_hash(responder_pub)
    h = Blake2b::hash_two(&h, rs_bytes);

    // Receive e: mix_hash(ephemeral_pub)
    h = Blake2b::hash_two(&h, snow_e_pub);

    // es: DH(s, re)
    let snow_e_pub_key = P256r1PublicKey::from_bytes(snow_e_pub).unwrap();
    let shared_secret = provider.dh(&our_static, &snow_e_pub_key).await.unwrap();
    let ss_bytes: &[u8] = shared_secret.as_ref();

    // mix_key(shared_secret)
    let temp_key = Blake2b::hmac(&ck, ss_bytes);
    let output1 = Blake2b::hmac(&temp_key, &[0x01]);
    let mut input2 = output1.clone();
    input2.push(0x02);
    let output2 = Blake2b::hmac(&temp_key, &input2);
    ck = output1;
    let _ = ck; // consumed by split in a full handshake
    let mut cipher_key = [0u8; 32];
    cipher_key.copy_from_slice(&output2[..32]);

    // DecryptAndHash(tag)
    let nonce = [0u8; 12];
    let mut cipher = cryptoxide::chacha20poly1305::ChaCha20Poly1305::new(&cipher_key, &nonce, &h);
    assert!(
        cipher.decrypt(&[], &mut [], snow_tag),
        "payload tag decryption failed"
    );

    h = Blake2b::hash_two(&h, snow_tag);
    assert_eq!(h.as_slice(), snow_init.get_handshake_hash());
}
