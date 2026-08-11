//! Primitive- and handshake-level diagnostics that compare hiss directly
//! against `snow`'s own dependencies.
//!
//! These are the two tests that used to sit in hiss's `tests/snow_diag.rs`
//! and were the only reason that file linked `snow`. Their snow-free
//! siblings — the ipad/opad HMAC oracle and the NIST ECCCDH vector — stayed
//! behind in `tests/primitive_diag.rs`.
//!
//! What they add over the frozen corpora: the first checks that `eccoxide`
//! and the `p256` crate derive the *same* public key from the same scalar,
//! and the second replays a Noise `N` handshake by hand — every mix_hash,
//! the HKDF, the AEAD — against a live snow initiator, so a divergence shows
//! up at the exact step it happened rather than as a wrong final byte.

use hiss::curve::p256::P256r1PublicKey;
use hiss::noise::Blake2b;
use hiss::noise::hash::Hash;

/// Verify eccoxide public key derivation matches snow's p256 crate
/// when using the same raw scalar bytes.
#[test]
fn eccoxide_pubkey_matches_snow_p256() {
    use eccoxide::curve::sec2::p256r1::{Point, Scalar};

    let snow_builder = snow::Builder::new("Noise_N_P256_ChaChaPoly_BLAKE2b".parse().unwrap());
    let kp = snow_builder.generate_keypair().unwrap();

    let scalar = Scalar::from_slice(&kp.private).unwrap();
    let derived = (&scalar * &Point::GENERATOR).to_affine().unwrap();
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
    use hiss::curve::p256::P256;
    use hiss::provider::EphemeralOnly;
    use hiss::provider::ProviderExt;
    use rand::{SeedableRng, rngs::StdRng};

    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    let our_static = provider.generate::<P256>().unwrap();
    let our_static_pub = provider.public(&our_static).unwrap();
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
    let shared_secret = our_static.dh(&snow_e_pub_key).unwrap();
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
