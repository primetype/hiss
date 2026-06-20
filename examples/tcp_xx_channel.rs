//! End-to-end Noise **XX** mutual-authentication handshake over a real
//! localhost TCP socket, driven by the **async (tokio)** handshake driver,
//! followed by one encrypted message exchanged in each direction.
//!
//! Run with:
//!
//! ```text
//! cargo run --example tcp_xx_channel --features async-io
//! ```
//!
//! # The XX pattern
//!
//! XX is the interactive, *mutually-authenticated* handshake in which
//! neither party knows the other's static key in advance — both statics
//! are transmitted (encrypted) **during** the handshake. Its token chain
//! is three messages:
//!
//! ```text
//!   -> e                  (msg1: initiator's ephemeral, in the clear)
//!   <- e, ee, s, es       (msg2: responder's ephemeral, the ee DH,
//!                          then the responder's static — now encrypted —
//!                          and the es DH that authenticates it)
//!   -> s, se              (msg3: initiator's static — encrypted — and
//!                          the se DH that authenticates it)
//! ```
//!
//! After msg3 both ends derive the same transport keys and the same
//! channel-binding `session_id` from the handshake hash.
//!
//! Contrast with the pre-known-static patterns (N, K, IK, XK): there the
//! recipient static is configured up front with `set_rs` and folded into
//! the prologue hash before the first byte goes out. **XX never calls
//! `set_rs`** — there is nothing to pre-set. Instead each side passes its
//! own static *private* key to the `s` token at the moment it is sent
//! (`.s(my_static)`), and learns the peer's static *public* key as the
//! return value of the `s` token when it is *received* (`let (peer_pub, _)
//! = recv.s().await?`). That asymmetry — private key in on send, public
//! key out on receive — is the whole shape of XX in this API.
//!
//! # Why the `TcpStream` is the whole story
//!
//! The async driver takes ownership of any `tokio::io::AsyncRead +
//! AsyncWrite` and `.await`s each token directly against the wire: there
//! is no caller-sized scratch buffer for handshake messages. Here the
//! `Io` is a live `TcpStream`. The in-memory ("buffer") case is the same
//! code with an in-memory `Io` (e.g. a duplex pipe) substituted for the
//! socket — nothing else changes.

use hiss::noise::{P256, Transport, XX};
use hiss::provider::{EphemeralOnly, ProviderExt};

use rand::{SeedableRng, rngs::StdRng};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Bind an ephemeral localhost port and learn the address the OS chose.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Spawn the responder. It accepts one connection and drives the XX
    // handshake from the listening end, then echoes its half of the
    // transport exchange. Its final message reports the agreed session id
    // and the plaintext it decrypted, so `main` can cross-check both.
    let responder = tokio::spawn(responder(listener));

    // The initiator dials the responder over loopback TCP.
    let initiator = tokio::spawn(initiator(addr));

    // Join both halves; either side's error (handshake, I/O, or a failed
    // assert) surfaces here.
    let (init_sid, init_decrypted) = initiator.await??;
    let (resp_sid, resp_decrypted) = responder.await??;

    // Channel binding: a completed XX handshake yields the same session id
    // (the handshake hash) on both ends. If these differ, the peers did
    // not share a handshake transcript.
    assert_eq!(
        init_sid, resp_sid,
        "session ids must match (channel binding)"
    );

    println!("handshake complete");
    println!("session id (hex): {init_sid}");
    println!("responder decrypted: {resp_decrypted:?}");
    println!("initiator decrypted: {init_decrypted:?}");

    Ok(())
}

/// Drive the XX handshake and transport exchange as the **initiator**.
///
/// Returns `(session_id_hex, plaintext_we_decrypted_from_the_responder)`.
async fn initiator(addr: std::net::SocketAddr) -> Result<(String, String), BoxError> {
    // `StdRng` is `Send + Sync`, which the async provider surface and
    // `tokio::spawn` both require; `rand::rng()` (a `!Send` `ThreadRng`)
    // would not cross the task boundary. Seed it from OS entropy.
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    // Our long-term static identity. In XX this is *not* known to the
    // peer in advance; we will reveal it (encrypted) in msg3.
    let my_static = provider.generate::<P256>()?;

    // The `TcpStream` itself is the async `Io` the handshake drives.
    let stream = TcpStream::connect(addr).await?;

    // Begin XX as initiator. No `set_rs`: XX has no pre-known remote
    // static. The empty slice is the (here unused) prologue.
    let hs = XX::async_initiator(provider, &[], stream);

    // msg1  -> e          ephemeral only; the cipher is not yet keyed, so
    //                     these bytes go out in the clear.
    let hs = hs.e().await?;

    // msg2  <- e, ee, s, es
    //   Read the responder's ephemeral, mix the ee DH, then receive its
    //   static: the `s` token returns the peer's static *public* key,
    //   which es then binds via the responder-static DH.
    let (_their_e, recv) = hs.recv().e().await?;
    let recv = recv.ee().await?;
    let (_responder_static_pub, recv) = recv.s().await?;
    let hs = recv.es().await?;

    // msg3  -> s, se
    //   Send our own static (encrypted, authenticated by se). The final
    //   token transitions the handshake into the transport state.
    let transport = hs.s(my_static).await?.se().await?;
    let (mut transport, mut stream) = transport.into_parts();

    let session_id = transport.session_id().to_string();

    // Transport phase. Handshake messages were framed on the wire by the
    // driver; transport messages are plain buffers, so we add our own
    // 2-byte big-endian length prefix per record.
    let plaintext = b"hello from the XX initiator";
    let mut ciphertext = vec![0u8; plaintext.len() + Transport::<XX>::OVERHEAD];
    let n = transport.send(plaintext, &mut ciphertext)?;
    write_frame(&mut stream, &ciphertext[..n]).await?;

    // Receive the responder's reply and decrypt it.
    let frame = read_frame(&mut stream).await?;
    let mut decrypted = vec![0u8; frame.len()];
    let n = transport.receive(&frame, &mut decrypted)?;
    decrypted.truncate(n);

    Ok((session_id, String::from_utf8(decrypted)?))
}

/// Drive the XX handshake and transport exchange as the **responder**.
///
/// Returns `(session_id_hex, plaintext_we_decrypted_from_the_initiator)`.
async fn responder(listener: TcpListener) -> Result<(String, String), BoxError> {
    // `StdRng` rather than `rand::rng()`: see the initiator for why the
    // provider RNG must be `Send + Sync`.
    let mut provider = EphemeralOnly::new(StdRng::from_os_rng());

    // Our long-term static identity, revealed (encrypted) in msg2.
    let my_static = provider.generate::<P256>()?;

    let (stream, _peer) = listener.accept().await?;

    // Begin XX as responder. Like the initiator, no `set_rs`.
    let hs = XX::async_responder(provider, &[], stream);

    // msg1  -> e          read the initiator's ephemeral.
    let (_their_e, recv) = hs.recv().e().await?;

    // msg2  <- e, ee, s, es
    //   Send our ephemeral, mix ee, send our static (the `s` token takes
    //   our static *private* key and streams the encrypted public key),
    //   then es. This message starts in the clear (e) and is keyed from
    //   ee onward.
    let hs = recv.e().await?.ee().await?.s(my_static).await?.es().await?;

    // msg3  -> s, se
    //   Read the initiator's static: the `s` token returns its static
    //   *public* key. se finalizes the handshake into the transport state.
    let (_initiator_static_pub, recv) = hs.recv().s().await?;
    let transport = recv.se().await?;
    let (mut transport, mut stream) = transport.into_parts();

    let session_id = transport.session_id().to_string();

    // Transport phase. Receive the initiator's message first, then reply.
    let frame = read_frame(&mut stream).await?;
    let mut decrypted = vec![0u8; frame.len()];
    let n = transport.receive(&frame, &mut decrypted)?;
    decrypted.truncate(n);

    let reply = b"hello back from the XX responder";
    let mut ciphertext = vec![0u8; reply.len() + Transport::<XX>::OVERHEAD];
    let n = transport.send(reply, &mut ciphertext)?;
    write_frame(&mut stream, &ciphertext[..n]).await?;

    Ok((session_id, String::from_utf8(decrypted)?))
}

/// Write a single transport record with a 2-byte big-endian length prefix.
async fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), BoxError> {
    let len = u16::try_from(payload.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a single length-prefixed transport record.
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, BoxError> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}
