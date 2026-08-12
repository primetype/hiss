//! Noise handshake patterns.
//!
//! A pattern defines the pre-message knowledge and the sequence of
//! handshake messages. Every marker in this module is defined with the
//! [`noise!`](crate::noise!) macro, in the Noise specification's own
//! notation — the notation *is* the definition, and the type-level
//! [`Pattern`] encoding (the `Cons`/`Nil` message lists the compiler
//! checks) is generated from it.
//!
//! These built-ins are **suite-generic markers**: combine one with a
//! concrete suite through [`Noise<P, Cu, Ci, H>`](super::Noise). To get
//! a suite-pinned handshake with a generated sans-io state machine
//! (fixed-size messages, one method per handshake message), invoke
//! [`noise!`](crate::noise!) yourself, naming a suite — and note that
//! your pattern's *name* is part of the protocol identity, so a
//! handshake defined under your own name only completes against peers
//! speaking exactly that protocol.

use super::tokens::ContainsPsk;

/// A Noise handshake pattern.
///
/// Implementors encode the full message flow as associated types
/// built from [`Cons`](super::Cons)/[`Nil`](super::Nil) lists of
/// [`Message`](super::Message)s, making the handshake structure
/// available to the compiler at monomorphisation time.
///
/// Do not implement this by hand: define patterns with
/// [`noise!`](crate::noise!), which derives the encoding from the
/// specification notation and asserts Noise §7.3 validity at compile
/// time.
pub trait Pattern {
    /// Noise name component (e.g. `"IKpsk1"`).
    const NAME: &'static str;

    /// Number of handshake messages (excluding pre-messages).
    const NUM_MESSAGES: usize;

    /// Pre-message pattern — type-level list of
    /// [`Message`](super::Message)s describing knowledge held before
    /// the handshake begins.
    type PreMessages;

    /// Handshake message pattern — type-level list of
    /// [`Message`](super::Message)s describing the handshake flights.
    ///
    /// The `ContainsPsk` bound lets the crate derive the PSK modifier from
    /// the token list (`DerivedHasPsk`) rather than a hand-written constant
    /// that could drift out of sync with the tokens.
    type Messages: ContainsPsk;
}

hiss_macros::noise! {
    /// `N` — one-way pattern. The sender knows the recipient's static
    /// key. No sender authentication.
    ///
    /// Used for encrypting data at rest to a known public key (e.g.
    /// sealing per-pair PSKs to the device's own Secure Enclave key).
    /// With no `ee`, forward secrecy is **sender-side only**: the fresh
    /// per-write ephemeral protects a captured message against later
    /// compromise of the sender's keys, but the recipient's static
    /// private key still decrypts it.
    pub N {
        <- s
        ...
        -> e, es
    }
}

hiss_macros::noise! {
    /// `K` — one-way authenticated pattern. Both static keys are known
    /// before the handshake. The sender is authenticated via `ss`.
    ///
    /// Used for sealed envelopes between two peers who have already
    /// completed a trust ceremony — the message is confidential and
    /// sender-authenticated. With no `ee`, forward secrecy is
    /// **sender-side only**: the fresh per-write ephemeral protects a
    /// captured message against later compromise of the sender's keys,
    /// but the recipient's static private key still decrypts it.
    pub K {
        -> s
        <- s
        ...
        -> e, es, ss
    }
}

hiss_macros::noise! {
    /// `Kpsk0` — one-way authenticated pattern with PSK at position 0.
    /// Both static keys are known; the PSK is mixed before the ephemeral
    /// key, binding the entire message to the ceremony-established trust.
    ///
    /// With no `ee`, forward secrecy is **sender-side only**: the fresh
    /// per-write ephemeral protects a captured message against later
    /// compromise of the sender's keys, but the recipient's static
    /// private key **and** the PSK together still decrypt it.
    pub Kpsk0 {
        -> s
        <- s
        ...
        -> psk, e, es, ss
    }
}

hiss_macros::noise! {
    /// `IKpsk1` — the initiator knows the responder's static key and
    /// transmits their own static key encrypted in msg1. A PSK is
    /// mixed at the end of msg1.
    ///
    /// The initiator's identity is revealed to the responder during
    /// msg1 processing (after `es` DH), enabling per-pair PSK lookup
    /// before the `psk` token.
    pub IKpsk1 {
        <- s
        ...
        -> e, es, s, ss, psk
        <- e, ee, se
    }
}

hiss_macros::noise! {
    /// `IK` — interactive mutual authentication. The initiator knows the
    /// responder's static key up front and transmits its own static key,
    /// encrypted, in msg1; the responder authenticates in msg2.
    ///
    /// Identical to [`IKpsk1`] without the pre-shared key — full mutual
    /// authentication from raw static-key DH alone.
    pub IK {
        <- s
        ...
        -> e, es, s, ss
        <- e, ee, se
    }
}

hiss_macros::noise! {
    /// `NK` — interactive, responder-authenticated handshake. The
    /// initiator knows the responder's static key up front and is
    /// **anonymous** (it has no static key of its own); only the
    /// responder is authenticated, via the `es` DH that binds its static
    /// key.
    ///
    /// Like [`IK`] minus the initiator's static key — confidentiality to
    /// a known recipient plus a fresh responder ephemeral, without
    /// initiator authentication.
    pub NK {
        <- s
        ...
        -> e, es
        <- e, ee
    }
}

hiss_macros::noise! {
    /// `IX` — interactive mutual authentication with **no pre-messages**:
    /// neither party knows the other's static key up front. Both transmit
    /// their static keys *during* the handshake (as `s` tokens).
    ///
    /// Because the initiator's static is sent in msg1 **before any DH**, it
    /// travels **in the clear** — exposed to a passive eavesdropper. The
    /// responder's static is sent in msg2 *after* `ee` keys the cipher, so
    /// it is encrypted. Authentication is mutual: the initiator is
    /// authenticated to the responder via `se`, the responder to the
    /// initiator via `es`.
    ///
    /// Unlike [`IK`], there is no pre-known static on either side — IX
    /// trades the initiator's identity privacy for not needing the
    /// responder's static key in advance.
    pub IX {
        -> e, s
        <- e, ee, se, s, es
    }
}

hiss_macros::noise! {
    /// `XK` — interactive mutual authentication over **three messages**
    /// with strong **initiator-identity privacy**. The initiator knows the
    /// responder's static key up front (pre-message `<- s`) and
    /// authenticates the responder early via `es`. The initiator's own
    /// static key is transmitted **encrypted in msg3** (after `ee` has
    /// keyed the cipher), so it is hidden from a passive eavesdropper, and
    /// is authenticated via `se`.
    ///
    /// Unlike [`IK`] (where the initiator's static rides in msg1), XK defers
    /// the initiator's static to a third flight, after both ephemerals are
    /// mixed — giving the initiator's identity full forward-secret
    /// confidentiality at the cost of an extra round trip.
    pub XK {
        <- s
        ...
        -> e, es
        <- e, ee
        -> s, se
    }
}

hiss_macros::noise! {
    /// `NN` — interactive handshake with **no static keys** and **no
    /// pre-messages**: both parties are anonymous. The only key material
    /// exchanged is a fresh ephemeral from each side.
    ///
    /// `NN` provides **no authentication** of either party — it is
    /// vulnerable to an active man-in-the-middle. Confidentiality holds
    /// only against a *passive* eavesdropper. Once `ee` mixes both
    /// ephemerals, the session has **full forward secrecy**.
    ///
    /// msg1 (`-> e`) never keys the cipher, so it is just the bare
    /// ephemeral (no payload tag).
    pub NN {
        -> e
        <- e, ee
    }
}

hiss_macros::noise! {
    /// `XX` — the canonical interactive, mutually-authenticated handshake
    /// over **three messages** with **no pre-messages**. Both parties
    /// transmit their static keys *during* the handshake, and both do so
    /// **encrypted** (after `ee` keys the cipher), so **both identities are
    /// hidden from a passive eavesdropper**.
    ///
    /// The initiator is authenticated to the responder via `se`; the
    /// responder to the initiator via `es`. Neither side needs to pre-know
    /// the other's static key — unlike [`XK`] (which pre-knows the
    /// responder's static via a pre-message), XX learns both statics on
    /// the wire. Once `ee` mixes both ephemerals, the session has **full
    /// forward secrecy**.
    ///
    /// **Authentication is conditional:** completing XX proves the peer holds a
    /// static private key, not that you trust it — check `remote_static()`
    /// against your own trust policy before acting on the channel.
    ///
    /// msg1 (`-> e`) never keys the cipher, so it is the bare ephemeral
    /// with no payload tag; msg3 (`-> s, se`) sends the initiator's static
    /// encrypted.
    pub XX {
        -> e
        <- e, ee, s, es
        -> s, se
    }
}

hiss_macros::noise! {
    /// `X` — one-way authenticated pattern with sender-identity hiding. The
    /// sender knows the recipient's static key up front (pre-message `<- s`)
    /// and transmits its **own** static key, encrypted, within the single
    /// message; the sender is authenticated via `ss`.
    ///
    /// Like [`K`] it is a one-shot seal to a known recipient, but where `K`
    /// pre-shares *both* statics, `X` pre-shares only the recipient's and
    /// carries the sender's static **encrypted in-band** (after `es` keys the
    /// cipher), so the sender's identity is hidden from a passive
    /// eavesdropper. Its single message is the same token sequence as
    /// [`IK`]'s msg1, without the responder's reply — confidential and
    /// sender-authenticated. With no `ee`, forward secrecy is
    /// **sender-side only**: the fresh per-write ephemeral protects a
    /// captured message against later compromise of the sender's keys,
    /// but the recipient's static private key still decrypts it.
    pub X {
        <- s
        ...
        -> e, es, s, ss
    }
}

hiss_macros::noise! {
    /// `NX` — interactive, **responder-authenticated** handshake with no
    /// pre-messages. The initiator is **anonymous** (it has no static key);
    /// the responder transmits its static key in msg2 and is authenticated
    /// via `es`.
    ///
    /// The responder's static is sent *after* `ee` keys the cipher, so it is
    /// hidden from a passive eavesdropper — but **any anonymous initiator can
    /// ask for it**, since nothing gates the handshake. Where [`XX`] lets the
    /// responder learn who is asking before revealing itself, NX has no msg3
    /// and therefore no initiator identity at all. Once `ee` mixes both
    /// ephemerals the session has **full forward secrecy**.
    ///
    /// It is [`XX`] without msg3: pick it when the initiator genuinely has no
    /// identity to offer and the responder is content to identify itself to
    /// anyone.
    pub NX {
        -> e
        <- e, ee, s, es
    }
}

hiss_macros::noise! {
    /// `XN` — interactive, **initiator-authenticated** handshake over three
    /// messages, with no pre-messages. The responder is **anonymous** (it has
    /// no static key); the initiator transmits its static key in msg3 and is
    /// authenticated via `se`.
    ///
    /// The initiator's static is sent *after* `ee` keys the cipher, so it is
    /// hidden from a passive eavesdropper — but it is **sent to a responder
    /// that was never authenticated**, so completing XN tells you nothing
    /// about who received your identity. An active man-in-the-middle can
    /// impersonate the responder outright.
    ///
    /// It is [`XX`] without the responder's static — the mirror image of
    /// [`NX`], paying an extra round trip to put the identity on the
    /// initiator's side.
    pub XN {
        -> e
        <- e, ee
        -> s, se
    }
}

hiss_macros::noise! {
    /// `KN` — interactive handshake whose initiator's static key is
    /// **pre-shared** (`-> s`) and whose responder is **anonymous**. The
    /// initiator is authenticated via `se`; **the responder is never
    /// authenticated**.
    ///
    /// Nothing identifying travels on the wire, but pre-shared is not the
    /// same as private: an **active** attacker who impersonates the initiator
    /// and later obtains a candidate for the initiator's *private* key can
    /// confirm the guess.
    ///
    /// Like [`IN`] but with the initiator's static arranged in advance
    /// instead of sent in the clear. As with every pattern whose name starts
    /// with `K` or `I`, the responder has only **weak** forward secrecy for
    /// the transport messages it sends until it receives one from the
    /// initiator.
    pub KN {
        -> s
        ...
        -> e
        <- e, ee, se
    }
}

hiss_macros::noise! {
    /// `KK` — interactive mutual authentication with **both** static keys
    /// pre-shared, and the only built-in interactive pattern offering
    /// **zero-RTT**: msg1's payload is already encrypted.
    ///
    /// That zero-RTT payload carries two caveats, and both matter. Its sender
    /// authentication rests on the static–static `ss` DH, so it is
    /// **vulnerable to key-compromise impersonation** — an attacker holding
    /// the *responder's* private key can forge a msg1 that appears to come
    /// from the initiator. And msg1 **can be replayed**: no responder
    /// ephemeral contributes to it. Both properties harden once msg2 lands.
    ///
    /// Nothing identifying is transmitted, but a **passive** attacker can
    /// test candidate (responder private key, initiator public key) pairs
    /// against a recorded handshake. Like [`K`] it pre-shares both statics;
    /// unlike `K` the responder replies, so the session reaches full forward
    /// secrecy once `ee` is mixed. The `K`/`I` responder caveat applies until
    /// the responder receives a transport message.
    pub KK {
        -> s
        <- s
        ...
        -> e, es, ss
        <- e, ee, se
    }
}

hiss_macros::noise! {
    /// `KX` — interactive mutual authentication where the initiator's static
    /// key is **pre-shared** (`-> s`) and the responder's is transmitted,
    /// encrypted, in msg2. The initiator is authenticated via `se`, the
    /// responder via `es`.
    ///
    /// The responder's identity has only **weak** forward secrecy: the
    /// initiator's alleged ephemeral may have been forged by an active
    /// attacker, so a later compromise of the responder's static key can
    /// expose which responder answered. The initiator's own key, being
    /// pre-shared, carries the same active-attacker caveat as [`KN`].
    ///
    /// It is [`IX`] with the initiator's static arranged in advance rather
    /// than sent in the clear. The `K`/`I` responder caveat applies until the
    /// responder receives a transport message.
    pub KX {
        -> s
        ...
        -> e
        <- e, ee, se, s, es
    }
}

hiss_macros::noise! {
    /// `IN` — interactive handshake with no pre-messages whose initiator
    /// transmits its static key in msg1 and whose responder is **anonymous**.
    /// The initiator is authenticated via `se`; the responder never is.
    ///
    /// **The initiator's static key travels in msg1 in the clear**, before
    /// any DH keys the cipher — so a *passive* observer learns the
    /// initiator's identity outright. That is the weakest identity exposure
    /// of any pattern this crate ships; prefer [`KN`] (pre-share it) or
    /// [`XN`] (send it encrypted in msg3) whenever the initiator's identity
    /// is worth hiding.
    ///
    /// It is [`IX`] without the responder's static. The `K`/`I` responder
    /// caveat applies until the responder receives a transport message.
    pub IN {
        -> e, s
        <- e, ee, se
    }
}
