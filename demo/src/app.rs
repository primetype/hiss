//! Leptos UI for the hiss browser playground — a guided walkthrough.
//!
//! Top to bottom: choose a **curve** and see **both participants** (initiator +
//! responder, each a persistent per-curve static key, regenerated together);
//! choose a **pattern** and read its properties; **step through the handshake**
//! one message at a time (the initiator activates first, then the responder),
//! with each message explaining its tokens and what they add; then **chat** over
//! the established session, picking who sends, newest message on top.
//!
//! All crypto runs in [`crate::noise`]. Styling follows the project house
//! aesthetic (`.planning/html/styles.css`): austere, monochrome, monospace,
//! one cold cyan accent (plus a reserved neon-orange for the safety warning).

use leptos::prelude::*;

use crate::noise::{
    self, ChatLine, CurveKind, Direction, Established, Identity, LiveSession, PatternKind, Peer,
    WireMessage,
};

/// The live session handle: a non-`Send`/`Clone` boxed trait object, so it
/// lives in a thread-local signal (the browser is single-threaded anyway).
type SessionSig = RwSignal<Option<Box<dyn LiveSession>>, LocalStorage>;

/// Clone-able metadata about an established session (everything except the live
/// transports, which stay in [`SessionSig`]).
#[derive(Clone)]
struct SessionMeta {
    protocol_name: String,
    session_id: String,
    session_ids_match: bool,
    /// The handshake messages, in order (for the stepped reveal).
    wire: Vec<WireMessage>,
    one_way: bool,
}

// Shared class strings (the house "panel" / "section" / control treatments).
const PANEL: &str = "rounded-lg border border-line bg-gradient-to-b from-panel to-panel-2 p-5";
const SECTION_TITLE: &str =
    "text-xs font-semibold uppercase tracking-[0.2em] text-silver-faint border-b border-line-soft pb-2";
const FIELD_LABEL: &str = "text-[11px] font-semibold uppercase tracking-[0.18em] text-silver-faint";
const SELECT: &str =
    "rounded border border-line bg-ink px-3 py-2 text-sm font-mono text-silver focus:border-cyan focus:outline-none";
const INPUT: &str =
    "rounded border border-line bg-ink px-3 py-2 text-sm text-silver focus:border-cyan focus:outline-none";
const BTN_ACCENT: &str =
    "rounded border border-cyan-dim px-4 py-2 text-sm text-cyan transition-colors hover:border-cyan hover:bg-cyan/5";
const BTN_GHOST: &str =
    "shrink-0 rounded border border-line px-3 py-1.5 text-xs text-silver-dim transition-colors hover:border-silver-faint hover:text-silver";

// ── localStorage helpers ─────────────────────────────────────────────

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn storage_get(key: &str) -> Option<String> {
    storage()?.get_item(key).ok().flatten()
}

fn storage_set(key: &str, value: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(key, value);
    }
}

fn peer_slug(peer: Peer) -> &'static str {
    match peer {
        Peer::Initiator => "initiator",
        Peer::Responder => "responder",
    }
}

/// Per-peer, per-curve `localStorage` key for a persisted identity.
fn identity_key(peer: Peer, curve: CurveKind) -> String {
    format!("hiss-demo-id-{}-{}-v1", peer_slug(peer), curve.name())
}

/// Load the persisted identity for `peer`/`curve`, or mint and persist one.
fn load_identity(peer: Peer, curve: CurveKind) -> Identity {
    let key = identity_key(peer, curve);
    if let Some(hex) = storage_get(&key) {
        if let Ok(id) = Identity::from_secret_hex(curve, &hex) {
            return id;
        }
    }
    let id = Identity::generate(curve);
    storage_set(&key, &id.secret_hex());
    id
}

/// Group raw bytes as space-separated hex (`a3 f1 09 …`).
fn hex_grouped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The sending peer of a message token line (e.g. `"-> e, es"` → initiator).
fn sender_of_line(line: &str) -> Peer {
    if line.starts_with("<- ") {
        Peer::Responder
    } else {
        Peer::Initiator
    }
}

/// The sending peer of a computed handshake message.
fn sender_of(dir: Direction) -> Peer {
    match dir {
        Direction::InitiatorToResponder => Peer::Initiator,
        Direction::ResponderToInitiator => Peer::Responder,
    }
}

/// Split a token line (`"-> e, es"`) into its individual tokens (`["e", "es"]`).
fn split_tokens(line: &str) -> Vec<String> {
    let rest = line
        .strip_prefix("-> ")
        .or_else(|| line.strip_prefix("<- "))
        .unwrap_or(line);
    rest.split(", ").map(str::to_string).collect()
}

/// What a Noise token *is* (its semantics). Whether the bytes are encrypted is
/// shown separately per field, since it depends on the key state at that point.
fn token_help(token: &str) -> &'static str {
    match token {
        "e" => "fresh ephemeral key pair; its public key goes on the wire — the peer needs it to compute DH",
        "s" => "this peer's static (long-term) public key — its identity",
        "ee" => "DH(initiator ephemeral, responder ephemeral) — no bytes on the wire; mixed into the keys",
        "es" => "DH(initiator ephemeral, responder static) — no bytes on the wire; mixed into the keys",
        "se" => "DH(initiator static, responder ephemeral) — no bytes on the wire; mixed into the keys",
        "ss" => "DH(initiator static, responder static) — no bytes on the wire; mixed into the keys",
        "psk" => "pre-shared symmetric key — no bytes on the wire; mixed into the keys",
        _ => "",
    }
}

/// The on-the-wire public-key length for a curve (X25519 32 B, P-256 65 B SEC1,
/// X448 56 B). Used to compute the cleartext/encrypted byte split.
fn public_len(curve: CurveKind) -> usize {
    match curve {
        CurveKind::X25519 => 32,
        CurveKind::P256 => 65,
        CurveKind::X448 => 56,
    }
}

/// Encryption status of one message field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CryptoStatus {
    /// On the wire, unencrypted.
    Clear,
    /// On the wire, AEAD-encrypted (a key has been established).
    Encrypted,
    /// A DH or PSK token — no bytes on the wire; mixes into the keys.
    KeyMix,
}

#[derive(Clone)]
struct Field {
    token: String,
    status: CryptoStatus,
}

/// The per-message encryption breakdown for the stepped view.
#[derive(Clone)]
struct MsgCrypto {
    /// Leading cleartext byte count (the ephemeral, and any pre-key static).
    clear_len: usize,
    /// Trailing encrypted byte count (encrypted statics + the payload tag).
    enc_len: usize,
    fields: Vec<Field>,
    /// True if this message is where the first key gets established.
    establishes_key: bool,
}

/// Walk a pattern's messages left-to-right, tracking when a key exists, to
/// classify every field as cleartext / encrypted and size the byte split.
/// Mirrors hiss: `e` is `mix_hash` (always cleartext); `s` and the trailing
/// empty payload go through `encrypt_and_hash` (encrypted once a key exists);
/// `ee/es/se/ss/psk` (and, under PSK, `e`) establish the key.
fn analyze(pattern: PatternKind, curve: CurveKind) -> Vec<MsgCrypto> {
    let is_psk = pattern.needs_psk();
    let plen = public_len(curve);
    let mut has_key = false;
    pattern
        .message_token_lines()
        .into_iter()
        .map(|line| {
            let before = has_key;
            let mut clear_len = 0usize;
            let mut enc_len = 0usize;
            let mut fields = Vec::new();
            for t in split_tokens(line) {
                let status = match t.as_str() {
                    "e" => {
                        clear_len += plen; // mix_hash → always cleartext
                        if is_psk {
                            has_key = true; // PSK: e also mixes into the key
                        }
                        CryptoStatus::Clear
                    }
                    "s" if has_key => {
                        enc_len += plen + 16; // encrypt_and_hash → ciphertext + tag
                        CryptoStatus::Encrypted
                    }
                    "s" => {
                        clear_len += plen; // no key yet → cleartext static
                        CryptoStatus::Clear
                    }
                    "ee" | "es" | "se" | "ss" | "psk" => {
                        has_key = true;
                        CryptoStatus::KeyMix
                    }
                    _ => CryptoStatus::Clear,
                };
                fields.push(Field { token: t, status });
            }
            if has_key {
                enc_len += 16; // trailing encrypt_and_hash(empty payload) tag
            }
            MsgCrypto {
                clear_len,
                enc_len,
                fields,
                establishes_key: !before && has_key,
            }
        })
        .collect()
}

/// Label + colour class for a field's encryption status.
fn status_chip(status: CryptoStatus) -> (&'static str, &'static str) {
    match status {
        CryptoStatus::Clear => ("in the clear", "text-partial"),
        CryptoStatus::Encrypted => ("🔒 encrypted", "text-done"),
        CryptoStatus::KeyMix => ("key mix · no wire bytes", "text-cyan"),
    }
}

// ── handshake / chat actions ─────────────────────────────────────────

/// Tear down any handshake-in-progress / session and clear the conversation.
fn reset_handshake(
    session: SessionSig,
    meta: RwSignal<Option<SessionMeta>>,
    step: RwSignal<usize>,
    chat: RwSignal<Vec<ChatLine>>,
    draft: RwSignal<String>,
    sender: RwSignal<Peer>,
    error: RwSignal<Option<String>>,
) {
    session.set(None);
    meta.set(None);
    step.set(0);
    chat.set(Vec::new());
    draft.set(String::new());
    sender.set(Peer::Initiator);
    error.set(None);
}

/// Advance the stepped handshake: the first click computes the whole handshake
/// (both peers, all ephemerals) and reveals message 1; later clicks reveal the
/// next message.
#[allow(clippy::too_many_arguments)]
fn handshake_advance(
    pattern: RwSignal<PatternKind>,
    curve: RwSignal<CurveKind>,
    initiator: RwSignal<Identity>,
    responder: RwSignal<Identity>,
    session: SessionSig,
    meta: RwSignal<Option<SessionMeta>>,
    step: RwSignal<usize>,
    error: RwSignal<Option<String>>,
) {
    if meta.with(Option::is_none) {
        match noise::establish(
            pattern.get(),
            curve.get(),
            &initiator.get(),
            &responder.get(),
        ) {
            Ok(Established {
                protocol_name,
                wire,
                session_id,
                session_ids_match,
                session: live,
            }) => {
                session.set(Some(live));
                meta.set(Some(SessionMeta {
                    protocol_name,
                    session_id,
                    session_ids_match,
                    wire,
                    one_way: pattern.get().is_one_way(),
                }));
                step.set(1);
                error.set(None);
            }
            Err(e) => error.set(Some(e.to_string())),
        }
    } else {
        step.update(|s| *s += 1);
    }
}

/// Encrypt `draft` as `from`, deliver to the other peer, append to the log.
fn send_message(
    from: Peer,
    session: SessionSig,
    draft: RwSignal<String>,
    chat: RwSignal<Vec<ChatLine>>,
    error: RwSignal<Option<String>>,
) {
    let text = draft.get();
    if text.trim().is_empty() {
        return;
    }
    session.update(|opt| {
        if let Some(s) = opt.as_mut() {
            match s.send(from, &text) {
                Ok(line) => chat.update(|log| log.push(line)),
                Err(e) => error.set(Some(e.to_string())),
            }
        }
    });
    draft.set(String::new());
}

// ── Root component ───────────────────────────────────────────────────

#[component]
pub fn App() -> impl IntoView {
    let curve = RwSignal::new(CurveKind::X25519);
    let pattern = RwSignal::new(PatternKind::Xx);
    let initiator = RwSignal::new(load_identity(Peer::Initiator, CurveKind::X25519));
    let responder = RwSignal::new(load_identity(Peer::Responder, CurveKind::X25519));
    let session: SessionSig = RwSignal::new_local(None);
    let meta = RwSignal::new(None::<SessionMeta>);
    let step = RwSignal::new(0usize);
    let chat = RwSignal::new(Vec::<ChatLine>::new());
    let draft = RwSignal::new(String::new());
    let sender = RwSignal::new(Peer::Initiator);
    let error = RwSignal::new(None::<String>);

    // Keep both identities in sync with the selected curve.
    Effect::new(move |_| {
        let c = curve.get();
        initiator.set(load_identity(Peer::Initiator, c));
        responder.set(load_identity(Peer::Responder, c));
    });

    let regenerate = move |_| {
        let c = curve.get();
        let i = Identity::generate(c);
        storage_set(&identity_key(Peer::Initiator, c), &i.secret_hex());
        initiator.set(i);
        let r = Identity::generate(c);
        storage_set(&identity_key(Peer::Responder, c), &r.secret_hex());
        responder.set(r);
        reset_handshake(session, meta, step, chat, draft, sender, error);
    };

    let proto_name = move || noise::protocol_name(pattern.get(), curve.get());

    // The stepped handshake message cards (reactive on pattern/curve/step/meta).
    let cards = move || {
        let p = pattern.get();
        let is_psk = p.needs_psk();
        let crypto = analyze(p, curve.get());
        let lines = p.message_token_lines();
        let count = lines.len();
        let cur = step.get();
        (0..count)
            .map(|i| {
                let line = lines[i];
                let mc = crypto[i].clone();
                let is_sent = i < cur;
                let is_active = i == cur && cur < count;
                // Sent messages are read from the computed handshake record;
                // not-yet-sent ones are shown from the pattern's plan.
                let sent = if is_sent {
                    meta.with(|m| m.as_ref().and_then(|m| m.wire.get(i)).cloned())
                } else {
                    None
                };
                let from = match &sent {
                    Some(w) => sender_of(w.direction),
                    None => sender_of_line(line),
                };
                let n = match &sent {
                    Some(w) => w.index + 1,
                    None => i + 1,
                };
                let shown_bytes = sent.map(|w| w.bytes);
                let (accent, who_color, who) = peer_style(from);
                let recipient = from.other().label();
                let frame = if is_active {
                    "border-cyan"
                } else if is_sent {
                    "border-line"
                } else {
                    "border-line-soft opacity-60"
                };
                let (status, status_color) = if is_sent {
                    ("sent", "text-done")
                } else if is_active {
                    ("ready to send", "text-cyan")
                } else {
                    ("waiting", "text-silver-faint")
                };
                let (badge, badge_color) = if mc.enc_len == 0 {
                    ("cleartext", "text-partial")
                } else if mc.clear_len == 0 {
                    ("encrypted", "text-done")
                } else {
                    ("ephemeral in the clear · rest encrypted", "text-silver-dim")
                };
                let fields = mc.fields.clone();
                let clear_len = mc.clear_len;
                let enc_len = mc.enc_len;
                view! {
                    <li class=format!("rounded border border-l-2 bg-ink/40 p-3 {accent} {frame}")>
                        <div class="flex items-center justify-between gap-3 text-xs">
                            <span class=who_color>"message " {n} " · " {who} " → " {recipient}</span>
                            <span class=status_color>{status}</span>
                        </div>
                        <div class="mt-1 flex flex-wrap items-center gap-x-2 text-[11px]">
                            <span class="font-mono text-silver-faint">{line}</span>
                            <span class=format!("uppercase tracking-wider {badge_color}")>{badge}</span>
                        </div>
                        {mc.establishes_key.then(|| view! {
                            <p class="mt-1 text-[11px] text-cyan">
                                "🔑 keys established here — fields after this point are encrypted"
                            </p>
                        })}
                        <ul class="mt-2 space-y-1 text-[11px] text-silver-dim">
                            {fields
                                .into_iter()
                                .map(|f| {
                                    let help = token_help(&f.token);
                                    let (chip, chip_color) = if f.token == "e" {
                                        let label = if is_psk {
                                            "in the clear · also mixed into the key"
                                        } else {
                                            "in the clear"
                                        };
                                        (label, "text-partial")
                                    } else {
                                        status_chip(f.status)
                                    };
                                    view! {
                                        <li class="flex flex-wrap items-baseline gap-x-1.5">
                                            <span class="text-silver">{f.token}</span>
                                            <span class=format!("text-[10px] {chip_color}")>{chip}</span>
                                            <span>"— " {help}</span>
                                        </li>
                                    }
                                })
                                .collect_view()}
                        </ul>
                        {shown_bytes.map(|b| {
                            if clear_len > 0 && enc_len > 0 && clear_len + enc_len == b.len() {
                                let (clear, enc) = b.split_at(clear_len);
                                view! {
                                    <code class="mt-2 block max-h-24 overflow-y-auto break-words text-[11px]">
                                        <span class="text-partial">{hex_grouped(clear)}</span>
                                        " "
                                        <span class="text-done">{hex_grouped(enc)}</span>
                                    </code>
                                }
                                .into_any()
                            } else {
                                let color = if enc_len == 0 { "text-partial" } else { "text-done" };
                                view! {
                                    <code class=format!("mt-2 block max-h-24 overflow-y-auto break-words text-[11px] {color}")>
                                        {hex_grouped(&b)}
                                    </code>
                                }
                                .into_any()
                            }
                        })}
                        {is_active.then(|| view! {
                            <button
                                class=format!("{BTN_ACCENT} mt-3")
                                on:click=move |_| handshake_advance(
                                    pattern, curve, initiator, responder, session, meta, step, error,
                                )
                            >
                                "Send message " {n} " as " {who}
                            </button>
                        })}
                    </li>
                }
            })
            .collect_view()
    };

    // The "session established" summary, shown once every message is sent.
    let established = move || {
        let cur = step.get();
        meta.with(|m| {
            m.as_ref().filter(|m| cur >= m.wire.len()).map(|m| {
                let matched = m.session_ids_match;
                view! {
                    <div class="space-y-1 rounded border border-line-soft bg-ink/40 p-3">
                        <div class=FIELD_LABEL>"Session established"</div>
                        <p class="text-xs text-silver-faint">{m.protocol_name.clone()}</p>
                        <div class="pt-1 text-[10px] uppercase tracking-[0.18em] text-silver-faint">"Session ID"</div>
                        <code class="block break-all text-sm text-cyan">{m.session_id.clone()}</code>
                        <div class=if matched {
                            "flex items-center gap-2 text-xs text-done"
                        } else {
                            "flex items-center gap-2 text-xs text-blocked"
                        }>
                            <span class=if matched {
                                "inline-block h-1.5 w-1.5 rounded-full bg-done shadow-[0_0_8px_#6fcf97]"
                            } else {
                                "inline-block h-1.5 w-1.5 rounded-full bg-blocked"
                            }></span>
                            {if matched {
                                "both peers derived the same id"
                            } else {
                                "session id mismatch"
                            }}
                        </div>
                    </div>
                }
            })
        })
    };

    // The chat box, shown once the handshake is complete.
    let chat_box = move || {
        let complete = meta.with(|m| m.as_ref().is_some_and(|m| step.get() >= m.wire.len()));
        if !complete {
            return None;
        }
        let one_way = meta.with(|m| m.as_ref().is_some_and(|m| m.one_way));
        Some(view! {
            <section class=format!("{PANEL} space-y-3")>
                <div class=SECTION_TITLE>"Conversation"</div>
                <div class="flex items-center gap-2 text-xs">
                    <span class="text-silver-faint">"Send as"</span>
                    <button
                        class=move || sender_btn(sender.get() == Peer::Initiator)
                        on:click=move |_| sender.set(Peer::Initiator)
                    >
                        "Initiator"
                    </button>
                    {(!one_way).then(|| view! {
                        <button
                            class=move || sender_btn(sender.get() == Peer::Responder)
                            on:click=move |_| sender.set(Peer::Responder)
                        >
                            "Responder"
                        </button>
                    })}
                </div>
                <div class="flex items-center gap-2">
                    <input
                        class=format!("{INPUT} flex-1")
                        placeholder="Type a message…"
                        prop:value=move || draft.get()
                        on:input:target=move |ev| draft.set(ev.target().value())
                        on:keydown=move |ev: web_sys::KeyboardEvent| {
                            if ev.key() == "Enter" {
                                send_message(sender.get(), session, draft, chat, error);
                            }
                        }
                    />
                    <button
                        class=BTN_ACCENT
                        on:click=move |_| send_message(sender.get(), session, draft, chat, error)
                    >
                        "Send"
                    </button>
                </div>
                <div class="max-h-80 space-y-2 overflow-y-auto">
                    {move || {
                        let lines = chat.get();
                        if lines.is_empty() {
                            view! {
                                <p class="text-xs italic text-silver-faint">
                                    "No messages yet — newest will appear here, on top."
                                </p>
                            }
                            .into_any()
                        } else {
                            lines
                                .into_iter()
                                .rev()
                                .map(|line| view! { <ChatBubble line=line /> })
                                .collect_view()
                                .into_any()
                        }
                    }}
                </div>
            </section>
        })
    };

    view! {
        <div class="mx-auto max-w-3xl px-6 pb-24">
            <header class="pt-12 space-y-3">
                <div class="flex items-baseline gap-3">
                    <h1 class="text-5xl font-semibold tracking-[0.14em] text-silver">"hiss"</h1>
                    <span class="text-cyan text-xs tracking-[0.35em] uppercase">"static noise"</span>
                </div>
                <p class="max-w-2xl text-sm leading-relaxed text-silver-dim">
                    "A guided Noise handshake from the "
                    <code class="text-cyan">"hiss"</code>
                    " crate, compiled to WebAssembly. Set up two peers, step through the handshake "
                    "message by message, then chat over the encrypted channel — all in this page."
                </p>
            </header>

            <div class="static-band my-7"></div>

            <div class="space-y-6">
                <aside class="rounded-lg border border-warn/60 bg-warn/5 px-4 py-3 shadow-[0_0_20px_rgba(255,122,24,0.15)]">
                    <div class="flex items-start gap-3">
                        <span class="text-lg leading-none text-warn">"⚠"</span>
                        <div class="space-y-1">
                            <div class="text-xs font-semibold uppercase tracking-[0.2em] text-warn">
                                "Demo only — not secure"
                            </div>
                            <p class="text-xs leading-relaxed text-silver-dim">
                                "A playground, nothing more. Both identity keys are generated in your browser and "
                                "stored " <span class="text-silver">"unencrypted"</span>
                                " in localStorage — any script on this page can read them. Do not use this for "
                                "production, real identities, or sensitive data."
                            </p>
                        </div>
                    </div>
                </aside>

                // ── 1. curve + both participants ──────────────────────
                <section class=format!("{PANEL} space-y-4")>
                    <div class="flex items-end justify-between gap-4">
                        <label class="flex flex-col gap-1.5">
                            <span class=FIELD_LABEL>"Curve"</span>
                            <select
                                class=SELECT
                                prop:value=move || curve.get().name()
                                on:change:target=move |ev| {
                                    if let Some(c) = CurveKind::from_name(&ev.target().value()) {
                                        curve.set(c);
                                        reset_handshake(session, meta, step, chat, draft, sender, error);
                                    }
                                }
                            >
                                {CurveKind::ALL
                                    .into_iter()
                                    .map(|c| view! { <option value=c.name()>{c.name()}</option> })
                                    .collect_view()}
                            </select>
                        </label>
                        <button class=BTN_GHOST on:click=regenerate>"Regenerate both"</button>
                    </div>
                    <p class="text-[11px] text-silver-faint">{move || curve.get().description()}</p>

                    <div class="grid gap-3 sm:grid-cols-2">
                        <Participant
                            role=Peer::Initiator
                            fingerprint=Signal::derive(move || fingerprint_of(initiator))
                            uses_static=Signal::derive(move || pattern.get().initiator_has_static())
                        />
                        <Participant
                            role=Peer::Responder
                            fingerprint=Signal::derive(move || fingerprint_of(responder))
                            uses_static=Signal::derive(move || pattern.get().responder_has_static())
                        />
                    </div>
                </section>

                // ── 2. pattern + explanation ──────────────────────────
                <section class=format!("{PANEL} space-y-4")>
                    <label class="flex flex-col gap-1.5">
                        <span class=FIELD_LABEL>"Handshake pattern"</span>
                        <select
                            class=SELECT
                            prop:value=move || pattern.get().name()
                            on:change:target=move |ev| {
                                if let Some(p) = PatternKind::from_name(&ev.target().value()) {
                                    pattern.set(p);
                                    reset_handshake(session, meta, step, chat, draft, sender, error);
                                }
                            }
                        >
                            {PatternKind::ALL
                                .into_iter()
                                .map(|p| view! { <option value=p.name()>{p.name()}</option> })
                                .collect_view()}
                        </select>
                    </label>
                    <code class="block break-all text-sm text-cyan">{proto_name}</code>
                    <PatternInfo pattern=pattern.into() />
                </section>

                {move || error.get().map(|e| view! {
                    <p class="rounded border border-blocked/40 bg-blocked/5 px-4 py-3 text-sm text-blocked">
                        {e}
                    </p>
                })}

                // ── 3. stepped handshake ──────────────────────────────
                <section class=format!("{PANEL} space-y-3")>
                    <div class=SECTION_TITLE>"Handshake"</div>
                    <p class="text-xs text-silver-dim">
                        "Send each message in turn — the initiator goes first. Each card shows what its "
                        "tokens add and whether each field is "
                        <span class="text-partial">"in the clear"</span>
                        " or "
                        <span class="text-done">"encrypted"</span>
                        "; the raw bytes (coloured the same way) appear once sent."
                    </p>
                    <ol class="space-y-2">{cards}</ol>
                    {established}
                </section>

                // ── 4. chat ───────────────────────────────────────────
                {chat_box}
            </div>

            <footer class="mt-12 flex flex-wrap justify-between gap-2 border-t border-line-soft pt-4 text-[11px] text-silver-faint">
                <span>"Demo only — not for production or sensitive data."</span>
                <span class="tracking-[0.25em] uppercase">"hiss · static noise"</span>
            </footer>
        </div>
    }
}

// ── helpers used by the view ─────────────────────────────────────────

fn fingerprint_of(identity: RwSignal<Identity>) -> String {
    identity
        .get()
        .public_fingerprint()
        .unwrap_or_else(|_| "unavailable".to_string())
}

/// Per-peer styling: (left-accent border class, text colour class, label).
fn peer_style(peer: Peer) -> (&'static str, &'static str, &'static str) {
    match peer {
        Peer::Initiator => ("border-l-cyan-dim", "text-cyan", "Initiator"),
        Peer::Responder => ("border-l-silver-faint", "text-silver-dim", "Responder"),
    }
}

fn sender_btn(active: bool) -> &'static str {
    if active {
        "rounded border border-cyan-dim bg-cyan/10 px-3 py-1 text-cyan"
    } else {
        "rounded border border-line px-3 py-1 text-silver-dim transition-colors hover:border-silver-faint"
    }
}

// ── small components ─────────────────────────────────────────────────

#[component]
fn Participant(
    role: Peer,
    fingerprint: Signal<String>,
    uses_static: Signal<bool>,
) -> impl IntoView {
    let (accent, color, label) = peer_style(role);
    view! {
        <div class=format!("space-y-1 rounded border border-line border-l-2 bg-ink/50 p-3 {accent}")>
            <div class=format!("text-[11px] uppercase tracking-[0.18em] {color}")>{label}</div>
            <code class="block break-all text-xs text-silver-dim">{move || fingerprint.get()}</code>
            <p class="text-[11px] text-silver-faint">
                {move || if uses_static.get() {
                    "static key used in this pattern"
                } else {
                    "no static key in this pattern"
                }}
            </p>
        </div>
    }
}

#[component]
fn PatternInfo(pattern: Signal<PatternKind>) -> impl IntoView {
    view! {
        {move || {
            let p = pattern.get();
            view! {
                <div class="space-y-3 rounded border border-line-soft bg-ink/40 p-4">
                    <div class="text-sm text-silver-dim">{p.description()}</div>
                    <div class="flex flex-wrap items-center gap-2">
                        {p.needs_responder_static().then(|| badge("responder static", "key"))}
                        {p.needs_initiator_static_preshared().then(|| badge("initiator static", "key"))}
                        {p.needs_psk().then(|| badge("PSK", "psk"))}
                        {p.is_one_way().then(|| badge("one-way", "dim"))}
                    </div>
                    <pre class="whitespace-pre-wrap text-xs leading-relaxed text-silver-dim">{p.tokens()}</pre>
                </div>
            }
        }}
    }
}

/// A small bordered chip. `tone` is one of "key" | "psk" | "dim".
fn badge(text: &'static str, tone: &'static str) -> impl IntoView {
    let classes = match tone {
        "psk" => "border-cyan-dim text-cyan",
        "dim" => "border-line-soft text-silver-faint",
        _ => "border-line text-silver-dim",
    };
    view! {
        <span class=format!(
            "inline-block rounded border bg-ink px-2 py-0.5 text-[11px] {classes}"
        )>{text}</span>
    }
}

#[component]
fn ChatBubble(line: ChatLine) -> impl IntoView {
    let from_initiator = line.from == Peer::Initiator;
    let row_align = if from_initiator {
        "flex justify-start"
    } else {
        "flex justify-end"
    };
    let (accent, who_color, who) = peer_style(line.from);
    let recipient = line.from.other().label();
    let ok = line.ok;
    let plaintext = line.plaintext;
    let ciphertext = hex_grouped(&line.ciphertext);

    view! {
        <div class=row_align>
            <div class=format!("max-w-[80%] rounded border border-line border-l-2 bg-ink/50 p-2.5 {accent}")>
                <div class="flex items-center justify-between gap-3 text-[11px]">
                    <span class=who_color>{who} " → " {recipient}</span>
                    <span class=if ok { "text-done" } else { "text-blocked" }>
                        {if ok { "✓ delivered" } else { "✗ decrypt failed" }}
                    </span>
                </div>
                <p class="text-sm text-silver">{plaintext}</p>
                <code class="mt-1 block max-h-16 overflow-y-auto break-words text-[11px] text-silver-faint">
                    {ciphertext}
                </code>
            </div>
        </div>
    }
}
