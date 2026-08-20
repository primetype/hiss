//! Code generation for the `noise!` macro.
//!
//! Two modes, selected by whether the invocation names a suite:
//!
//! * **marker mode** (no suite) — just the pattern marker, its `Pattern`
//!   impl derived from the notation, and the `WellFormed` assertion.
//!   This is how `hiss` defines its suite-generic built-in patterns.
//! * **suite mode** (`Name<Curve, Cipher, Hash>`) — everything below.
//!
//! In suite mode, from the parsed pattern this emits into the caller's
//! crate:
//!
//! * the pattern marker struct, its `hiss::noise::Pattern` and
//!   `hiss::noise::Protocol` impls, and a `WellFormed` assertion so that
//!   Noise §7.3 violations are compile errors at the invocation site;
//! * exact per-message wire-size consts (`MSG1_SIZE`, …), expressed as
//!   const expressions over `hiss`'s `WireSize` machinery — the macro
//!   itself does **no** size arithmetic, so the sizes cannot drift from
//!   the engine;
//! * two sans-io state machines (initiator and responder) at **message
//!   granularity**: one constructor per role (provider + prologue +
//!   pre-message keys) and then exactly one method per handshake message
//!   (`write_message_N` / `read_message_N`). The per-token crypto is
//!   straight-line code *inside* those methods, so a pattern costs one
//!   state type per message per role — not one per token.
//!
//! Outgoing messages are returned as fixed `[u8; MSGn_SIZE]` arrays;
//! incoming messages are borrowed for the duration of the `read_message`
//! call. All runtime behaviour bottoms out in `hiss::noise::support` —
//! the same per-token engine `hiss` uses internally.
//!
//! A message declared with a `[N]` payload suffix carries an N-byte
//! application payload in its tail: the writer takes `payload: &[u8; N]`
//! as its last parameter and the reader returns the recovered `[u8; N]`
//! by value alongside the next state. The payload rides the same
//! `encrypt_and_hash` that already closes every message, so `MSGn_SIZE`
//! grows by exactly `N` and the tail's tag byte-count is unchanged.
//! Whether that tail is encrypted is **positional** — see
//! [`keyed_at_tail`] — and the generated docs state the concrete
//! property per message.
//!
//! PSKs are plain `&Psk` parameters — most deployments know the PSK in
//! advance. When a *received* message reveals the peer's static (`s`)
//! before its `psk` token (e.g. IKpsk1), an additional
//! `read_message_N_with` variant is generated whose PSK parameter is a
//! lookup closure `FnOnce(&PublicKey) -> Result<Psk, _>`, for
//! deployments that select a per-peer PSK (or reject unknown peers)
//! from the just-revealed identity.
//!
//! A first message whose token sequence ends `…, s, ss` (IK's shape)
//! additionally gets a **staged** read: `read_message_1_intro` stops
//! after the revealed static — exactly the DH work up to that point —
//! and suspends into an owned mid-state whose `complete()` pays the
//! rest. The synchronous styles above decide *inside* the read; the
//! staged pair returns control to the caller at the identity boundary,
//! for decisions held across event-loop turns. See [`gen_split_read`].

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Ident, Path};

use crate::parse::{Dir, Line, NoiseInput, Suite, Tok};

/// Which side of the handshake a state machine is generated for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn send_dir(self) -> Dir {
        match self {
            Role::Initiator => Dir::ToResponder,
            Role::Responder => Dir::ToInitiator,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Role::Initiator => "Initiator",
            Role::Responder => "Responder",
        }
    }

    fn hiss_ty(self) -> TokenStream {
        match self {
            Role::Initiator => quote!(::hiss::noise::Initiator),
            Role::Responder => quote!(::hiss::noise::Responder),
        }
    }
}

/// Everything the per-state generators need, precomputed once.
struct Ctx<'a> {
    input: &'a NoiseInput,
    name: &'a Ident,
    curve: &'a Path,
    cipher: &'a Path,
    hash: &'a Path,
    suite: String,
}

impl Ctx<'_> {
    fn inner_ty(&self) -> TokenStream {
        let (curve, cipher, hash) = (self.curve, self.cipher, self.hash);
        quote!(::hiss::noise::support::HandshakeInner<#curve, #cipher, #hash, CP>)
    }

    fn privkey_ty(&self) -> TokenStream {
        let curve = self.curve;
        quote!(<CP as ::hiss::provider::CryptoKeyProvider<#curve>>::PrivateKey)
    }

    fn pubkey_ty(&self) -> TokenStream {
        let curve = self.curve;
        quote!(<#curve as ::hiss::curve::Curve>::PublicKey)
    }

    fn size_path(&self, msg: usize) -> TokenStream {
        let name = self.name;
        let size = format_ident!("MSG{}_SIZE", msg + 1);
        quote!(#name::#size)
    }

    /// The state awaiting handshake message `msg` (0-based), e.g.
    /// `IKpsk1InitiatorMsg2`.
    fn state_ident(&self, role: Role, msg: usize) -> Ident {
        format_ident!("{}{}Msg{}", self.name, role.name(), msg + 1)
    }

    /// The qualifying staged first message, if any — the one predicate
    /// behind every "does this pattern stage?" question outside a real
    /// message loop (see [`split_read_on`]).
    fn staged_msg1(&self) -> Option<&Line> {
        self.input
            .messages
            .first()
            .filter(|line| split_read_on(0, line))
    }
}

/// The role that *reads* a line — the side the staged pair lands on.
fn reader_of(line: &Line) -> Role {
    if line.dir == Role::Initiator.send_dir() {
        Role::Responder
    } else {
        Role::Initiator
    }
}

/// Whether a *received* line reveals the peer's static before its `psk`
/// token — the case where the PSK parameter becomes a lookup closure.
fn psk_after_s(line: &Line) -> bool {
    let s = line.tokens.iter().position(|(t, _)| *t == Tok::S);
    let psk = line.tokens.iter().position(|(t, _)| *t == Tok::Psk);
    matches!((s, psk), (Some(s), Some(p)) if s < p)
}

fn has_tok(line: &Line, tok: Tok) -> bool {
    line.tokens.iter().any(|(t, _)| *t == tok)
}

/// Whether the cipher is keyed by the time message `msg`'s tail closes —
/// i.e. a `mix_key` has run: any DH or `psk` token so far or, in a PSK
/// pattern, any `e` (which also calls `mix_key`).
///
/// This mirrors the engine's `WireSize` keying rule for **documentation
/// only** — a keyed tail means the payload is encrypted, an unkeyed one
/// means it travels in the clear, and the generated docs say which. The
/// sizes themselves still come from the `WireSize` consts, never from
/// this function.
fn keyed_at_tail(ctx: &Ctx<'_>, msg: usize) -> bool {
    let has_psk = ctx.input.has_psk();
    ctx.input.messages[..=msg].iter().any(|line| {
        line.tokens.iter().any(|(t, _)| match t {
            Tok::Ee | Tok::Es | Tok::Se | Tok::Ss | Tok::Psk => true,
            Tok::E => has_psk,
            Tok::S => false,
        })
    })
}

/// Right-fold a token list into `Cons<E, Cons<…, Nil>>`.
fn cons_tokens(tokens: &[(Tok, proc_macro2::Span)]) -> TokenStream {
    let mut list = quote!(::hiss::noise::Nil);
    for (tok, _) in tokens.iter().rev() {
        let ty = format_ident!("{}", tok.type_name());
        list = quote!(::hiss::noise::Cons<::hiss::noise::#ty, #list>);
    }
    list
}

/// Right-fold message lines into `Cons<Message<Dir, Toks>, …, Nil>`.
fn cons_messages(lines: &[Line]) -> TokenStream {
    let mut list = quote!(::hiss::noise::Nil);
    for line in lines.iter().rev() {
        let dir = match line.dir {
            Dir::ToResponder => quote!(::hiss::noise::ToResponder),
            Dir::ToInitiator => quote!(::hiss::noise::ToInitiator),
        };
        let toks = cons_tokens(&line.tokens);
        list = quote!(::hiss::noise::Cons<::hiss::noise::Message<#dir, #toks>, #list>);
    }
    list
}

/// The pattern in Noise notation, for doc comments.
fn pattern_diagram(input: &NoiseInput) -> String {
    let mut out = format!("{}:\n", input.name);
    for line in &input.pre_messages {
        out.push_str(&format!("  {}\n", line.render()));
    }
    if !input.pre_messages.is_empty() {
        out.push_str("  ...\n");
    }
    for line in &input.messages {
        out.push_str(&format!("  {}\n", line.render()));
    }
    out
}

pub(crate) fn expand(input: &NoiseInput) -> TokenStream {
    match &input.suite {
        Some(suite) => expand_suite(input, suite),
        None => expand_marker(input),
    }
}

/// Marker mode (no suite named): the pattern marker, its `Pattern` impl
/// derived from the notation, and the `WellFormed` assertion — no state
/// machines. This is how `hiss` defines its suite-generic built-ins.
fn expand_marker(input: &NoiseInput) -> TokenStream {
    let attrs = &input.attrs;
    let vis = &input.vis;
    let name = &input.name;
    let diagram = pattern_diagram(input);
    let generated = format!(
        "\n\n```text\n{diagram}```\n\nSuite-generic pattern marker: combine \
         it with a concrete suite through `Noise<P, Cu, Ci, H>`, or define \
         a suite-pinned handshake with its own sans-io state machine by \
         invoking `noise!` with a suite (e.g. \
         `noise! {{ pub MyHandshake<X25519, ChaChaPoly, Blake2b> {{ … }} }}`)."
    );
    let pattern_impl = gen_pattern_impl(input);
    quote! {
        #(#attrs)*
        #[doc = #generated]
        #[derive(Debug, Clone, Copy, Default)]
        #vis struct #name;

        #pattern_impl
    }
}

/// Suite mode: everything marker mode emits, plus the `Protocol` impl,
/// the wire-size consts, and the two per-message state machines.
fn expand_suite(input: &NoiseInput, suite: &Suite) -> TokenStream {
    let rendered_suite = {
        let render = |p: &Path| quote!(#p).to_string().replace(' ', "");
        format!(
            "{} / {} / {}",
            render(&suite.curve),
            render(&suite.cipher),
            render(&suite.hash)
        )
    };
    let ctx = Ctx {
        input,
        name: &input.name,
        curve: &suite.curve,
        cipher: &suite.cipher,
        hash: &suite.hash,
        suite: rendered_suite,
    };

    let main = gen_main_struct(&ctx);
    let pattern_impl = gen_pattern_impl(ctx.input);
    let protocol_impl = gen_protocol_impl(&ctx);
    let sizes = gen_sizes(&ctx);
    let entries = gen_entries(&ctx);
    let initiator = gen_role(&ctx, Role::Initiator);
    let responder = gen_role(&ctx, Role::Responder);

    quote! {
        #main
        #pattern_impl
        #protocol_impl
        #sizes
        #entries
        #initiator
        #responder
    }
}

// ═══════════════════════════════════════════════════════════════
//  Pattern marker, Pattern/Protocol impls, WellFormed assertion
// ═══════════════════════════════════════════════════════════════

fn gen_main_struct(ctx: &Ctx<'_>) -> TokenStream {
    let attrs = &ctx.input.attrs;
    let vis = &ctx.input.vis;
    let name = ctx.name;
    let diagram = pattern_diagram(ctx.input);
    let suite = &ctx.suite;
    // Both roles share one suite, so either both walkthroughs compile or
    // neither can — see `usage_doctest`. A pattern with a staged msg1
    // read gets a third walkthrough, from whichever role *reads* msg1.
    let staged_reader = ctx.staged_msg1().map(reader_of);
    let usage = match (
        usage_doctest(ctx, Role::Initiator, false),
        usage_doctest(ctx, Role::Responder, false),
    ) {
        (Some(initiator), Some(responder)) => {
            let mut out = format!(
                "\n\n# Usage\n\nAs the initiator:\n\n```\n{initiator}```\n\nAs \
                 the responder:\n\n```\n{responder}```"
            );
            if let Some(role) = staged_reader
                && let Some(staged) = usage_doctest(ctx, role, true)
            {
                out.push_str(&format!(
                    "\n\nAs the {}, **staged** — suspend on the claimed \
                     identity and decide across turns before paying the \
                     proving DH:\n\n```\n{staged}```",
                    role.name().to_lowercase(),
                ));
            }
            out
        }
        _ => {
            let initiator = usage_snippet(ctx, Role::Initiator, false);
            let responder = usage_snippet(ctx, Role::Responder, false);
            let mut out = format!(
                "\n\n# Usage\n\nSketches rather than doctests: this suite is \
                 named through paths `noise!` cannot respell for a doctest \
                 crate (a local alias, or a `Curve` of your own), so the \
                 walkthroughs below are uncompiled. Spell the suite as \
                 `hiss::noise::…` to get compiled ones.\n\nAs the \
                 initiator:\n\n```text\n{initiator}```\n\nAs the \
                 responder:\n\n```text\n{responder}```"
            );
            if let Some(role) = staged_reader {
                let staged = usage_snippet(ctx, role, true);
                out.push_str(&format!(
                    "\n\nAs the {}, staged:\n\n```text\n{staged}```",
                    role.name().to_lowercase(),
                ));
            }
            out
        }
    };
    let generated = format!(
        "\n\n```text\n{diagram}```\n\nOver the suite {suite}. Generated by \
         `hiss::noise!`. Each handshake message is a fixed-size byte array \
         and no I/O is performed — transporting the messages is the \
         caller's job.{usage}"
    );
    quote! {
        #(#attrs)*
        #[doc = #generated]
        #[derive(Debug, Clone, Copy, Default)]
        #vis struct #name;
    }
}

fn gen_pattern_impl(input: &NoiseInput) -> TokenStream {
    let name = &input.name;
    let name_str = name.to_string();
    let num = input.messages.len();
    let pre = cons_messages(&input.pre_messages);
    let msgs = cons_messages(&input.messages);
    quote! {
        impl ::hiss::noise::Pattern for #name {
            const NAME: &'static str = #name_str;
            const NUM_MESSAGES: usize = #num;
            type PreMessages = #pre;
            type Messages = #msgs;
        }

        // Noise §7.3 validity, enforced by hiss's type-level guard: a
        // malformed pattern fails to compile right here.
        const _: fn() = || {
            fn assert_well_formed<P: ::hiss::noise::WellFormed>() {}
            let _ = assert_well_formed::<#name>;
        };
    }
}

fn gen_protocol_impl(ctx: &Ctx<'_>) -> TokenStream {
    let name = ctx.name;
    let (curve, cipher, hash) = (ctx.curve, ctx.cipher, ctx.hash);
    quote! {
        impl ::hiss::noise::Protocol for #name {
            type Pattern = #name;
            type Curve = #curve;
            type Cipher = #cipher;
            type Hash = #hash;
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Wire-size consts
// ═══════════════════════════════════════════════════════════════

fn gen_sizes(ctx: &Ctx<'_>) -> TokenStream {
    let name = ctx.name;
    let (curve, cipher) = (ctx.curve, ctx.cipher);
    let has_psk = ctx.input.has_psk();

    let mut consts = TokenStream::new();
    consts.extend(quote! {
        #[doc(hidden)]
        pub const __KEYED_BEFORE_MSG1: bool = false;
    });
    for (i, line) in ctx.input.messages.iter().enumerate() {
        let toks = cons_tokens(&line.tokens);
        let wire = quote!(<#toks as ::hiss::noise::WireSize<#curve, #cipher, #has_psk>>);
        let before = format_ident!("__KEYED_BEFORE_MSG{}", i + 1);
        let after = format_ident!("__KEYED_BEFORE_MSG{}", i + 2);
        let size = format_ident!("MSG{}_SIZE", i + 1);
        // The declared payload length is caller data passed straight
        // through — the token bytes and the tag's presence still come
        // from the `WireSize` machinery alone.
        let (payload_term, tail_doc) = match line.payload {
            Some(payload) => {
                let n = payload.len;
                (
                    quote!(+ #n),
                    format!(
                        "the {n}-byte application payload, and its trailing \
                         authentication tag once the cipher is keyed"
                    ),
                )
            }
            None => (
                quote!(),
                "the trailing empty-payload authentication tag once the \
                 cipher is keyed"
                    .to_string(),
            ),
        };
        let doc = format!(
            "Exact wire size in bytes of handshake message {} (`{}`): the \
             token bytes plus {tail_doc}.",
            i + 1,
            line.render(),
        );
        consts.extend(quote! {
            #[doc(hidden)]
            pub const #after: bool = if Self::#before {
                #wire::KEYED_AFTER_KEYED
            } else {
                #wire::KEYED_AFTER_UNKEYED
            };

            #[doc = #doc]
            pub const #size: usize = (if Self::#before {
                #wire::SIZE_KEYED
            } else {
                #wire::SIZE_UNKEYED
            }) + (if Self::#after {
                <#cipher as ::hiss::noise::Cipher>::TAG_SIZE
            } else {
                0
            }) #payload_term;
        });
        // The staged read's mid-state owns this message's un-read tail —
        // the bytes after its final `s` token. DH tokens are zero-width
        // on the wire, so that tail is the message size minus the token
        // bytes: the same engine terms the size const above is built
        // from, subtracted rather than re-derived, so the two cannot
        // drift apart.
        if split_read_on(i, line) {
            let tail_const = format_ident!("MSG{}_INTRO_TAIL", i + 1);
            let intro_tail_doc = format!(
                "Bytes of handshake message {} left un-read by \
                 `read_message_{}_intro` — the declared payload (if any) \
                 plus its authentication tag. The staged read's mid-state \
                 carries exactly this many bytes between `intro` and \
                 `complete`.",
                i + 1,
                i + 1,
            );
            consts.extend(quote! {
                #[doc = #intro_tail_doc]
                pub const #tail_const: usize = Self::#size
                    - (if Self::#before {
                        #wire::SIZE_KEYED
                    } else {
                        #wire::SIZE_UNKEYED
                    });
            });
        }
    }
    quote! {
        impl #name {
            #consts
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Entry points — provider + prologue + pre-message keys, one call
// ═══════════════════════════════════════════════════════════════

/// The pre-message parameters a role must supply: `(is_local, arg_name)`
/// per pre-message line, in pattern order.
fn premessage_params(ctx: &Ctx<'_>, role: Role) -> Vec<(bool, Ident)> {
    ctx.input
        .pre_messages
        .iter()
        .map(|line| {
            let local = line.dir == role.send_dir();
            let name = if local {
                format_ident!("static_key")
            } else {
                format_ident!("remote_static")
            };
            (local, name)
        })
        .collect()
}

fn gen_entries(ctx: &Ctx<'_>) -> TokenStream {
    let name = ctx.name;
    let curve = ctx.curve;
    let mut fns = TokenStream::new();
    for role in [Role::Initiator, Role::Responder] {
        let fn_name = format_ident!("{}", role.name().to_lowercase());
        let first = ctx.state_ident(role, 0);
        let params = premessage_params(ctx, role);
        let fallible = params.iter().any(|(local, _)| *local);

        let mut args = TokenStream::new();
        let mut setup = TokenStream::new();
        for (local, arg) in &params {
            if *local {
                let privkey = ctx.privkey_ty();
                args.extend(quote!(, #arg: #privkey));
                setup.extend(quote! {
                    ::hiss::noise::support::set_s(&mut inner, #arg)?;
                });
            } else {
                let pubkey = ctx.pubkey_ty();
                args.extend(quote!(, #arg: #pubkey));
                setup.extend(quote! {
                    ::hiss::noise::support::set_rs(&mut inner, #arg);
                });
            }
        }

        let mut doc = format!(
            "Begin the `{name}` handshake as the **{}**.\n\n\
             `prologue` is arbitrary context both parties must agree on — \
             it is mixed into the transcript before anything else, and a \
             mismatch fails the first authenticated token. Use `&[]` for \
             none.",
            role.name().to_lowercase(),
        );
        for ((local, _), line) in params.iter().zip(&ctx.input.pre_messages) {
            let what = if *local {
                "`static_key` — our static key pair is known to the peer in \
                 advance; provide its private half"
            } else {
                "`remote_static` — the peer's static public key, known in \
                 advance (pinned, configured, or exchanged out of band)"
            };
            doc.push_str(&format!("\n\nPre-message `{}`: {what}.", line.render()));
        }

        let body = quote! {
            #[allow(unused_mut)]
            let mut inner =
                ::hiss::noise::support::new_handshake::<#name, CP>(provider, prologue);
            #setup
        };
        let f = if fallible {
            quote! {
                #[doc = #doc]
                pub fn #fn_name<CP>(
                    provider: CP,
                    prologue: &[u8]
                    #args
                ) -> ::core::result::Result<#first<CP>, ::hiss::noise::HandshakeError>
                where
                    CP: ::hiss::provider::DhProvider<#curve>,
                {
                    #body
                    Ok(#first { inner })
                }
            }
        } else {
            quote! {
                #[doc = #doc]
                pub fn #fn_name<CP>(
                    provider: CP,
                    prologue: &[u8]
                    #args
                ) -> #first<CP>
                where
                    CP: ::hiss::provider::DhProvider<#curve>,
                {
                    #body
                    #first { inner }
                }
            }
        };
        fns.extend(f);
    }
    quote! {
        impl #name {
            #fns
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Role state machines — one state and one method per message
// ═══════════════════════════════════════════════════════════════

/// Where a mid-handshake key became available, for accessor doc text.
#[derive(Clone, Copy)]
enum KeySource {
    /// Supplied up front via a pre-message argument of the constructor.
    PreMessage,
    /// Established by the given handshake message (0-based).
    Message(usize),
}

fn gen_role(ctx: &Ctx<'_>, role: Role) -> TokenStream {
    let mut out = TokenStream::new();
    // Which step established each observable key, if any — folded over
    // everything *before* the state being generated, so accessors exist
    // exactly on the states where the key is guaranteed present.
    let mut local_e: Option<KeySource> = None;
    let mut remote_e: Option<KeySource> = None;
    let mut remote_s: Option<KeySource> = None;
    // A pre-message `s` line in the peer's direction is the remote static,
    // supplied to the constructor — available from the very first state.
    if ctx
        .input
        .pre_messages
        .iter()
        .any(|line| line.dir != role.send_dir() && has_tok(line, Tok::S))
    {
        remote_s = Some(KeySource::PreMessage);
    }
    for (msg, line) in ctx.input.messages.iter().enumerate() {
        out.extend(gen_state_struct(ctx, role, msg));
        out.extend(gen_key_accessors(
            ctx, role, msg, local_e, remote_e, remote_s,
        ));
        let ours = line.dir == role.send_dir();
        if ours {
            out.extend(gen_write_message(ctx, role, msg));
        } else {
            out.extend(gen_read_message(ctx, role, msg));
            if split_read_on(msg, line) {
                out.extend(gen_split_read(ctx, role, msg));
            }
        }
        if has_tok(line, Tok::E) {
            if ours {
                local_e = Some(KeySource::Message(msg));
            } else {
                remote_e = Some(KeySource::Message(msg));
            }
        }
        if !ours && has_tok(line, Tok::S) {
            remote_s = Some(KeySource::Message(msg));
        }
    }
    out
}

/// Accessors for keys observable mid-handshake, generated only on states
/// where the state machine guarantees the key exists — so they return
/// `&PublicKey`, not an `Option`. (After the handshake, the ephemerals
/// remain available via `Transport::local_ephemeral`/`remote_ephemeral`.)
fn gen_key_accessors(
    ctx: &Ctx<'_>,
    role: Role,
    msg: usize,
    local_e: Option<KeySource>,
    remote_e: Option<KeySource>,
    remote_s: Option<KeySource>,
) -> TokenStream {
    if local_e.is_none() && remote_e.is_none() && remote_s.is_none() {
        return quote!();
    }
    let id = ctx.state_ident(role, msg);
    let curve = ctx.curve;
    let pubkey = ctx.pubkey_ty();
    let mut fns = TokenStream::new();
    if let Some(KeySource::Message(set_by)) = local_e {
        let doc = format!(
            "Our ephemeral public key, generated by message {}'s `e` token. \
             Useful mid-handshake, e.g. to correlate this session while \
             awaiting the peer's next message.",
            set_by + 1,
        );
        fns.extend(quote! {
            #[doc = #doc]
            pub fn local_ephemeral(&self) -> &#pubkey {
                ::hiss::noise::support::local_ephemeral(&self.inner)
                    .expect("set by an earlier message; guaranteed by the state machine")
            }
        });
    }
    if let Some(KeySource::Message(set_by)) = remote_e {
        let doc = format!(
            "The peer's ephemeral public key, read from message {}'s `e` \
             token. Useful mid-handshake, e.g. to index a pending handshake \
             while awaiting the peer's next message.",
            set_by + 1,
        );
        fns.extend(quote! {
            #[doc = #doc]
            pub fn remote_ephemeral(&self) -> &#pubkey {
                ::hiss::noise::support::remote_ephemeral(&self.inner)
                    .expect("set by an earlier message; guaranteed by the state machine")
            }
        });
    }
    if let Some(source) = remote_s {
        let doc = match source {
            KeySource::PreMessage => "The peer's static public key, as supplied up front via the \
                 pre-message argument of the constructor."
                .to_string(),
            KeySource::Message(set_by) => format!(
                "The peer's static public key, revealed by message {}'s `s` \
                 token — the identity to verify against your trust store \
                 before relying on the channel.",
                set_by + 1,
            ),
        };
        fns.extend(quote! {
            #[doc = #doc]
            pub fn remote_static(&self) -> &#pubkey {
                ::hiss::noise::support::remote_static(&self.inner)
                    .expect("set by an earlier step; guaranteed by the state machine")
            }
        });
    }
    quote! {
        impl<CP> #id<CP>
        where
            CP: ::hiss::provider::CryptoKeyProvider<#curve>,
        {
            #fns
        }
    }
}

fn gen_state_struct(ctx: &Ctx<'_>, role: Role, msg: usize) -> TokenStream {
    let vis = &ctx.input.vis;
    let id = ctx.state_ident(role, msg);
    let curve = ctx.curve;
    let inner_ty = ctx.inner_ty();
    let line = &ctx.input.messages[msg];
    let name = ctx.name;
    let n = ctx.input.messages.len();
    let sending = line.dir == role.send_dir();
    let method = method_ident(sending, msg);
    let action = if sending {
        format!("build and send it with [`{method}`](Self::{method})")
    } else {
        format!("feed the peer's bytes to [`{method}`](Self::{method})")
    };
    let doc = format!(
        "**{name}** {} — awaiting message {} of {n} (`{}`): {action}.",
        role.name().to_lowercase(),
        msg + 1,
        line.render(),
    );
    quote! {
        #[doc = #doc]
        #vis struct #id<CP>
        where
            CP: ::hiss::provider::CryptoKeyProvider<#curve>,
        {
            inner: #inner_ty,
        }
    }
}

fn method_ident(sending: bool, msg: usize) -> Ident {
    if sending {
        format_ident!("write_message_{}", msg + 1)
    } else {
        format_ident!("read_message_{}", msg + 1)
    }
}

/// The staged pair's phase-1 method — one spelling for the definition
/// and every doc cross-link, so a rename cannot orphan a link.
fn intro_ident(msg: usize) -> Ident {
    format_ident!("read_message_{}_intro", msg + 1)
}

/// The identity-hook variant's name (`read_message_N_with`).
fn with_ident(msg: usize) -> Ident {
    format_ident!("read_message_{}_with", msg + 1)
}

/// The expression producing the state (or transport) after message `msg`.
fn next_state(ctx: &Ctx<'_>, role: Role, msg: usize) -> (TokenStream, TokenStream) {
    let name = ctx.name;
    if msg + 1 == ctx.input.messages.len() {
        let role_ty = role.hiss_ty();
        (
            quote!(::hiss::noise::Transport<#name>),
            quote!(::hiss::noise::support::into_transport::<#name, #role_ty, CP>(self.inner)),
        )
    } else {
        let id = ctx.state_ident(role, msg + 1);
        (quote!(#id<CP>), quote!(#id { inner: self.inner }))
    }
}

/// One bullet of method documentation per token.
fn token_bullet(tok: Tok, sending: bool) -> &'static str {
    match (tok, sending) {
        (Tok::E, true) => {
            "`e` — generates a fresh ephemeral key pair and writes its \
             public half"
        }
        (Tok::E, false) => {
            "`e` — reads the peer's ephemeral public key (available \
             after the handshake via `Transport::remote_ephemeral`)"
        }
        (Tok::S, true) => {
            "`s` — writes our static public key, encrypted once the \
             cipher is keyed (consumes `static_key`)"
        }
        (Tok::S, false) => {
            "`s` — reads (and decrypts) the peer's static public key; it is \
             observable afterwards via `remote_static()` — verify the peer's \
             identity **before** trusting the channel"
        }
        (Tok::Ee, _) => {
            "`ee` — mixes `DH(initiator ephemeral, responder ephemeral)` \
             into the key schedule"
        }
        (Tok::Es, _) => {
            "`es` — mixes `DH(initiator ephemeral, responder static)` \
             into the key schedule"
        }
        (Tok::Se, _) => {
            "`se` — mixes `DH(initiator static, responder ephemeral)` \
             into the key schedule"
        }
        (Tok::Ss, _) => {
            "`ss` — mixes `DH(initiator static, responder static)` into \
             the key schedule"
        }
        (Tok::Psk, _) => "`psk` — mixes the pre-shared key into the key schedule",
    }
}

fn message_doc(ctx: &Ctx<'_>, msg: usize, sending: bool) -> String {
    let name = ctx.name;
    let line = &ctx.input.messages[msg];
    let mut doc = if sending {
        format!(
            "Build handshake message {} (`{}`) and return it as a \
             [`{name}::MSG{}_SIZE`]-byte array — transport it to the peer \
             however you like. Token by token:\n",
            msg + 1,
            line.render(),
            msg + 1,
        )
    } else {
        format!(
            "Process the peer's handshake message {} (`{}`), exactly \
             [`{name}::MSG{}_SIZE`] bytes. Token by token:\n",
            msg + 1,
            line.render(),
            msg + 1,
        )
    };
    for (tok, _) in &line.tokens {
        doc.push_str(&format!("\n* {}", token_bullet(*tok, sending)));
    }
    if let Some(payload) = line.payload {
        doc.push_str(&payload_doc(ctx, msg, payload.len, sending));
    }
    if msg + 1 == ctx.input.messages.len() {
        doc.push_str(
            "\n\nThis is the final handshake message: it completes into the \
             session `Transport`.",
        );
    }
    doc
}

/// The documentation paragraph for a message's `[N]` application payload.
///
/// Confidentiality and integrity are **positional** — they depend on
/// whether the cipher is keyed when the tail closes — so the text states
/// the concrete property for this message rather than a generic hedge.
fn payload_doc(ctx: &Ctx<'_>, msg: usize, n: usize, sending: bool) -> String {
    match (sending, keyed_at_tail(ctx, msg)) {
        (true, true) => format!(
            "\n\nThe message also carries a {n}-byte application payload, \
             supplied as `payload` and sealed into the message's tail. The \
             cipher **is keyed** at this point, so the payload is encrypted \
             and authenticated — readable only by a peer that can complete \
             this handshake's key schedule. Its exact security is that of \
             this message's position in the handshake: consult the \
             pattern's payload security properties (Noise §7.7) before \
             trusting it with secrets."
        ),
        (true, false) => format!(
            "\n\nThe message also carries a {n}-byte application payload, \
             supplied as `payload` and appended as the message's tail. The \
             cipher is **not yet keyed** at this point, so the payload \
             travels **in the clear** — readable, and undetectably \
             alterable at this message, by anyone on the wire. It is still \
             mixed into the transcript, so a tampered payload fails the \
             next authenticated token later in the handshake."
        ),
        (false, true) => format!(
            "\n\nThe message also carries a {n}-byte application payload, \
             returned by value on success. The cipher **is keyed** at this \
             point, so the tail was decrypted and its authentication tag \
             verified — a tampered tail fails with `DecryptionFailed` and \
             yields neither payload nor state, and the fixed-size message \
             makes a length mismatch unrepresentable at this API. Its \
             confidentiality is that of this message's position in the \
             handshake (Noise §7.7)."
        ),
        (false, false) => format!(
            "\n\nThe message also carries a {n}-byte application payload, \
             returned by value on success. The cipher is **not yet keyed** \
             at this point, so the payload travelled **in the clear** and \
             nothing verifies it at this read — a wire tamper is only \
             caught by the next authenticated token later in the \
             handshake. Treat the bytes as unauthenticated input until \
             then."
        ),
    }
}

fn gen_write_message(ctx: &Ctx<'_>, role: Role, msg: usize) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let id = ctx.state_ident(role, msg);
    let curve = ctx.curve;
    let size = ctx.size_path(msg);
    let support = quote!(::hiss::noise::support);
    let method = method_ident(true, msg);
    let (next_ty, next_expr) = next_state(ctx, role, msg);
    let doc = message_doc(ctx, msg, true);

    let mut args = TokenStream::new();
    let mut stmts = TokenStream::new();
    for (tok, _) in &line.tokens {
        match tok {
            Tok::E => stmts.extend(quote! {
                let n = #support::send_e(&mut self.inner, &mut buf[cursor..])?;
                let cursor = cursor + n;
            }),
            Tok::S => {
                let privkey = ctx.privkey_ty();
                args.extend(quote!(, static_key: #privkey));
                stmts.extend(quote! {
                    let n = #support::send_s(&mut self.inner, &mut buf[cursor..], static_key)?;
                    let cursor = cursor + n;
                });
            }
            Tok::Psk => {
                args.extend(quote!(, psk: &::hiss::psk::Psk));
                stmts.extend(quote! {
                    #support::psk(&mut self.inner, psk)?;
                });
            }
            dh => {
                let call = dh_call(*dh, role);
                stmts.extend(quote! {
                    #support::#call(&mut self.inner)?;
                });
            }
        }
    }

    // The payload is the message's tail, so its parameter comes last, in
    // keeping with token order.
    let tail_arg = match line.payload {
        Some(payload) => {
            let n = payload.len;
            args.extend(quote!(, payload: &[u8; #n]));
            quote!(payload)
        }
        None => quote!(&[]),
    };

    quote! {
        impl<CP> #id<CP>
        where
            CP: ::hiss::provider::DhProvider<#curve>,
        {
            #[doc = #doc]
            pub fn #method(
                mut self
                #args
            ) -> ::core::result::Result<([u8; #size], #next_ty), ::hiss::noise::HandshakeError>
            {
                let mut buf = [0u8; #size];
                let cursor = 0usize;
                #stmts
                let tail = #support::send_tail(&mut self.inner, &mut buf[cursor..], #tail_arg)?;
                debug_assert_eq!(cursor + tail, #size, "message size bookkeeping");
                Ok((buf, #next_expr))
            }
        }
    }
}

/// How a receive method exposes the identities its tokens reveal.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStyle {
    /// Everything is known in advance: a plain `psk: &Psk` parameter for
    /// a `psk` token; revealed keys observable through state accessors.
    Plain,
    /// The PSK is selected per peer: a lookup closure over the identity
    /// the message reveals before its `psk` token.
    Lookup,
    /// The message reveals the peer's static: a verification closure
    /// sees the identity as soon as it is decrypted, before any of the
    /// message's remaining tokens are processed.
    Verify,
}

/// Whether a *received* message gets the `_with` verification variant:
/// it reveals the peer's static and is not the PSK-lookup shape (whose
/// lookup closure is already the identity hook). Every `s`-revealing
/// read qualifies, final or not — on the final message there is no later
/// state to observe the key on (only `Transport::remote_static()`, an
/// `Option`); on a non-final message the closure rejects the claimed
/// identity before the message's remaining DH tokens are computed, so
/// an unwanted peer costs no further provider work (on IK's first
/// message, rejection costs the responder exactly the one `es` DH).
fn verify_on_read(line: &Line) -> bool {
    has_tok(line, Tok::S) && !psk_after_s(line)
}

/// Whether a *received* message gets the staged `intro`/`complete` read
/// pair: the first message, with its token sequence ending `…, s, ss` (a
/// declared payload may follow). At that boundary the claimed static has
/// just been revealed, and everything still unpaid — the proving `ss`
/// and the tail — needs no further input bytes, so the read can suspend
/// into a self-contained mid-state and resume later.
///
/// Deliberately narrower than the mechanism could carry:
///
/// * a msg1 with a **trailing `psk`** (IKpsk1's shape) is excluded — its
///   `complete()` would need the PSK re-supplied mid-read, breaking the
///   mid-state's "nothing re-supplied later" contract, and the `_with`
///   lookup closure already serves per-peer PSK selection there;
/// * later messages, and shapes with non-DH tokens after the last `s`,
///   are excluded until something needs them. The split point itself is
///   derived, not enumerated — everything after the *last* `s` (see
///   [`gen_split_read`]) — so widening this predicate is a policy
///   decision, not a rewrite.
fn split_read_on(msg: usize, line: &Line) -> bool {
    msg == 0 && matches!(line.tokens.as_slice(), [.., (Tok::S, _), (Tok::Ss, _)])
}

fn gen_read_message(ctx: &Ctx<'_>, role: Role, msg: usize) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let id = ctx.state_ident(role, msg);
    let curve = ctx.curve;

    // The plain form is always the primary method. When the message
    // reveals the peer's static before its `psk` token, an additional
    // `read_message_N_with` variant lets the PSK be selected per peer.
    // When any other received message reveals the peer's static, the
    // `_with` variant instead takes a verification closure, so the peer
    // can be rejected before the message's remaining tokens are
    // processed.
    let mut methods = gen_read_method(ctx, role, msg, ReadStyle::Plain);
    if psk_after_s(line) {
        methods.extend(gen_read_method(ctx, role, msg, ReadStyle::Lookup));
    } else if verify_on_read(line) {
        methods.extend(gen_read_method(ctx, role, msg, ReadStyle::Verify));
    }

    quote! {
        impl<CP> #id<CP>
        where
            CP: ::hiss::provider::DhProvider<#curve>,
        {
            #methods
        }
    }
}

fn gen_read_method(ctx: &Ctx<'_>, role: Role, msg: usize, style: ReadStyle) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let size = ctx.size_path(msg);
    let base = method_ident(false, msg);
    let method = match style {
        ReadStyle::Plain => base.clone(),
        ReadStyle::Lookup | ReadStyle::Verify => format_ident!("{base}_with"),
    };
    let (next_ty, next_expr) = next_state(ctx, role, msg);
    let final_msg = msg + 1 == ctx.input.messages.len();
    let mut doc = message_doc(ctx, msg, false);
    match style {
        ReadStyle::Plain if psk_after_s(line) => {
            let with = format_ident!("{base}_with");
            doc.push_str(&format!(
                "\n\nThe PSK is supplied up front. When it must instead be \
                 selected by the identity this message reveals (per-peer \
                 PSKs), use [`{with}`](Self::{with}).",
            ));
        }
        ReadStyle::Plain if verify_on_read(line) && final_msg => {
            let with = format_ident!("{base}_with");
            doc.push_str(&format!(
                "\n\nThis final message reveals the peer's static identity; \
                 afterwards it is only observable via \
                 `Transport::remote_static` (an `Option`). To verify the \
                 peer at the protocol-correct moment — after the identity \
                 is revealed but **before** the handshake completes — use \
                 [`{with}`](Self::{with}).",
            ));
        }
        ReadStyle::Plain if verify_on_read(line) => {
            let with = format_ident!("{base}_with");
            doc.push_str(&format!(
                "\n\nThis message reveals the peer's static identity; it \
                 becomes observable via `remote_static()` on the returned \
                 state. To reject an unknown peer at the earliest protocol \
                 moment — before the message's remaining DH tokens are \
                 even computed — use [`{with}`](Self::{with}).",
            ));
        }
        ReadStyle::Lookup => {
            doc.push_str(
                "\n\nVariant taking the PSK as a **lookup**: the pattern \
                 places `psk` after the peer's identity is revealed, so the \
                 closure receives that identity and returns the PSK enrolled \
                 for it — or an error (e.g. \
                 `HandshakeError::PeerRejected`) to reject an unknown peer \
                 and abort the handshake. At that point the identity is \
                 claimed, not yet proven — ownership of the key is only \
                 established as the message's remaining tokens are processed \
                 — so selecting a PSK by it is sound (a mismatch fails the \
                 handshake), but side effects in the closure must not treat \
                 the key as authenticated.",
            );
        }
        ReadStyle::Verify if final_msg => {
            doc.push_str(
                "\n\nVariant taking a **verification** closure: this final \
                 message reveals the peer's static identity, and the closure \
                 receives it as soon as it is read — before the remaining \
                 tokens are processed. Return `Ok(())` to accept the peer, \
                 or an error (e.g. `HandshakeError::PeerRejected`) to \
                 reject it: the handshake aborts and no `Transport` is \
                 produced for an unverified peer. At that point the \
                 identity is **claimed, not yet proven**: ownership of the \
                 key is only established by the message's remaining DH \
                 tokens and final tag, so rejecting is always safe, but \
                 side effects in the closure must not treat the key as \
                 authenticated — and in a pattern whose `s` precedes every \
                 DH token it arrives unencrypted.",
            );
        }
        ReadStyle::Verify => {
            doc.push_str(
                "\n\nVariant taking a **verification** closure: this \
                 message reveals the peer's static identity, and the \
                 closure receives it as soon as it is read — before the \
                 message's remaining DH tokens are even computed. Return \
                 `Ok(())` to accept the peer, or an error (e.g. \
                 `HandshakeError::PeerRejected`) to reject it: the \
                 handshake aborts at the cheapest possible moment and no \
                 next state is produced for an unverified peer. At that \
                 point the identity is **claimed, not yet proven**: \
                 ownership of the key is only established by the message's \
                 remaining DH tokens and later tags, so rejecting is always \
                 safe, but side effects in the closure must not treat the \
                 key as authenticated — and in a pattern whose `s` precedes \
                 every DH token it arrives unencrypted.",
            );
        }
        ReadStyle::Plain => {}
    }
    // Composition with a `[N]` payload: the tail is processed after every
    // token, so an identity closure always fires before the payload is
    // touched — an accepted read is the only way to the payload.
    if line.payload.is_some() && matches!(style, ReadStyle::Lookup | ReadStyle::Verify) {
        doc.push_str(
            "\n\nThe closure fires before the message's remaining tokens, \
             and therefore before the payload's tail is decrypted: the \
             payload is only ever returned from an accepted read.",
        );
    }
    // A qualifying first message also carries the staged pair; point the
    // synchronous styles at it.
    if split_read_on(msg, line) {
        let intro = intro_ident(msg);
        doc.push_str(&format!(
            "\n\nTo hold the trust decision **across event-loop turns** \
             instead of inside this call — inspect the claimed identity, \
             suspend, and pay the remaining DH only on acceptance — use \
             [`{intro}`](Self::{intro})."
        ));
    }

    let (args, stmts) = read_token_stmts(ctx, role, style, &line.tokens, false);

    let (ret_ty, tail, ok_expr) =
        recv_tail_arm(line, &(next_ty, next_expr), quote!(&message[cursor..]));

    quote! {
        #[doc = #doc]
        pub fn #method(
            mut self,
            message: &[u8; #size]
            #args
        ) -> ::core::result::Result<#ret_ty, ::hiss::noise::HandshakeError> {
            let cursor = 0usize;
            #stmts
            #tail
            Ok(#ok_expr)
        }
    }
}

/// Per-token parameters and statements for a received message's token
/// slice — the one engine-call sequence behind every read surface
/// (one-shot, `_with`, and the staged pair, which splits this sequence
/// across two methods rather than re-deriving it).
///
/// `expose_s` binds the revealed static as `remote_static` even in
/// `Plain` style, for a caller that returns it (the staged intro read).
/// Otherwise the revealed static is not bound: it stays observable via
/// `remote_static()` on the next state (or on the `Transport`), and the
/// binding is only consumed by a PSK-lookup or verification closure.
fn read_token_stmts(
    ctx: &Ctx<'_>,
    role: Role,
    style: ReadStyle,
    tokens: &[(Tok, proc_macro2::Span)],
    expose_s: bool,
) -> (TokenStream, TokenStream) {
    let support = quote!(::hiss::noise::support);
    let mut args = TokenStream::new();
    let mut stmts = TokenStream::new();
    for (tok, _) in tokens {
        match tok {
            Tok::E => stmts.extend(quote! {
                let (_remote_ephemeral, n) =
                    #support::recv_e(&mut self.inner, &message[cursor..])?;
                let cursor = cursor + n;
            }),
            Tok::S if style == ReadStyle::Lookup => stmts.extend(quote! {
                let (remote_static, n) =
                    #support::recv_s(&mut self.inner, &message[cursor..])?;
                let cursor = cursor + n;
            }),
            Tok::S if style == ReadStyle::Verify => {
                let pubkey = ctx.pubkey_ty();
                args.extend(quote! {
                    , verify: impl ::core::ops::FnOnce(
                        &#pubkey,
                    ) -> ::core::result::Result<(), ::hiss::noise::HandshakeError>
                });
                stmts.extend(quote! {
                    let (remote_static, n) =
                        #support::recv_s(&mut self.inner, &message[cursor..])?;
                    let cursor = cursor + n;
                    verify(&remote_static)?;
                });
            }
            Tok::S if expose_s => stmts.extend(quote! {
                let (remote_static, n) =
                    #support::recv_s(&mut self.inner, &message[cursor..])?;
                let cursor = cursor + n;
            }),
            Tok::S => stmts.extend(quote! {
                let (_remote_static, n) =
                    #support::recv_s(&mut self.inner, &message[cursor..])?;
                let cursor = cursor + n;
            }),
            Tok::Psk => match style {
                ReadStyle::Lookup => {
                    let pubkey = ctx.pubkey_ty();
                    args.extend(quote! {
                        , psk: impl ::core::ops::FnOnce(
                            &#pubkey,
                        ) -> ::core::result::Result<::hiss::psk::Psk, ::hiss::noise::HandshakeError>
                    });
                    stmts.extend(quote! {
                        let psk_key = psk(&remote_static)?;
                        #support::psk(&mut self.inner, &psk_key)?;
                    });
                }
                // A `psk` in a Verify message precedes the `s` (else the
                // lookup variant would have been generated), so it is a
                // plain parameter; token order keeps it ahead of `verify`
                // in the signature.
                ReadStyle::Plain | ReadStyle::Verify => {
                    args.extend(quote!(, psk: &::hiss::psk::Psk));
                    stmts.extend(quote! {
                        #support::psk(&mut self.inner, psk)?;
                    });
                }
            },
            dh => {
                let call = dh_call(*dh, role);
                stmts.extend(quote! {
                    #support::#call(&mut self.inner)?;
                });
            }
        }
    }
    (args, stmts)
}

/// A received message's tail — return type, recovery statements, success
/// expression — parameterized over where the tail bytes come from:
/// `&message[cursor..]` for the synchronous styles, the mid-state's
/// owned array for the staged `complete`. One definition, so the two
/// surfaces cannot drift.
///
/// A `[N]` payload is recovered into a caller-owned array, returned by
/// value alongside the next state. On the error paths nothing
/// authenticated was written: the cipher zeroes the output on a failed
/// tag, and the array never leaves the generated frame.
fn recv_tail_arm(
    line: &Line,
    next: &(TokenStream, TokenStream),
    source: TokenStream,
) -> (TokenStream, TokenStream, TokenStream) {
    let support = quote!(::hiss::noise::support);
    let (next_ty, next_expr) = next;
    match line.payload {
        Some(payload) => {
            let n = payload.len;
            (
                quote!(([u8; #n], #next_ty)),
                quote! {
                    let mut payload = [0u8; #n];
                    #support::recv_tail(&mut self.inner, #source, &mut payload)?;
                },
                quote!((payload, #next_expr)),
            )
        }
        None => (
            quote!(#next_ty),
            quote! {
                #support::recv_tail(&mut self.inner, #source, &mut [])?;
            },
            quote!(#next_expr),
        ),
    }
}

/// The staged read for a qualifying first message (see
/// [`split_read_on`]): an `intro` method on the message's state that
/// stops after the revealed static, the owned mid-state it suspends
/// into, and the consuming `complete` that pays the rest.
///
/// The synchronous styles are untouched; this is their suspending
/// sibling — the same [`read_token_stmts`] engine calls in the same
/// order, with control returned to the caller at the identity boundary
/// instead of a closure called inside the read. The mid-state is the one
/// deliberate exception to "one state type per message per role": a
/// suspension point *is* a state, and only qualifying patterns pay for
/// it.
fn gen_split_read(ctx: &Ctx<'_>, role: Role, msg: usize) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let vis = &ctx.input.vis;
    let name = ctx.name;
    let state = ctx.state_ident(role, msg);
    let mid = format_ident!("{}{}Msg{}Intro", ctx.name, role.name(), msg + 1);
    let curve = ctx.curve;
    let pubkey = ctx.pubkey_ty();
    let inner_ty = ctx.inner_ty();
    let size = ctx.size_path(msg);
    let read_method = method_ident(false, msg);
    let intro_method = intro_ident(msg);
    let with_method = with_ident(msg);
    let tail_const = format_ident!("MSG{}_INTRO_TAIL", msg + 1);
    let next = next_state(ctx, role, msg);

    // Split point: everything through the *last* `s` is intro's; the
    // trailing DH token(s) and the tail are `complete`'s. Derived from
    // the token list rather than assumed from the predicate's current
    // shape, so widening `split_read_on` cannot desynchronise it.
    let split = line
        .tokens
        .iter()
        .rposition(|(t, _)| *t == Tok::S)
        .expect("split_read_on guarantees an `s`")
        + 1;
    let prefix = &line.tokens[..split];
    let (intro_args, intro_stmts) = read_token_stmts(ctx, role, ReadStyle::Plain, prefix, true);
    let (_, complete_stmts) =
        read_token_stmts(ctx, role, ReadStyle::Plain, &line.tokens[split..], false);

    let intro_dhs = prefix
        .iter()
        .filter(|(t, _)| matches!(t, Tok::Ee | Tok::Es | Tok::Se | Tok::Ss))
        .count();
    let dh_ops = if intro_dhs == 1 {
        "1 DH operation".to_string()
    } else {
        format!("{intro_dhs} DH operations")
    };

    let mut intro_doc = format!(
        "Begin reading handshake message 1 (`{}`) in two stages — the \
         suspending sibling of [`{with_method}`](Self::{with_method}): \
         instead of a closure deciding inside the read, the read stops at \
         the revealed identity and hands control back. Token by token, \
         this call performs:\n",
        line.render(),
    );
    for (tok, _) in prefix {
        if *tok == Tok::S {
            intro_doc.push_str(
                "\n* `s` — reads (and decrypts) the peer's **claimed** \
                 static public key: returned by value, and observable on \
                 the mid-state via `claimed_static()`",
            );
        } else {
            intro_doc.push_str(&format!("\n* {}", token_bullet(*tok, false)));
        }
    }
    intro_doc.push_str(&format!(
        "\n\nThat is exactly {dh_ops}; the proving `ss` and the message's \
         tail wait in the returned [`{mid}`]. Nothing of `message` is \
         borrowed — the un-read tail is copied into the mid-state, so it \
         is a plain owned value to park across event-loop turns while the \
         identity is judged. Continue with [`complete`]({mid}::complete), \
         or drop the mid-state to reject the peer: rejection costs only \
         the DH work above.\n\nAt this point the identity is **claimed, \
         not yet proven** — ownership of the key is only established by \
         the tokens `complete()` pays — so rejecting is always safe, but \
         nothing may treat the key as authenticated until `complete()` \
         succeeds."
    ));

    let mid_doc = format!(
        "**{name}** {} — suspended inside message 1 (`{}`), after its \
         revealed `s` and before the rest: created by \
         [`{intro_method}`]({state}::{intro_method}), finished by \
         [`complete`](Self::complete).\n\nThe peer's **claimed** static is \
         revealed ([`claimed_static`](Self::claimed_static)); the proving \
         `ss` and the message's tail are unpaid. A self-contained owned \
         value: the handshake state plus the message's remaining \
         [`{name}::{tail_const}`] bytes — no borrow of the input buffer, \
         and no bytes re-supplied at `complete()`. Park it and decide at \
         leisure; dropping it abandons the handshake with no further \
         work. Key material is scrubbed on drop by the handshake state's \
         own `Drop` implementations — this type holds none outside types \
         that already scrub themselves.",
        role.name().to_lowercase(),
        line.render(),
    );

    let claimed_doc = "The peer's **claimed** static public key, as revealed by \
         message 1's `s` token — decrypted, but not yet proven: ownership \
         of the key is only established when [`complete`](Self::complete) \
         succeeds. Judge it against your trust store; side effects must \
         not treat it as authenticated.";

    let (ret_ty, tail_stmts, ok_expr) = recv_tail_arm(line, &next, quote!(&self.tail));
    let payload_sentence = match line.payload {
        Some(payload) => format!(
            "decrypts the {}-byte payload and verifies the message's tag",
            payload.len
        ),
        None => "verifies the message's authentication tag".to_string(),
    };

    // `claimed_static` sits on its own `CryptoKeyProvider` impl — the
    // same bound split `gen_key_accessors` uses for every state's
    // accessors — even though only a `DhProvider` entry point can ever
    // construct the mid-state: accessors never need DH, and the
    // convention stays uniform across the generated surface.

    let complete_doc = format!(
        "Finish reading message 1: pays the remaining `ss` DH, then \
         {payload_sentence}.\n\nOn success this returns exactly what the \
         one-shot [`{read_method}`]({state}::{read_method}) would have — \
         transcript byte-identical, so the handshake proceeds as if the \
         read had never been suspended. On failure it returns the error \
         and yields **neither** payload nor state: `complete` consumes \
         the mid-state, so a failed read cannot be retried."
    );

    quote! {
        impl<CP> #state<CP>
        where
            CP: ::hiss::provider::DhProvider<#curve>,
        {
            #[doc = #intro_doc]
            pub fn #intro_method(
                mut self,
                message: &[u8; #size]
                #intro_args
            ) -> ::core::result::Result<(#pubkey, #mid<CP>), ::hiss::noise::HandshakeError>
            {
                let cursor = 0usize;
                #intro_stmts
                debug_assert_eq!(
                    cursor + #name::#tail_const,
                    #size,
                    "message size bookkeeping"
                );
                let mut tail = [0u8; #name::#tail_const];
                tail.copy_from_slice(&message[cursor..]);
                Ok((remote_static, #mid { inner: self.inner, tail }))
            }
        }

        // The staged pair is opt-in surface: a consumer that never
        // suspends leaves the mid-state unconstructed, and generated
        // code must not warn for an API choice.
        #[allow(dead_code)]
        #[doc = #mid_doc]
        #[must_use = "dropping this abandons the handshake; call `complete()` to finish reading message 1"]
        #vis struct #mid<CP>
        where
            CP: ::hiss::provider::CryptoKeyProvider<#curve>,
        {
            inner: #inner_ty,
            tail: [u8; #name::#tail_const],
        }

        impl<CP> #mid<CP>
        where
            CP: ::hiss::provider::CryptoKeyProvider<#curve>,
        {
            #[doc = #claimed_doc]
            pub fn claimed_static(&self) -> &#pubkey {
                ::hiss::noise::support::remote_static(&self.inner)
                    .expect("set by this message's `s` token; guaranteed by the state machine")
            }
        }

        impl<CP> #mid<CP>
        where
            CP: ::hiss::provider::DhProvider<#curve>,
        {
            #[doc = #complete_doc]
            pub fn complete(
                mut self
            ) -> ::core::result::Result<#ret_ty, ::hiss::noise::HandshakeError>
            {
                #complete_stmts
                #tail_stmts
                Ok(#ok_expr)
            }
        }
    }
}

/// The `support` DH helper for a role-sensitive token.
fn dh_call(tok: Tok, role: Role) -> Ident {
    match (tok, role) {
        (Tok::Ee, _) => format_ident!("ee"),
        (Tok::Ss, _) => format_ident!("ss"),
        (Tok::Es, Role::Initiator) => format_ident!("es_initiator"),
        (Tok::Es, Role::Responder) => format_ident!("es_responder"),
        (Tok::Se, Role::Initiator) => format_ident!("se_initiator"),
        (Tok::Se, Role::Responder) => format_ident!("se_responder"),
        _ => unreachable!("dh_call only handles DH tokens"),
    }
}

// ═══════════════════════════════════════════════════════════════
//  Generated usage walkthrough (for the marker type's docs)
// ═══════════════════════════════════════════════════════════════

/// The concrete suite types `hiss` exports from `hiss::noise`.
///
/// A doctest is compiled as its own crate: it inherits neither the
/// invocation site's `use` items nor its module path, so a suite written
/// as a bare `X25519` only resolves there if we can respell it
/// absolutely. These are the names we can — see [`doctest_suite_path`].
const HISS_SUITE_TYPES: &[&str] = &[
    "AesGcm",
    "Blake2b",
    "Blake2s",
    "ChaChaPoly",
    "P256",
    "Sha256",
    "Sha512",
    "X25519",
    "X448",
];

/// A suite path respelled so it resolves from the root of a doctest
/// crate, or `None` when it cannot be — a suite named through a path
/// this cannot reconstruct is unreachable from there, and
/// [`gen_main_struct`] falls back to an uncompiled sketch.
///
/// The bare-ident arm matches on the *name written*, not on what it
/// resolves to, because a proc macro has no name resolution. So
/// `use hiss::noise::P256 as X25519;` is accepted and the doctest is
/// built over hiss's real `X25519`. That is deliberate: the alternative
/// is dropping the bare-ident arm, which is how nearly every suite is
/// actually spelled, and the mismatch is contained — the doctest is
/// hermetic, so it cannot go red, and the rendered docs still name the
/// suite exactly as it was written.
fn doctest_suite_path(path: &Path) -> Option<String> {
    let rendered = quote!(#path).to_string().replace(' ', "");
    if let Some(ident) = path.get_ident() {
        let name = ident.to_string();
        return HISS_SUITE_TYPES
            .contains(&name.as_str())
            .then(|| format!("::hiss::noise::{name}"));
    }
    if let Some(rest) = rendered.strip_prefix("hiss::") {
        return Some(format!("::hiss::{rest}"));
    }
    rendered.starts_with("::hiss::").then_some(rendered)
}

/// The role's walkthrough as a **doctest that compiles**, or `None` when
/// the suite cannot be reached from a doctest crate.
///
/// The visible lines are exactly [`usage_snippet`]'s call sequence. What
/// is hidden makes them type-check without inventing values the reader
/// would then have to unlearn: the same pattern re-declared over the
/// same suite (absolutely spelled, so no import or module path is
/// assumed), and a never-called generic function whose parameters are
/// the walkthrough's placeholders — `provider`, `prologue`, the peer's
/// message bytes — at their real types. Nothing runs; what is checked is
/// that this call sequence is the API the macro actually generates.
fn usage_doctest(ctx: &Ctx<'_>, role: Role, staged: bool) -> Option<String> {
    let curve = doctest_suite_path(ctx.curve)?;
    let cipher = doctest_suite_path(ctx.cipher)?;
    let hash = doctest_suite_path(ctx.hash)?;
    let name = ctx.name;
    let privkey = format!("<CP as ::hiss::provider::CryptoKeyProvider<{curve}>>::PrivateKey");
    let pubkey = format!("<{curve} as ::hiss::curve::Curve>::PublicKey");

    // `extern crate hiss;` is what makes this work on a 2015-edition
    // consumer, where a doctest crate gets no extern prelude and every
    // `::hiss::…` path below is otherwise E0433. It is legal and silent
    // on 2018 and later, so it is emitted unconditionally — the macro
    // cannot see the caller's edition.
    let mut out = String::from(
        "# #![allow(unused)]\n# extern crate hiss;\n# fn main() {}\n# ::hiss::noise! {\n",
    );
    out.push_str(&format!("#     pub {name}<{curve}, {cipher}, {hash}> {{\n"));
    for line in &ctx.input.pre_messages {
        out.push_str(&format!("#         {}\n", line.render()));
    }
    if !ctx.input.pre_messages.is_empty() {
        out.push_str("#         ...\n");
    }
    for line in &ctx.input.messages {
        out.push_str(&format!("#         {}\n", line.render()));
    }
    out.push_str(
        "#     }\n# }\n# fn walkthrough<CP>(\n#     provider: CP,\n#     prologue: &[u8],\n",
    );

    // Every placeholder the snippet names, at the type the generated API
    // gives it — in the order the walkthrough reaches for them.
    let mut static_key_bound = false;
    for (local, _) in premessage_params(ctx, role) {
        if local {
            out.push_str(&format!("#     static_key: {privkey},\n"));
            static_key_bound = true;
        } else {
            out.push_str(&format!("#     remote_static: {pubkey},\n"));
        }
    }
    for (i, line) in ctx.input.messages.iter().enumerate() {
        if line.dir == role.send_dir() {
            if has_tok(line, Tok::S) && !static_key_bound {
                out.push_str(&format!("#     static_key: {privkey},\n"));
                static_key_bound = true;
            }
            if let Some(payload) = line.payload {
                out.push_str(&format!("#     payload{}: [u8; {}],\n", i + 1, payload.len));
            }
        } else {
            // Received bytes: the peer's, so they arrive as a parameter
            // rather than being conjured — a conjured one would decrypt
            // to an error and the doctest would fail at run time.
            out.push_str(&format!(
                "#     msg{}: [u8; {name}::MSG{}_SIZE],\n",
                i + 1,
                i + 1
            ));
            // The identity hook the walkthrough hands to `_with`: a PSK
            // lookup where `s` precedes `psk`, a plain accept/reject
            // otherwise. At most one per role — re-sending `s` is not a
            // well-formed pattern.
            if has_tok(line, Tok::S) {
                let (arg, ret) = if psk_after_s(line) {
                    ("psk_for_peer", "::hiss::psk::Psk")
                } else {
                    ("accept_peer", "()")
                };
                // Prelude names, not `::core::…`: an edition-2015
                // doctest has no `core` at its crate root, and unlike
                // the generated code this text is not macro-expanded.
                out.push_str(&format!(
                    "#     {arg}: impl FnOnce(\n#         &{pubkey},\n\
                     #     ) -> Result<{ret}, ::hiss::noise::HandshakeError>,\n"
                ));
            }
        }
    }
    if ctx.input.has_psk() {
        out.push_str("#     psk: ::hiss::psk::Psk,\n");
    }

    out.push_str("# ) -> Result<(), ::hiss::noise::HandshakeError>\n");
    out.push_str(&format!(
        "# where\n#     CP: ::hiss::provider::DhProvider<{curve}>,\n# {{\n"
    ));
    out.push_str(&usage_snippet(ctx, role, staged));
    out.push_str("# Ok(())\n# }\n");
    Some(out)
}

fn usage_snippet(ctx: &Ctx<'_>, role: Role, staged: bool) -> String {
    let name = ctx.name;
    let params = premessage_params(ctx, role);
    let fallible = params.iter().any(|(local, _)| *local);

    let mut out = String::new();
    let mut pre_args = String::new();
    for (local, _) in &params {
        pre_args.push_str(if *local {
            ", static_key"
        } else {
            ", remote_static"
        });
    }
    out.push_str(&format!(
        "let hs = {name}::{}(provider, prologue{pre_args}){};\n",
        role.name().to_lowercase(),
        if fallible { "?" } else { "" },
    ));

    let last = ctx.input.messages.len() - 1;
    for (i, line) in ctx.input.messages.iter().enumerate() {
        let state = if i == last { "transport" } else { "hs" };
        if line.dir == role.send_dir() {
            let mut args = String::new();
            for (tok, _) in &line.tokens {
                match tok {
                    Tok::S => args.push_str(", static_key"),
                    Tok::Psk => args.push_str(", &psk"),
                    _ => {}
                }
            }
            if line.payload.is_some() {
                args.push_str(&format!(", &payload{}", i + 1));
            }
            let args = args.trim_start_matches(", ");
            out.push_str(&format!(
                "let (msg{}, {state}) = hs.write_message_{}({args})?; // {}\n",
                i + 1,
                i + 1,
                line.render(),
            ));
        } else if staged && split_read_on(i, line) {
            // The staged read: intro, the trust decision in the open, then
            // complete. A pre-`s` psk rides intro; the payload arrives at
            // complete. `accept_peer` plays the decision the reader would
            // otherwise make inside the `_with` closure.
            let mut args = format!("&msg{}", i + 1);
            if has_tok(line, Tok::Psk) {
                args.push_str(", &psk");
            }
            let binding = if line.payload.is_some() {
                format!("(payload{}, {state})", i + 1)
            } else {
                state.to_string()
            };
            out.push_str(
                "// The claimed identity arrives with the proving DH still unpaid —\n\
                 // hold `mid` across turns while deciding; dropping it rejects.\n",
            );
            out.push_str(&format!(
                "let (claimed, mid) = hs.read_message_{}_intro({args})?; // {}\n",
                i + 1,
                line.render(),
            ));
            out.push_str("accept_peer(&claimed)?;\n");
            out.push_str(&format!("let {binding} = mid.complete()?;\n"));
        } else {
            // A read that reveals the peer's static is shown in its
            // `_with` form. Completing a Noise pattern proves the peer
            // holds *a* static key; it says nothing about whether that
            // key is one you trust, and the plain read gives the
            // walkthrough's reader no place to say so.
            let hook = has_tok(line, Tok::S);
            let lookup = hook && psk_after_s(line);
            let mut args = format!("&msg{}", i + 1);
            if lookup {
                // `s` names the peer before `psk` needs a key, so the
                // lookup closure is already the identity hook.
                args.push_str(", psk_for_peer");
            } else {
                if has_tok(line, Tok::Psk) {
                    args.push_str(", &psk");
                }
                if hook {
                    args.push_str(", accept_peer");
                }
            }
            let binding = if line.payload.is_some() {
                format!("(payload{}, {state})", i + 1)
            } else {
                state.to_string()
            };
            if lookup {
                out.push_str(
                    "// `s` names the peer before `psk` needs a key, so the lookup is the\n\
                     // trust decision too: `Err` rejects a peer you hold no PSK for.\n",
                );
            } else if hook {
                out.push_str(
                    "// Completing this proves the peer holds a static key, not that you\n\
                     // trust it — `accept_peer` is that decision, and `Err` aborts here.\n",
                );
            }
            out.push_str(&format!(
                "let {binding} = hs.read_message_{}{}({args})?; // {}\n",
                i + 1,
                if hook { "_with" } else { "" },
                line.render(),
            ));
            if hook {
                out.push_str(&format!(
                    "let peer_identity = {state}.remote_static(); // the key you just accepted\n",
                ));
            }
        }
    }
    out
}
