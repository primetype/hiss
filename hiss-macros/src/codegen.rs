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
//! the same per-token engine the crate's own drivers use.
//!
//! PSKs are plain `&Psk` parameters — most deployments know the PSK in
//! advance. When a *received* message reveals the peer's static (`s`)
//! before its `psk` token (e.g. IKpsk1), an additional
//! `read_message_N_with` variant is generated whose PSK parameter is a
//! lookup closure `FnOnce(&PublicKey) -> Result<Psk, _>`, for
//! deployments that select a per-peer PSK (or reject unknown peers)
//! from the just-revealed identity.

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
    let initiator_usage = usage_snippet(ctx, Role::Initiator);
    let responder_usage = usage_snippet(ctx, Role::Responder);
    let generated = format!(
        "\n\n```text\n{diagram}```\n\nOver the suite {suite}. Generated by \
         `hiss::noise!`. Each handshake message is a fixed-size byte array \
         and no I/O is performed — transporting the messages is the \
         caller's job.\n\n# Usage\n\nAs the initiator:\n\n```ignore\
         \n{initiator_usage}```\n\nAs the responder:\n\n```ignore\
         \n{responder_usage}```"
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
        let doc = format!(
            "Exact wire size in bytes of handshake message {} (`{}`): the \
             token bytes plus the trailing empty-payload authentication \
             tag once the cipher is keyed.",
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
            });
        });
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
    if msg + 1 == ctx.input.messages.len() {
        doc.push_str(
            "\n\nThis is the final handshake message: it completes into the \
             session `Transport`.",
        );
    }
    doc
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
                let tail = #support::send_tail(&mut self.inner, &mut buf[cursor..])?;
                debug_assert_eq!(cursor + tail, #size, "message size bookkeeping");
                Ok((buf, #next_expr))
            }
        }
    }
}

/// How a receive method obtains the PSK for a `psk` token.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PskStyle {
    /// The PSK is known in advance: a plain `psk: &Psk` parameter.
    Plain,
    /// The PSK is selected per peer: a lookup closure over the identity
    /// the message reveals before its `psk` token.
    Lookup,
}

fn gen_read_message(ctx: &Ctx<'_>, role: Role, msg: usize) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let id = ctx.state_ident(role, msg);
    let curve = ctx.curve;

    // The plain form is always the primary method. When the message
    // reveals the peer's static before its `psk` token, an additional
    // `read_message_N_with` variant lets the PSK be selected per peer.
    let mut methods = gen_read_method(ctx, role, msg, PskStyle::Plain);
    if psk_after_s(line) {
        methods.extend(gen_read_method(ctx, role, msg, PskStyle::Lookup));
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

fn gen_read_method(ctx: &Ctx<'_>, role: Role, msg: usize, style: PskStyle) -> TokenStream {
    let line = &ctx.input.messages[msg];
    let size = ctx.size_path(msg);
    let support = quote!(::hiss::noise::support);
    let base = method_ident(false, msg);
    let method = match style {
        PskStyle::Plain => base.clone(),
        PskStyle::Lookup => format_ident!("{base}_with"),
    };
    let (next_ty, next_expr) = next_state(ctx, role, msg);
    let mut doc = message_doc(ctx, msg, false);
    match style {
        PskStyle::Plain if psk_after_s(line) => {
            let with = format_ident!("{base}_with");
            doc.push_str(&format!(
                "\n\nThe PSK is supplied up front. When it must instead be \
                 selected by the identity this message reveals (per-peer \
                 PSKs), use [`{with}`](Self::{with}).",
            ));
        }
        PskStyle::Lookup => {
            doc.push_str(
                "\n\nVariant taking the PSK as a **lookup**: the pattern \
                 places `psk` after the peer's identity is revealed, so the \
                 closure receives that identity and returns the PSK enrolled \
                 for it — or an error (e.g. \
                 `HandshakeError::PeerRejected`) to reject an unknown peer \
                 and abort the handshake.",
            );
        }
        PskStyle::Plain => {}
    }

    let mut args = TokenStream::new();
    let mut stmts = TokenStream::new();
    for (tok, _) in &line.tokens {
        match tok {
            Tok::E => stmts.extend(quote! {
                let (_remote_ephemeral, n) =
                    #support::recv_e(&mut self.inner, &message[cursor..])?;
                let cursor = cursor + n;
            }),
            // The revealed static is not returned: it stays observable via
            // `remote_static()` on the next state (or on the `Transport`).
            // The binding is only consumed by a PSK-lookup closure.
            Tok::S if style == PskStyle::Lookup => stmts.extend(quote! {
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
                PskStyle::Lookup => {
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
                PskStyle::Plain => {
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

    quote! {
        #[doc = #doc]
        pub fn #method(
            mut self,
            message: &[u8; #size]
            #args
        ) -> ::core::result::Result<#next_ty, ::hiss::noise::HandshakeError> {
            let cursor = 0usize;
            #stmts
            #support::recv_tail(&mut self.inner, &message[cursor..])?;
            Ok(#next_expr)
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

fn usage_snippet(ctx: &Ctx<'_>, role: Role) -> String {
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
            let args = args.trim_start_matches(", ");
            out.push_str(&format!(
                "let (msg{}, {state}) = hs.write_message_{}({args})?; // {}\n",
                i + 1,
                i + 1,
                line.render(),
            ));
        } else {
            let mut args = format!("&msg{}", i + 1);
            if has_tok(line, Tok::Psk) {
                args.push_str(", &psk");
            }
            out.push_str(&format!(
                "let {state} = hs.read_message_{}({args})?; // {}\n",
                i + 1,
                line.render(),
            ));
            if has_tok(line, Tok::S) {
                out.push_str(&format!(
                    "let peer_identity = {state}.remote_static(); // revealed by the `s` token\n",
                ));
            }
        }
    }
    out
}
