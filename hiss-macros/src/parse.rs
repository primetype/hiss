//! Parser for the `noise!` pattern DSL.
//!
//! The input mirrors the Noise specification's pattern notation
//! verbatim — it survives Rust's lexer because every piece of the
//! notation happens to be a valid Rust token (`->` is one token, `<-`
//! arrives as an adjacent `<` `-` pair, `...` is one token, the rest
//! are identifiers and commas):
//!
//! ```text
//! noise! {
//!     /// Ceremony channel between two enrolled devices.
//!     pub IKpsk1<X25519, ChaChaPoly, Blake2b> {
//!         <- s
//!         ...
//!         -> e, es, s, ss, psk
//!         <- e, ee, se
//!     }
//! }
//! ```
//!
//! Lines before the `...` separator are pre-messages; lines after it
//! are the handshake messages. Without a `...` the whole body is
//! handshake messages (patterns like `NN`/`XX` have no pre-messages).
//!
//! Only *surface* syntax is validated here (unknown tokens, misplaced
//! separators, duplicate tokens within a message). Noise §7.3 validity —
//! every DH operating on transmitted keys, the cipher ending keyed — is
//! deliberately **not** re-implemented: the generated code asserts
//! `hiss`'s type-level `WellFormed` guard, so those errors surface at
//! the macro invocation with the diagnostics `hiss` already provides.

use proc_macro2::Span;
use syn::parse::{Parse, ParseStream};
use syn::{Attribute, Ident, Path, Token, Visibility, braced};

/// One Noise token, with the span of the identifier that named it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tok {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
    Psk,
}

impl Tok {
    fn from_ident(ident: &Ident) -> syn::Result<Self> {
        match ident.to_string().as_str() {
            "e" => Ok(Tok::E),
            "s" => Ok(Tok::S),
            "ee" => Ok(Tok::Ee),
            "es" => Ok(Tok::Es),
            "se" => Ok(Tok::Se),
            "ss" => Ok(Tok::Ss),
            "psk" => Ok(Tok::Psk),
            other => Err(syn::Error::new(
                ident.span(),
                format!(
                    "unknown Noise token `{other}`; expected one of \
                     `e`, `s`, `ee`, `es`, `se`, `ss`, `psk`"
                ),
            )),
        }
    }

    /// The token as written in Noise notation (`es`, `psk`, …).
    pub(crate) fn noise_name(self) -> &'static str {
        match self {
            Tok::E => "e",
            Tok::S => "s",
            Tok::Ee => "ee",
            Tok::Es => "es",
            Tok::Se => "se",
            Tok::Ss => "ss",
            Tok::Psk => "psk",
        }
    }

    /// The `hiss::noise` marker type name (`Es`, `Psk`, …).
    pub(crate) fn type_name(self) -> &'static str {
        match self {
            Tok::E => "E",
            Tok::S => "S",
            Tok::Ee => "Ee",
            Tok::Es => "Es",
            Tok::Se => "Se",
            Tok::Ss => "Ss",
            Tok::Psk => "Psk",
        }
    }
}

/// Message direction. `->` is initiator-to-responder.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    ToResponder,
    ToInitiator,
}

impl Dir {
    /// The arrow as written in Noise notation.
    pub(crate) fn arrow(self) -> &'static str {
        match self {
            Dir::ToResponder => "->",
            Dir::ToInitiator => "<-",
        }
    }
}

/// One pre-message or handshake message line: an arrow and its tokens.
pub(crate) struct Line {
    pub(crate) dir: Dir,
    pub(crate) tokens: Vec<(Tok, Span)>,
}

impl Line {
    /// Render the line in Noise notation, e.g. `-> e, es, s, ss, psk`.
    pub(crate) fn render(&self) -> String {
        let tokens = self
            .tokens
            .iter()
            .map(|(t, _)| t.noise_name())
            .collect::<Vec<_>>()
            .join(", ");
        format!("{} {}", self.dir.arrow(), tokens)
    }
}

/// The suite a handshake is pinned to — the DH curve, AEAD cipher, and
/// hash named between angle brackets. When absent, the invocation is in
/// *marker mode*: only the pattern marker (and its `Pattern` impl) is
/// generated, no state machines.
pub(crate) struct Suite {
    pub(crate) curve: Path,
    pub(crate) cipher: Path,
    pub(crate) hash: Path,
}

/// The fully parsed `noise!` invocation.
pub(crate) struct NoiseInput {
    pub(crate) attrs: Vec<Attribute>,
    pub(crate) vis: Visibility,
    pub(crate) name: Ident,
    pub(crate) suite: Option<Suite>,
    pub(crate) pre_messages: Vec<Line>,
    pub(crate) messages: Vec<Line>,
}

impl NoiseInput {
    /// Whether any handshake message carries a `psk` token.
    pub(crate) fn has_psk(&self) -> bool {
        self.messages
            .iter()
            .any(|m| m.tokens.iter().any(|(t, _)| *t == Tok::Psk))
    }
}

impl Parse for NoiseInput {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let attrs = input.call(Attribute::parse_outer)?;
        let vis: Visibility = input.parse()?;
        let name: Ident = input.parse()?;

        let suite = if input.peek(Token![<]) {
            input.parse::<Token![<]>()?;
            let curve: Path = input.parse()?;
            input.parse::<Token![,]>()?;
            let cipher: Path = input.parse()?;
            input.parse::<Token![,]>()?;
            let hash: Path = input.parse()?;
            input.parse::<Token![>]>()?;
            Some(Suite {
                curve,
                cipher,
                hash,
            })
        } else {
            None
        };

        let content;
        braced!(content in input);

        let mut pre_messages: Vec<Line> = Vec::new();
        let mut messages: Vec<Line> = Vec::new();
        let mut seen_separator = false;

        while !content.is_empty() {
            if content.peek(Token![...]) {
                let sep: Token![...] = content.parse()?;
                if seen_separator {
                    return Err(syn::Error::new(
                        sep.spans[0],
                        "the `...` pre-message separator may appear only once",
                    ));
                }
                seen_separator = true;
                pre_messages = std::mem::take(&mut messages);
                continue;
            }

            let dir = if content.peek(Token![->]) {
                content.parse::<Token![->]>()?;
                Dir::ToResponder
            } else if content.peek(Token![<]) {
                content.parse::<Token![<]>()?;
                content.parse::<Token![-]>()?;
                Dir::ToInitiator
            } else {
                return Err(content.error("expected `->`, `<-`, or `...`"));
            };

            let mut tokens: Vec<(Tok, Span)> = Vec::new();
            loop {
                let ident: Ident = content.parse()?;
                let tok = Tok::from_ident(&ident)?;
                if tokens.iter().any(|(t, _)| *t == tok) {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "token `{}` appears twice in the same message",
                            tok.noise_name()
                        ),
                    ));
                }
                tokens.push((tok, ident.span()));
                if content.peek(Token![,]) {
                    content.parse::<Token![,]>()?;
                } else {
                    break;
                }
            }
            messages.push(Line { dir, tokens });
        }

        if messages.is_empty() {
            return Err(syn::Error::new(
                name.span(),
                "a Noise pattern needs at least one handshake message after `...`",
            ));
        }

        for line in &pre_messages {
            for (tok, span) in &line.tokens {
                if *tok != Tok::S {
                    return Err(syn::Error::new(
                        *span,
                        format!(
                            "only `s` pre-messages are supported, found `{}`",
                            tok.noise_name()
                        ),
                    ));
                }
            }
        }

        Ok(NoiseInput {
            attrs,
            vis,
            name,
            suite,
            pre_messages,
            messages,
        })
    }
}
