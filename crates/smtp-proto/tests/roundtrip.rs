//! Property tests: serializing a value and parsing it back gives the same
//! value, and the DATA codec is independent of how input is chunked.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use proptest::prelude::*;
use smtp_proto::data::{self, DataDecoder, Progress};
use smtp_proto::limits::REPLY_LINE;
use smtp_proto::*;

const LABEL: &str = "[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?";

fn domain() -> impl Strategy<Value = String> {
    proptest::collection::vec(LABEL, 1..4).prop_map(|labels| labels.join("."))
}

fn host() -> impl Strategy<Value = Host> {
    prop_oneof![
        domain().prop_map(Host::Domain),
        any::<[u8; 4]>().prop_map(|o| Host::Ipv4(o.into())),
        any::<[u8; 16]>().prop_map(|o| Host::Ipv6(o.into())),
        ("x-[a-z0-9]{1,5}", "[!-Z^-~]{1,10}")
            .prop_map(|(tag, content)| Host::General { tag, content }),
    ]
}

fn local_part() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::collection::vec("[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]{1,8}", 1..4)
            .prop_map(|atoms| atoms.join(".")),
        "([ !#-\\[\\]-~]|\\\\[ -~]){0,10}".prop_map(|q| format!("\"{q}\"")),
        "[a-z]{1,4}[é用சக்தி]{1,3}",
    ]
}

fn mailbox() -> impl Strategy<Value = Mailbox> {
    (local_part(), host()).prop_map(|(local_part, host)| Mailbox { local_part, host })
}

fn raw_param() -> impl Strategy<Value = RawParam> {
    ("X-[A-Z0-9]{1,6}", proptest::option::of("[!-<>-~]{1,10}"))
        .prop_map(|(keyword, value)| RawParam { keyword, value })
}

fn mail_params() -> impl Strategy<Value = Vec<MailParam>> {
    (
        proptest::option::of(any::<u64>().prop_map(MailParam::Size)),
        proptest::option::of(prop_oneof![
            Just(MailParam::Body(BodyType::SevenBit)),
            Just(MailParam::Body(BodyType::EightBitMime)),
            Just(MailParam::Body(BodyType::BinaryMime)),
        ]),
        proptest::option::of(Just(MailParam::SmtpUtf8)),
        proptest::option::of(Just(MailParam::RequireTls)),
        proptest::option::of(prop_oneof![
            Just(MailParam::Ret(Ret::Full)),
            Just(MailParam::Ret(Ret::Hdrs))
        ]),
        // Short enough that the xtext encoding stays within 100 characters.
        proptest::option::of("[ -~]{1,30}".prop_map(MailParam::EnvId)),
        proptest::option::of("[ -~é]{1,30}".prop_map(MailParam::Auth)),
        proptest::option::of(raw_param().prop_map(MailParam::Other)),
    )
        .prop_map(|(a, b, c, d, e, f, g, h)| {
            [a, b, c, d, e, f, g, h].into_iter().flatten().collect()
        })
}

fn rcpt_params() -> impl Strategy<Value = Vec<RcptParam>> {
    let notify = prop_oneof![
        Just(Notify::Never),
        (any::<bool>(), any::<bool>(), any::<bool>())
            .prop_filter("at least one", |(s, f, d)| *s || *f || *d)
            .prop_map(|(success, failure, delay)| Notify::On {
                success,
                failure,
                delay
            }),
    ];
    (
        proptest::option::of(notify.prop_map(RcptParam::Notify)),
        proptest::option::of(
            ("rfc822|utf-8", "[!-<>-~]{1,20}")
                .prop_map(|(addr_type, addr)| RcptParam::Orcpt { addr_type, addr }),
        ),
        proptest::option::of(raw_param().prop_map(RcptParam::Other)),
    )
        .prop_map(|(a, b, c)| [a, b, c].into_iter().flatten().collect())
}

fn atom_or_quoted() -> impl Strategy<Value = String> {
    prop_oneof!["[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]{1,10}", "\"[ a-z]{0,10}\""]
}

fn command() -> impl Strategy<Value = Command> {
    prop_oneof![
        domain().prop_map(|d| Command::Helo {
            name: ClientName::Valid(Host::Domain(d))
        }),
        host().prop_map(|h| Command::Ehlo {
            name: ClientName::Valid(h)
        }),
        "[a-z_ ]{0,12}_[a-z ]{0,5}".prop_map(|s| Command::Ehlo {
            name: ClientName::Invalid(s)
        }),
        (
            prop_oneof![
                Just(ReversePath::Null),
                mailbox().prop_map(ReversePath::Mailbox)
            ],
            mail_params()
        )
            .prop_map(|(from, params)| Command::Mail { from, params }),
        (
            prop_oneof![
                Just(ForwardPath::Postmaster),
                mailbox().prop_map(ForwardPath::Mailbox)
            ],
            rcpt_params()
        )
            .prop_map(|(to, params)| Command::Rcpt { to, params }),
        Just(Command::Data),
        (any::<u64>(), any::<bool>()).prop_map(|(size, last)| Command::Bdat { size, last }),
        Just(Command::Rset),
        atom_or_quoted().prop_map(Command::Vrfy),
        atom_or_quoted().prop_map(Command::Expn),
        proptest::option::of(atom_or_quoted()).prop_map(Command::Help),
        proptest::option::of("[ -~]{0,20}").prop_map(Command::Noop),
        Just(Command::Quit),
        Just(Command::StartTls),
        (
            "[A-Z0-9_-]{1,20}",
            proptest::option::of(prop_oneof![
                Just(InitialResponse::Empty),
                proptest::collection::vec("[A-Za-z0-9+/]{4}", 1..5)
                    .prop_map(|q| InitialResponse::Base64(q.concat())),
            ])
        )
            .prop_map(|(mechanism, initial_response)| Command::Auth {
                mechanism,
                initial_response
            }),
    ]
}

fn reply() -> impl Strategy<Value = Reply> {
    (2u16..=5, 0u16..=5, 0u16..=9)
        .prop_flat_map(|(a, b, c)| {
            let code = a * 100 + b * 10 + c;
            let class = u8::try_from(a).unwrap_or(5);
            // RFC 3463 §2: enhanced code classes are 2, 4 and 5 only.
            let enhanced = if class == 3 {
                Just(None).boxed()
            } else {
                proptest::option::of(
                    (0u16..1000, 0u16..1000).prop_map(move |(s, d)| EnhancedCode::new(class, s, d)),
                )
                .boxed()
            };
            // Text starts with a letter so it never looks like an enhanced code.
            let lines = proptest::collection::vec("([a-zA-Z][ -~]{0,30})?", 1..5);
            (Just(code), enhanced, lines)
        })
        .prop_map(|(code, enhanced, lines)| Reply {
            code,
            enhanced,
            lines,
        })
}

/// A CRLF message: lines of bytes without CR or LF, each ending in CRLF.
fn message() -> impl Strategy<Value = Vec<u8>> {
    let line = proptest::collection::vec(
        any::<u8>().prop_filter("no CR/LF", |b| *b != b'\r' && *b != b'\n'),
        0..40,
    );
    proptest::collection::vec(line, 0..10).prop_map(|lines| {
        lines
            .into_iter()
            .flat_map(|mut l| {
                l.extend_from_slice(b"\r\n");
                l
            })
            .collect()
    })
}

fn decode_chunks(wire: &[u8], chunks: &[usize]) -> (usize, Vec<u8>) {
    let mut d = DataDecoder::new(None);
    let mut out = Vec::new();
    let mut pos = 0;
    let mut rest = wire;
    for &size in chunks.iter().chain(std::iter::repeat(&usize::MAX)) {
        let (chunk, tail) = rest.split_at(size.min(rest.len()));
        match d.decode(chunk, &mut out).unwrap() {
            Progress::Done { consumed } => return (pos + consumed, out),
            Progress::NeedMore => {
                pos += chunk.len();
                rest = tail;
                assert!(!chunk.is_empty() || !rest.is_empty(), "ran out of input");
            }
        }
    }
    unreachable!()
}

proptest! {
    #[test]
    fn command_round_trip(cmd in command()) {
        let bytes = cmd.to_bytes();
        prop_assert!(bytes.ends_with(b"\r\n"));
        let line = &bytes[..bytes.len() - 2];
        prop_assert_eq!(Command::parse(line), Ok(cmd));
    }

    #[test]
    fn reply_round_trip(r in reply()) {
        let bytes = r.to_bytes();
        let parsed = Reply::parse(&bytes, REPLY_LINE * 4);
        prop_assert_eq!(parsed, Ok(Some((r, bytes.len()))));
    }

    #[test]
    fn data_round_trip(msg in message(), chunks in proptest::collection::vec(1usize..16, 0..20)) {
        let mut wire = Vec::new();
        data::encode(&msg, &mut wire).unwrap();
        wire.extend_from_slice(b"QUIT\r\n");
        let (consumed, out) = decode_chunks(&wire, &chunks);
        prop_assert_eq!(consumed, wire.len() - 6);
        prop_assert_eq!(out, msg);
    }

    #[test]
    fn decoder_never_ends_early_on_bare_line_endings(prefix in message(), junk in "[\\r\\n.]{1,6}") {
        // Arbitrary sequences of CR, LF and '.' after valid lines either
        // error, wait for more, or end exactly at a real CRLF.CRLF.
        let mut wire = prefix.clone();
        wire.extend_from_slice(junk.as_bytes());
        let mut d = DataDecoder::new(None);
        let mut out = Vec::new();
        if let Ok(Progress::Done { consumed }) = d.decode(&wire, &mut out) {
            let end = &wire[..consumed];
            prop_assert!(end == b".\r\n" || end.ends_with(b"\r\n.\r\n"), "{:?}", end);
        }
    }
}
