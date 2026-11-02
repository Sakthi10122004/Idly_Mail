use super::*;

const NESTED: &[u8] = b"From: Alice <alice@example.org>\r\n\
To: bob@example.com, \"Carol C\" <carol@example.com>\r\n\
Subject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\r\n\
Message-ID: <m1@example.org>\r\n\
Date: Mon, 2 Nov 2026 10:00:00 +0000\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
This is the preamble.\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Gr=C3=BC=C3=9Fe\r\n\
--inner\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hi</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"r.pdf\"\r\n\
Content-Disposition: attachment; filename*=utf-8''%E2%82%AC.pdf\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0=\r\n\
--outer\r\n\
Content-Type: message/rfc822\r\n\
\r\n\
From: Dave <dave@example.net>\r\n\
Subject: inner\r\n\
\r\n\
Inner body\r\n\
--outer--\r\n\
epilogue\r\n";

#[test]
fn nested_structure() {
    let root = parse(NESTED);
    assert_eq!(root.mime_type(), "multipart/mixed");
    let Kind::Multipart(parts) = &root.kind else {
        panic!()
    };
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0].mime_type(), "multipart/alternative");

    let plain = root.section(&[1, 1]).unwrap();
    assert_eq!(plain.mime_type(), "text/plain");
    assert_eq!(plain.encoding, "quoted-printable");
    assert_eq!(plain.text(NESTED), "Gr\u{fc}\u{df}e");
    assert_eq!(&NESTED[plain.body.clone()], b"Gr=C3=BC=C3=9Fe");
    assert_eq!(plain.lines, 1);

    let html = root.section(&[1, 2]).unwrap();
    assert_eq!(&NESTED[html.body.clone()], b"<p>Hi</p>");

    let pdf = root.section(&[2]).unwrap();
    assert_eq!(pdf.filename().as_deref(), Some("\u{20ac}.pdf"));
    assert_eq!(pdf.decoded_body(NESTED), b"%PDF-");
    assert_eq!(pdf.disposition.as_ref().unwrap().value, "attachment");

    let msg = root.section(&[3]).unwrap();
    let Kind::Message(inner) = &msg.kind else {
        panic!()
    };
    assert_eq!(inner.0.subject.as_deref(), Some("inner"));
    assert_eq!(msg.lines, 4);
    // 3.1 is the embedded message's (only) body part.
    let inner_body = root.section(&[3, 1]).unwrap();
    assert_eq!(&NESTED[inner_body.body.clone()], b"Inner body");
    assert!(root.section(&[4]).is_none());
    assert!(root.section(&[0]).is_none());
    assert_eq!(root.walk().len(), 7);
}

#[test]
fn envelope_fields() {
    let env = envelope(NESTED);
    assert_eq!(env.subject.as_deref(), Some("=?UTF-8?Q?Gr=C3=BC=C3=9Fe?="));
    assert_eq!(env.message_id.as_deref(), Some("<m1@example.org>"));
    assert_eq!(env.to.len(), 2);
    // RFC 9051 §7.5.2: Sender and Reply-To default to From.
    assert_eq!(env.sender, env.from);
    assert_eq!(env.reply_to, env.from);
    assert!(env.cc.is_empty() && env.in_reply_to.is_none());
}

#[test]
fn defaults_for_plain_messages() {
    let msg = b"Subject: hi\r\n\r\nline one\r\nline two";
    let root = parse(msg);
    assert_eq!(root.mime_type(), "text/plain");
    assert_eq!(root.charset().as_deref(), Some("us-ascii"));
    assert_eq!(root.encoding, "7BIT");
    assert_eq!(root.lines, 2);
    assert_eq!(root.header, 0..15);
    assert_eq!(&msg[root.body.clone()], b"line one\r\nline two");
    assert_eq!(root.section(&[1]), Some(&root));
}

#[test]
fn digest_children_default_to_messages() {
    let msg = b"Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: one\r\n\r\nx\r\n--d--\r\n";
    let root = parse(msg);
    let part = root.section(&[1]).unwrap();
    assert_eq!(part.mime_type(), "message/rfc822");
    assert!(matches!(&part.kind, Kind::Message(m) if m.0.subject.as_deref() == Some("one")));
}

#[test]
fn missing_close_delimiter_and_bare_lf() {
    let msg = b"Content-Type: multipart/mixed; boundary=b\n\n--b\nContent-Type: text/plain\n\nunterminated";
    let root = parse(msg);
    let Kind::Multipart(parts) = &root.kind else {
        panic!()
    };
    assert_eq!(parts.len(), 1);
    assert_eq!(&msg[parts[0].body.clone()], b"unterminated");
}

#[test]
fn broken_content_type_falls_back() {
    let root = parse(b"Content-Type: garbage\r\n\r\nx");
    assert_eq!(root.mime_type(), "text/plain");
    let root = parse(b"Content-Type: multipart/mixed\r\n\r\nno boundary");
    assert!(matches!(&root.kind, Kind::Multipart(p) if p.is_empty()));
}

#[test]
fn depth_and_part_limits_hold() {
    // A deeply nested chain of message/rfc822.
    let mut msg = Vec::new();
    for _ in 0..200 {
        msg.extend_from_slice(b"Content-Type: message/rfc822\r\n\r\n");
    }
    msg.extend_from_slice(b"Subject: deep\r\n\r\nbody");
    let root = parse(&msg);
    assert!(root.walk().len() <= MAX_DEPTH + 1);

    // A multipart with too many parts.
    let mut many = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n".to_vec();
    for _ in 0..5000 {
        many.extend_from_slice(b"--b\r\n\r\nx\r\n");
    }
    let root = parse(&many);
    assert!(root.walk().len() <= MAX_PARTS + 1);
}
