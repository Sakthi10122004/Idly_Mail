//! FETCH data items (RFC 9051 §6.4.5), BINARY (RFC 9051 §6.4.5, from
//! RFC 3516) and MODSEQ (RFC 7162 §3.1.4).

use crate::parse::{Cursor, Result, err};

/// What part of a message BODY[...] refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionText {
    Header,
    HeaderFields { not: bool, fields: Vec<String> },
    Text,
    /// The MIME header of a part (only with a part number).
    Mime,
}

/// `section-spec`: a part path and what of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Section {
    pub part: Vec<u32>,
    pub text: Option<SectionText>,
}

/// A FETCH data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchAttr {
    Envelope,
    Flags,
    InternalDate,
    Rfc822Size,
    /// RFC822 (= BODY[]), RFC822.HEADER (= BODY.PEEK[HEADER]),
    /// RFC822.TEXT (= BODY[TEXT]): IMAP4rev1 forms.
    Rfc822,
    Rfc822Header,
    Rfc822Text,
    /// BODY (BODYSTRUCTURE without extension data).
    Body,
    BodyStructure,
    Uid,
    ModSeq,
    BodySection {
        peek: bool,
        section: Section,
        partial: Option<(u32, u32)>,
    },
    Binary {
        peek: bool,
        part: Vec<u32>,
        partial: Option<(u32, u32)>,
    },
    BinarySize(Vec<u32>),
}

/// The attributes after the sequence set: a macro, one item or a list.
pub(crate) fn parse_fetch_attrs(c: &mut Cursor<'_>) -> Result<Vec<FetchAttr>> {
    use FetchAttr::*;
    if c.eat_word("ALL") {
        return Ok(vec![Flags, InternalDate, Rfc822Size, Envelope]);
    }
    if c.eat_word("FAST") {
        return Ok(vec![Flags, InternalDate, Rfc822Size]);
    }
    if c.eat_word("FULL") {
        return Ok(vec![Flags, InternalDate, Rfc822Size, Envelope, Body]);
    }
    if c.peek() == Some(b'(') {
        let attrs = c.list(attr)?;
        if attrs.is_empty() {
            return err("empty FETCH list");
        }
        return Ok(attrs);
    }
    Ok(vec![attr(c)?])
}

fn attr(c: &mut Cursor<'_>) -> Result<FetchAttr> {
    use FetchAttr::*;
    // Longer names first: "BODY" is a prefix of the others.
    if c.eat_word("BODYSTRUCTURE") {
        return Ok(BodyStructure);
    }
    if c.eat_word("BODY.PEEK") {
        return body_section(c, true);
    }
    if c.eat_word("BODY") {
        if c.peek() == Some(b'[') {
            return body_section(c, false);
        }
        return Ok(Body);
    }
    if c.eat_word("BINARY.PEEK") {
        return binary(c, true);
    }
    if c.eat_word("BINARY.SIZE") {
        let part = binary_part(c)?;
        return Ok(BinarySize(part));
    }
    if c.eat_word("BINARY") {
        return binary(c, false);
    }
    if c.eat_word("RFC822.SIZE") {
        return Ok(Rfc822Size);
    }
    if c.eat_word("RFC822.HEADER") {
        return Ok(Rfc822Header);
    }
    if c.eat_word("RFC822.TEXT") {
        return Ok(Rfc822Text);
    }
    if c.eat_word("RFC822") {
        return Ok(Rfc822);
    }
    let a = c.atom()?.to_ascii_uppercase();
    Ok(match a.as_str() {
        "ENVELOPE" => Envelope,
        "FLAGS" => Flags,
        "INTERNALDATE" => InternalDate,
        "UID" => Uid,
        "MODSEQ" => ModSeq,
        _ => return err(format!("unknown FETCH item {a}")),
    })
}

fn part_numbers(c: &mut Cursor<'_>) -> Result<Vec<u32>> {
    let mut part = Vec::new();
    while matches!(c.peek(), Some(b'1'..=b'9')) {
        part.push(c.nz_number()?);
        if part.len() > 32 {
            return err("section path too deep");
        }
        if !c.eat(b'.') {
            break;
        }
    }
    Ok(part)
}

fn body_section(c: &mut Cursor<'_>, peek: bool) -> Result<FetchAttr> {
    c.expect(b'[')?;
    let part = part_numbers(c)?;
    let text = if c.peek() == Some(b']') {
        None
    } else {
        let w = c.atom()?.to_ascii_uppercase();
        Some(match w.as_str() {
            "HEADER" => SectionText::Header,
            "TEXT" => SectionText::Text,
            "MIME" if !part.is_empty() => SectionText::Mime,
            "HEADER.FIELDS" | "HEADER.FIELDS.NOT" => {
                c.sp()?;
                let fields = c.list(|c| Ok(String::from_utf8_lossy(&c.astring()?).into_owned()))?;
                if fields.is_empty() {
                    return err("empty header list");
                }
                SectionText::HeaderFields {
                    not: w.ends_with(".NOT"),
                    fields,
                }
            }
            _ => return err("bad section"),
        })
    };
    c.expect(b']')?;
    Ok(FetchAttr::BodySection {
        peek,
        section: Section { part, text },
        partial: partial(c)?,
    })
}

fn binary_part(c: &mut Cursor<'_>) -> Result<Vec<u32>> {
    c.expect(b'[')?;
    let part = part_numbers(c)?;
    c.expect(b']')?;
    Ok(part)
}

fn binary(c: &mut Cursor<'_>, peek: bool) -> Result<FetchAttr> {
    let part = binary_part(c)?;
    Ok(FetchAttr::Binary {
        peek,
        part,
        partial: partial(c)?,
    })
}

/// `<start.count>`.
fn partial(c: &mut Cursor<'_>) -> Result<Option<(u32, u32)>> {
    if !c.eat(b'<') {
        return Ok(None);
    }
    let start = c.number32()?;
    c.expect(b'.')?;
    let count = c.nz_number()?;
    c.expect(b'>')?;
    Ok(Some((start, count)))
}
