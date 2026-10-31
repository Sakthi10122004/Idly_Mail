//! `tag=value` lists, used by DKIM signatures and key records (RFC 6376
//! §3.2) and by DMARC records.

/// A parsed tag list. Tag names are case-sensitive (RFC 6376 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagList<'a> {
    tags: Vec<(&'a str, &'a str)>,
}

/// The tag list is malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTagList;

/// WSP and the CR/LF of folding (FWS).
fn is_fws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

impl<'a> TagList<'a> {
    /// Parses a tag list. RFC 6376 §3.2:
    /// ```text
    /// tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
    /// tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
    /// tag-name  =  ALPHA *ALNUMPUNC
    /// tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
    /// VALCHAR   =  %x21-3A / %x3C-7E
    /// ```
    /// Whitespace around values is dropped, whitespace inside is kept.
    /// A repeated tag name makes the whole list invalid.
    pub fn parse(input: &'a str) -> Result<Self, InvalidTagList> {
        let mut tags: Vec<(&str, &str)> = Vec::new();
        let specs: Vec<&str> = input.split(';').collect();
        let last = specs.len().saturating_sub(1);
        for (i, spec) in specs.into_iter().enumerate() {
            if spec.trim_matches(is_fws).is_empty() {
                // Only the optional trailing ";" may leave an empty spec.
                if i == last && i > 0 {
                    continue;
                }
                return Err(InvalidTagList);
            }
            let (name, value) = spec.split_once('=').ok_or(InvalidTagList)?;
            let name = name.trim_matches(is_fws);
            let value = value.trim_matches(is_fws);
            let mut chars = name.chars();
            if !chars.next().is_some_and(|c| c.is_ascii_alphabetic())
                || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(InvalidTagList);
            }
            // VALCHAR, or whitespace/folding between value characters.
            // Non-ASCII is tolerated, as RFC 6376 §3.2 advises for UTF-8.
            if !value
                .chars()
                .all(|c| matches!(c, '!'..=':' | '<'..='~') || is_fws(c) || !c.is_ascii())
            {
                return Err(InvalidTagList);
            }
            if tags.iter().any(|(n, _)| *n == name) {
                return Err(InvalidTagList);
            }
            tags.push((name, value));
        }
        Ok(Self { tags })
    }

    /// The value of tag `name`, if present.
    pub fn get(&self, name: &str) -> Option<&'a str> {
        self.tags.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }

    /// The first tag's name, if any.
    pub fn first_name(&self) -> Option<&'a str> {
        self.tags.first().map(|(n, _)| *n)
    }
}

/// Removes all whitespace (including folding) from a value, as needed for
/// base64 values such as DKIM `b=`, `bh=` and `p=` (RFC 6376 §3.5, §3.6.1).
pub(crate) fn strip_fws(v: &str) -> String {
    v.chars().filter(|&c| !is_fws(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims() {
        let t = TagList::parse(" v=1; a = rsa-sha256 ;\r\n\th=from : to;").unwrap();
        assert_eq!(t.get("v"), Some("1"));
        assert_eq!(t.get("a"), Some("rsa-sha256"));
        assert_eq!(t.get("h"), Some("from : to"), "inner whitespace kept");
        assert_eq!(t.get("x"), None);
        assert_eq!(t.first_name(), Some("v"));
    }

    #[test]
    fn empty_value_is_not_absent() {
        let t = TagList::parse("p=; k=rsa").unwrap();
        assert_eq!(t.get("p"), Some(""));
    }

    #[test]
    fn invalid_lists() {
        for bad in [
            "",
            ";",
            "a=1;;b=2",
            "a=1; a=2",
            "1a=x",
            "a",
            "a=1;b",
            "a=x;y",
            "a=semi\u{1}colon",
            "_a=1",
        ] {
            assert_eq!(TagList::parse(bad), Err(InvalidTagList), "{bad:?}");
        }
    }

    #[test]
    fn tags_are_case_sensitive() {
        let t = TagList::parse("A=1; a=2").unwrap();
        assert_eq!((t.get("A"), t.get("a")), (Some("1"), Some("2")));
    }

    #[test]
    fn strip_whitespace() {
        assert_eq!(strip_fws("ab cd\r\n\tef"), "abcdef");
    }
}
