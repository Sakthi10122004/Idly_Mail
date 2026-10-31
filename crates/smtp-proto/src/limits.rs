//! Size limits from RFC 5321 §4.5.3.1. All lengths are in octets.
//!
//! RFC 5321 §4.5.3.1 asks implementations to avoid limits on these objects
//! "to the maximum extent possible". We therefore only enforce the line
//! limits (which bound memory) and the DNS limits on domains (which are hard
//! limits in DNS itself). The local-part and path limits are exported for
//! callers that want them, but the parser does not apply them: real-world
//! addresses such as SRS rewrites often exceed 64 octets.

/// Maximum command line, CRLF included. RFC 5321 §4.5.3.1.4.
pub const COMMAND_LINE: usize = 512;

/// Maximum AUTH command line. RFC 4954 §4 requires handling the largest
/// encoded responses of the supported mechanisms, and notes that 12288
/// octets is considered sufficient for deployed mechanisms.
pub const AUTH_COMMAND_LINE: usize = 12288;

/// Maximum reply line, CRLF included. RFC 5321 §4.5.3.1.5.
pub const REPLY_LINE: usize = 512;

/// Maximum text line in DATA, CRLF included. RFC 5321 §4.5.3.1.6.
pub const TEXT_LINE: usize = 1000;

/// Maximum local-part. RFC 5321 §4.5.3.1.1. Not enforced by the parser.
pub const LOCAL_PART: usize = 64;

/// Maximum domain name. RFC 5321 §4.5.3.1.2; RFC 1035 §2.3.4.
pub const DOMAIN: usize = 255;

/// Maximum DNS label. RFC 1035 §2.3.4.
pub const LABEL: usize = 63;

/// Maximum path, angle brackets included. RFC 5321 §4.5.3.1.3. Not enforced
/// by the parser.
pub const PATH: usize = 256;
