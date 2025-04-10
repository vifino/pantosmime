use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::{line_ending, not_line_ending, space0, space1},
    multi::many0,
    sequence::{preceded, terminated},
    IResult,
};
use std::borrow::Cow;
use uuid::Uuid;

/// A MIME container holds a list of headers (in order), a body (preamble or full body)
/// and, in the case of multipart messages, a list of parts.
#[derive(Debug, PartialEq)]
pub struct MimeContainer<'a> {
    pub headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub body: Cow<'a, str>,
    pub parts: Vec<MimeContainer<'a>>,
}

/// Parse a single header line, supporting folded lines (i.e. lines that begin with a space or tab).
fn parse_header(input: &str) -> IResult<&str, (Cow<str>, Cow<str>)> {
    // Header names: alphanumerics, '-' and '_'
    let (input, name) =
        take_while1(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_')(input)?;
    let (input, _) = tag(":")(input)?;
    let (input, first_line) = preceded(space0, not_line_ending)(input)?;
    let (input, _) = line_ending(input)?;
    let (input, folded_lines) =
        many0(preceded(space1, terminated(not_line_ending, line_ending)))(input)?;
    if folded_lines.is_empty() {
        Ok((
            input,
            (Cow::Borrowed(name), Cow::Borrowed(first_line.trim())),
        ))
    } else {
        let mut value = first_line.trim().to_string();
        for line in folded_lines {
            value.push(' ');
            value.push_str(line.trim());
        }
        Ok((input, (Cow::Borrowed(name), Cow::Owned(value))))
    }
}

/// A helper parser that accepts either CRLF ("\r\n") or LF ("\n") line endings.
fn line_ending_custom(input: &str) -> IResult<&str, &str> {
    alt((tag("\r\n"), tag("\n")))(input)
}

/// Parse all headers until an empty line is encountered.
fn parse_headers(input: &str) -> IResult<&str, Vec<(Cow<str>, Cow<str>)>> {
    let mut headers = Vec::new();
    let mut input = input;
    loop {
        // An empty line signals the end of headers.
        if let Ok((remaining, _)) = line_ending_custom(input) {
            input = remaining;
            break;
        }
        let (remaining, header) = parse_header(input)?;
        headers.push(header);
        input = remaining;
    }
    Ok((input, headers))
}

/// Retrieve the Content-Type header value (case-insensitive).
fn get_content_type<'a>(headers: &'a [(Cow<str>, Cow<str>)]) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        .map(|(_, value)| value.to_string())
}

/// Extract the boundary parameter from a Content-Type header value.
fn extract_boundary(content_type: &str) -> Option<&str> {
    let lower = content_type.to_ascii_lowercase();
    if let Some(pos) = lower.find("boundary=") {
        // TODO: this is probably way too naive.
        let after = &content_type[pos + "boundary=".len()..];
        let boundary = after.trim().trim_matches(|c| c == '"' || c == '\'');
        let boundary = boundary
            .split(|c| c == '"' || c == ';' || c == ' ')
            .next()
            .unwrap_or(boundary);
        Some(boundary)
    } else {
        None
    }
}

/// Returns the boundary from the headers or generates a new one using a UUID.
fn get_or_generate_boundary(headers: &[(Cow<str>, Cow<str>)]) -> String {
    if let Some(ct) = get_content_type(headers) {
        if let Some(boundary) = extract_boundary(&ct) {
            return boundary.to_string();
        }
    }
    Uuid::new_v4().to_string()
}

fn trim_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or(input.strip_suffix("\n"))
        .unwrap_or(input)
}

/// Parse a multipart MIME container given a boundary.  
/// This function splits the body into a preamble (body field) and parts.
fn parse_multipart_container<'a>(
    input: &'a str,
    boundary: &str,
    headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
) -> IResult<&'a str, MimeContainer<'a>> {
    let boundary_marker_string = &format!("\r\n--{}", boundary);
    let boundary_marker = boundary_marker_string.as_str();
    let mut buf = input;

    // The preamble is everything before the first boundary marker.
    // We're slightly unconformant. If the exact boundary follows, but no newline or --,
    // this check will pass and cause the preamble to be skipped, but the later parsing will error
    // out. Sucks.
    let (i, preamble) = match buf.starts_with(&boundary_marker[2..]) {
        true => (input, ""),
        false => take_until(boundary_marker)(buf)?,
    };

    buf = i;
    let mut parts = Vec::new();
    loop {
        // Consume boundary marker and check if it's the end.
        let (i, _) = tag(boundary_marker)(buf)?;
        let (i, boundary_followup) = alt((tag("--"), preceded(space0, line_ending)))(i)?;
        if boundary_followup == "--" {
            buf = i;
            break;
        }

        // Use take_until to get the part content up to the next boundary marker.
        let (i, mut part_content) = take_until(boundary_marker)(i)?;
        part_content = trim_newline(part_content);

        // Parse the part content as an independent MIME container.
        let (_, part) = MimeContainer::parse_mime_container(part_content)?;
        parts.push(part);

        buf = i;
    }

    Ok((
        buf,
        MimeContainer {
            headers,
            body: Cow::Borrowed(preamble),
            parts,
        },
    ))
}

impl<'a> MimeContainer<'a> {
    pub fn find_header_value(&'a self, header: &str) -> Option<Cow<'a, str>> {
        self.headers
            .iter()
            .find(|e| e.0.eq_ignore_ascii_case(header))
            .map(|e| e.1.clone())
    }

    /// Parse a MIME container's body.
    /// If the message is multipart, delegate to the multipart parser.
    pub fn parse_mime_container_data(
        input: &'a str,
        headers: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    ) -> IResult<&'a str, MimeContainer<'a>> {
        if let Some(ct) = get_content_type(&headers) {
            if ct.to_ascii_lowercase().starts_with("multipart/") {
                if let Some(boundary) = extract_boundary(&ct) {
                    return parse_multipart_container(input, boundary, headers);
                }
            }
        }
        // Non-multipart: the remaining text is the body.
        Ok((
            "",
            MimeContainer {
                headers,
                body: Cow::Borrowed(input),
                parts: Vec::new(),
            },
        ))
    }

    /// Parse a complete MIME container: headers, then body.
    /// If the message is multipart, delegate to the multipart parser.
    pub fn parse_mime_container(input: &'a str) -> IResult<&'a str, MimeContainer<'a>> {
        let (input, headers) = parse_headers(input)?;
        Self::parse_mime_container_data(input, headers)
    }

    /// Convert the Container back into MIME message form
    pub fn to_mime_string(&self) -> String {
        let mut out = String::new();
        // Serialize headers.
        for (name, value) in &self.headers {
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");

        // If this is a multipart container (has parts), serialize accordingly.
        if !self.parts.is_empty() {
            // Write the preamble (body).
            out.push_str(&self.body);
            out.push_str("\r\n");
            let boundary = get_or_generate_boundary(&self.headers);
            for part in &self.parts {
                out.push_str("--");
                out.push_str(&boundary);
                out.push_str("\r\n");
                out.push_str(&part.to_mime_string());
                out.push_str("\r\n");
            }
            out.push_str("--");
            out.push_str(&boundary);
            out.push_str("--\r\n");
        } else {
            // Non-multipart: just write the body.
            out.push_str(&self.body);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A simple single-part message.
    const SINGLE_EMAIL: &str = "\
Content-Type: text/plain\r\n\
From: test@example.com\r\n\
\r\n\
Hello, this is a test email body.";

    // A multipart message taken from the example.
    const MULTIPART_EMAIL: &str = "\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=frontier\r\n\
\r\n\
This is a message with multiple parts in MIME format.\r\n\
--frontier\r\n\
Content-Type: text/plain\r\n\
\r\n\
This is the body of the message.\r\n\
--frontier\r\n\
Content-Type: application/octet-stream\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPgogIDxib2R5PgogICAgPHA+VGhpcyBpcyB0aGUg\r\n\
Ym9keSBvZiB0aGUgbWVzc2FnZS48L3A+CiAgPC9ib2R5Pgo8L2h0bWw+Cg==\r\n\
--frontier--\r\n";

    #[test]
    fn test_parse_single_part() {
        let res = MimeContainer::parse_mime_container(SINGLE_EMAIL);
        assert!(res.is_ok(), "Parsing single part failed: {:?}", res);
        let (_remaining, container) = res.unwrap();
        // For non-multipart, parts must be empty.
        assert!(container.parts.is_empty());
        // The body is the entire message body.
        assert_eq!(
            container.body,
            Cow::Borrowed("Hello, this is a test email body.")
        );
        // Header order preserved.
        assert_eq!(container.headers.len(), 2);
        assert_eq!(container.headers[0].0, Cow::Borrowed("Content-Type"));
    }

    #[test]
    fn test_parse_multipart() {
        let res = MimeContainer::parse_mime_container(MULTIPART_EMAIL);
        assert!(res.is_ok(), "Parsing multipart failed: {:?}", res);
        let (_remaining, container) = res.unwrap();
        // For multipart, there should be parts.
        assert!(!container.parts.is_empty());
        // The preamble is stored in the body.
        assert_eq!(
            container.body,
            Cow::Borrowed("This is a message with multiple parts in MIME format.")
        );

        let part1 = &container.parts[0];
        assert!(part1.parts.is_empty());
        assert_eq!(
            part1.body,
            Cow::Borrowed("This is the body of the message.")
        );
        let part2 = &container.parts[1];
        assert_eq!(part2.headers.len(), 2);
        assert!(part2.body.contains("PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPg"));
    }

    #[test]
    fn test_serialization_single() {
        let (_remaining, container) = MimeContainer::parse_mime_container(SINGLE_EMAIL).unwrap();
        let serialized = container.to_mime_string();
        assert!(serialized.contains("Content-Type: text/plain"));
        assert!(serialized.contains("Hello, this is a test email body."));
    }

    #[test]
    fn test_serialization_multipart() {
        let (_remaining, container) = MimeContainer::parse_mime_container(MULTIPART_EMAIL).unwrap();
        let serialized = container.to_mime_string();
        assert!(serialized.contains("This is a message with multiple parts in MIME format."));
        assert!(serialized.contains("--frontier") || serialized.contains("BOUNDARY-"));
        assert!(serialized.contains("This is the body of the message."));
        assert!(serialized.contains("PGh0bWw+CiAgPGhlYWQ+CiAgPC9oZWFkPg"));
    }

    #[test]
    fn test_round_trip_single() {
        let (_remaining, container) = MimeContainer::parse_mime_container(SINGLE_EMAIL).unwrap();
        let serialized = container.to_mime_string();
        let (_remaining2, container2) = MimeContainer::parse_mime_container(&serialized).unwrap();
        assert_eq!(container, container2, "Round-trip serialization failed");
    }
    #[test]
    fn test_round_trip_multipart() {
        let (_remaining, container) = MimeContainer::parse_mime_container(MULTIPART_EMAIL).unwrap();
        let serialized = container.to_mime_string();
        let (_remaining2, container2) = MimeContainer::parse_mime_container(&serialized).unwrap();
        assert_eq!(container, container2, "Round-trip serialization failed");
    }
    #[test]
    fn test_multipart_against_original() {
        let (_remaining, container) = MimeContainer::parse_mime_container(MULTIPART_EMAIL).unwrap();
        let serialized = container.to_mime_string();
        assert_eq!(
            serialized, MULTIPART_EMAIL,
            "Serialization does not match original"
        );
    }
}
