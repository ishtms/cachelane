use std::{error::Error, fmt};

const CRASH_CONTEXT_ROOT: &str = "FGenericCrashContext";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectLogTail {
    text: String,
    truncated: bool,
    invalid_utf8: bool,
}

impl ProjectLogTail {
    #[must_use]
    pub fn extract(input: &[u8], max_bytes: usize, max_lines: usize) -> Self {
        if input.is_empty() {
            return Self {
                text: String::new(),
                truncated: false,
                invalid_utf8: false,
            };
        }

        if max_bytes == 0 || max_lines == 0 {
            return Self {
                text: String::new(),
                truncated: true,
                invalid_utf8: false,
            };
        }

        let requested_start = input.len().saturating_sub(max_bytes);
        let source_start = next_utf8_boundary(input, requested_start);
        let source = &input[source_start..];
        let invalid_utf8 = std::str::from_utf8(source).is_err();
        let decoded = String::from_utf8_lossy(source);
        let byte_start = suffix_start(decoded.as_ref(), max_bytes);
        let byte_bounded = &decoded[byte_start..];
        let starts_mid_line = if byte_start > 0 {
            decoded.as_bytes()[byte_start - 1] != b'\n'
        } else {
            source_start > 0 && input[source_start - 1] != b'\n'
        };
        let partial_line_start = if starts_mid_line {
            byte_bounded
                .find('\n')
                .filter(|index| index + 1 < byte_bounded.len())
                .map_or(0, |index| index + 1)
        } else {
            0
        };
        let complete_lines = &byte_bounded[partial_line_start..];
        let line_start = last_lines_start(complete_lines, max_lines);

        Self {
            text: complete_lines[line_start..].to_owned(),
            truncated: source_start > 0
                || byte_start > 0
                || partial_line_start > 0
                || line_start > 0,
            invalid_utf8,
        }
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    #[must_use]
    pub const fn had_invalid_utf8(&self) -> bool {
        self.invalid_utf8
    }
}

fn next_utf8_boundary(input: &[u8], start: usize) -> usize {
    if start == 0 || start >= input.len() || input[start] & 0b1100_0000 != 0b1000_0000 {
        return start;
    }

    for candidate in start.saturating_sub(3)..start {
        let width = match input[candidate] {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => continue,
        };
        let end = candidate + width;

        if end > start && end <= input.len() && std::str::from_utf8(&input[candidate..end]).is_ok()
        {
            return end;
        }
    }

    start
}

fn suffix_start(value: &str, max_bytes: usize) -> usize {
    if value.len() <= max_bytes {
        return 0;
    }

    let mut start = value.len() - max_bytes;
    while !value.is_char_boundary(start) {
        start += 1;
    }
    start
}

fn last_lines_start(value: &str, max_lines: usize) -> usize {
    let bytes = value.as_bytes();
    let scan_end = if bytes.last() == Some(&b'\n') {
        bytes.len().saturating_sub(1)
    } else {
        bytes.len()
    };
    let mut lines = 1;

    for index in (0..scan_end).rev() {
        if bytes[index] == b'\n' {
            lines += 1;
            if lines > max_lines {
                return index + 1;
            }
        }
    }

    0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    InvalidXml,
    DtdForbidden,
    NodeLimitExceeded,
    UnexpectedRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    kind: ParseErrorKind,
    line: u32,
    column: u32,
}

impl ParseError {
    #[must_use]
    pub const fn kind(self) -> ParseErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn line(self) -> u32 {
        self.line
    }

    #[must_use]
    pub const fn column(self) -> u32 {
        self.column
    }

    fn from_xml(error: &roxmltree::Error) -> Self {
        let position = error.pos();
        let kind = match error {
            roxmltree::Error::DtdDetected => ParseErrorKind::DtdForbidden,
            roxmltree::Error::NodesLimitReached => ParseErrorKind::NodeLimitExceeded,
            _ => ParseErrorKind::InvalidXml,
        };

        Self {
            kind,
            line: position.row,
            column: position.col,
        }
    }

    fn unexpected_root(position: roxmltree::TextPos) -> Self {
        Self {
            kind: ParseErrorKind::UnexpectedRoot,
            line: position.row,
            column: position.col,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ParseErrorKind::InvalidXml => "invalid crash context XML",
            ParseErrorKind::DtdForbidden => "DTD is forbidden in crash context XML",
            ParseErrorKind::NodeLimitExceeded => "crash context XML node limit exceeded",
            ParseErrorKind::UnexpectedRoot => "unexpected crash context XML root",
        };

        write!(formatter, "{message} at {}:{}", self.line, self.column)
    }
}

impl Error for ParseError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrashContextParser {
    node_limit: u32,
}

impl CrashContextParser {
    #[must_use]
    pub const fn new(node_limit: u32) -> Self {
        Self { node_limit }
    }

    /// # Errors
    ///
    /// Returns an error when the XML is invalid, unsafe, too large, or has the wrong root.
    pub fn parse<'input>(&self, xml: &'input str) -> Result<CrashContext<'input>, ParseError> {
        let options = roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: self.node_limit,
            entity_resolver: None,
        };
        let document = roxmltree::Document::parse_with_options(xml, options)
            .map_err(|error| ParseError::from_xml(&error))?;
        let root = document.root_element();

        if root.tag_name().name() != CRASH_CONTEXT_ROOT {
            let position = document.text_pos_at(root.range().start);
            return Err(ParseError::unexpected_root(position));
        }

        Ok(CrashContext { document })
    }
}

pub struct CrashContext<'input> {
    document: roxmltree::Document<'input>,
}

impl<'input> CrashContext<'input> {
    pub fn sections(&self) -> impl Iterator<Item = CrashContextSection<'_, 'input>> + '_ {
        self.document
            .root_element()
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|node| CrashContextSection { node })
    }

    #[must_use]
    pub fn section(&self, name: &str) -> Option<CrashContextSection<'_, 'input>> {
        self.sections().find(|section| section.name() == name)
    }
}

#[derive(Clone, Copy)]
pub struct CrashContextSection<'document, 'input> {
    node: roxmltree::Node<'document, 'input>,
}

impl<'document, 'input> CrashContextSection<'document, 'input> {
    #[must_use]
    pub fn name(self) -> &'document str {
        self.node.tag_name().name()
    }

    pub fn fields(self) -> impl Iterator<Item = CrashContextField<'document, 'input>> {
        self.node
            .children()
            .filter(roxmltree::Node::is_element)
            .map(|node| CrashContextField { node })
    }

    #[must_use]
    pub fn field(self, name: &str) -> Option<CrashContextField<'document, 'input>> {
        self.fields().find(|field| field.name() == name)
    }
}

#[derive(Clone, Copy)]
pub struct CrashContextField<'document, 'input> {
    node: roxmltree::Node<'document, 'input>,
}

impl<'document> CrashContextField<'document, '_> {
    #[must_use]
    pub fn name(self) -> &'document str {
        self.node.tag_name().name()
    }

    #[must_use]
    pub fn value(self) -> Option<&'document str> {
        self.node.text()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CrashContext, CrashContextField, CrashContextParser, CrashContextSection, ParseErrorKind,
        ProjectLogTail,
    };

    fn parse(xml: &str) -> CrashContext<'_> {
        CrashContextParser::new(128)
            .parse(xml)
            .unwrap_or_else(|error| panic!("crash context must parse: {error}"))
    }

    #[test]
    fn parses_crash_context_sections_and_fields() {
        let context = parse(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<FGenericCrashContext>
  <RuntimeProperties>
    <CrashGUID>UECC-Windows-123</CrashGUID>
    <ErrorMessage>Fatal error</ErrorMessage>
  </RuntimeProperties>
  <PlatformProperties>
    <PlatformName>Windows</PlatformName>
  </PlatformProperties>
</FGenericCrashContext>"#,
        );
        let section_names = context
            .sections()
            .map(CrashContextSection::name)
            .collect::<Vec<_>>();
        let runtime = context
            .section("RuntimeProperties")
            .unwrap_or_else(|| panic!("runtime properties must exist"));

        assert_eq!(section_names, ["RuntimeProperties", "PlatformProperties"]);
        assert_eq!(
            runtime
                .field("CrashGUID")
                .and_then(CrashContextField::value),
            Some("UECC-Windows-123")
        );
        assert_eq!(
            runtime
                .field("ErrorMessage")
                .and_then(CrashContextField::value),
            Some("Fatal error")
        );
    }

    #[test]
    fn tolerates_missing_reordered_and_additional_fields() {
        let context = parse(
            r"<FGenericCrashContext>
  <FutureProperties><Flag>enabled</Flag></FutureProperties>
  <RuntimeProperties>
    <FutureField>first</FutureField>
    <CrashGUID>UECC-123</CrashGUID>
    <FutureField>second</FutureField>
  </RuntimeProperties>
</FGenericCrashContext>",
        );
        let runtime = context
            .section("RuntimeProperties")
            .unwrap_or_else(|| panic!("runtime properties must exist"));
        let repeated = runtime
            .fields()
            .filter(|field| field.name() == "FutureField")
            .filter_map(CrashContextField::value)
            .collect::<Vec<_>>();

        assert!(context.section("PlatformProperties").is_none());
        assert!(context.section("FutureProperties").is_some());
        assert_eq!(repeated, ["first", "second"]);
    }

    #[test]
    fn decodes_escaped_and_cdata_text() {
        let context = parse(
            r"<FGenericCrashContext><RuntimeProperties>
  <ErrorMessage>Bad &amp; worse</ErrorMessage>
  <UserDescription><![CDATA[<script>alert(1)</script>]]></UserDescription>
</RuntimeProperties></FGenericCrashContext>",
        );
        let runtime = context
            .section("RuntimeProperties")
            .unwrap_or_else(|| panic!("runtime properties must exist"));

        assert_eq!(
            runtime
                .field("ErrorMessage")
                .and_then(CrashContextField::value),
            Some("Bad & worse")
        );
        assert_eq!(
            runtime
                .field("UserDescription")
                .and_then(CrashContextField::value),
            Some("<script>alert(1)</script>")
        );
    }

    #[test]
    fn rejects_malformed_xml_without_echoing_input() {
        let error = CrashContextParser::new(128)
            .parse("<FGenericCrashContext><secret>do-not-log</FGenericCrashContext>")
            .err()
            .unwrap_or_else(|| panic!("malformed XML must fail"));
        let message = error.to_string();

        assert_eq!(error.kind(), ParseErrorKind::InvalidXml);
        assert!(error.line() > 0);
        assert!(error.column() > 0);
        assert!(!message.contains("secret"));
        assert!(!message.contains("do-not-log"));
    }

    #[test]
    fn rejects_dtd_and_entity_declarations() {
        for xml in [
            r"<!DOCTYPE FGenericCrashContext>
<FGenericCrashContext><RuntimeProperties /></FGenericCrashContext>",
            r#"<!DOCTYPE context [<!ENTITY payload SYSTEM "file:///etc/passwd">]>
<FGenericCrashContext><RuntimeProperties>&payload;</RuntimeProperties></FGenericCrashContext>"#,
        ] {
            let error = CrashContextParser::new(128)
                .parse(xml)
                .err()
                .unwrap_or_else(|| panic!("DTD input must fail"));

            assert_eq!(error.kind(), ParseErrorKind::DtdForbidden);
            assert_eq!(
                error.to_string(),
                "DTD is forbidden in crash context XML at 1:1"
            );
        }
    }

    #[test]
    fn rejects_unexpected_root_without_echoing_its_name() {
        let error = CrashContextParser::new(128)
            .parse("<NotCrashContext><Secret>do-not-log</Secret></NotCrashContext>")
            .err()
            .unwrap_or_else(|| panic!("unexpected root must fail"));
        let message = error.to_string();

        assert_eq!(error.kind(), ParseErrorKind::UnexpectedRoot);
        assert!(!message.contains("NotCrashContext"));
        assert!(!message.contains("do-not-log"));
    }

    #[test]
    fn enforces_the_configured_node_limit() {
        let error = CrashContextParser::new(2)
            .parse(
                "<FGenericCrashContext><RuntimeProperties><CrashGUID>123</CrashGUID></RuntimeProperties></FGenericCrashContext>",
            )
            .err()
            .unwrap_or_else(|| panic!("node limit must fail"));

        assert_eq!(error.kind(), ParseErrorKind::NodeLimitExceeded);
    }

    #[test]
    fn keeps_a_project_log_that_fits_the_limits() {
        let input = b"LogInit: Display: ready\nLogGame: Error: crashed\n";
        let tail = ProjectLogTail::extract(input, 1_024, 10);

        assert_eq!(tail.text(), String::from_utf8_lossy(input));
        assert!(!tail.truncated());
        assert!(!tail.had_invalid_utf8());
    }

    #[test]
    fn keeps_the_newest_lines_in_source_order() {
        let tail = ProjectLogTail::extract(b"one\ntwo\nthree\n", 1_024, 2);

        assert_eq!(tail.text(), "two\nthree\n");
        assert!(tail.truncated());
    }

    #[test]
    fn drops_a_partial_old_line_after_byte_truncation() {
        let input = b"ignored prefix\nkept one\nkept two\n";
        let max_bytes = input.len() - 3;
        let tail = ProjectLogTail::extract(input, max_bytes, 10);

        assert_eq!(tail.text(), "kept one\nkept two\n");
        assert!(tail.text().len() <= max_bytes);
        assert!(tail.truncated());
    }

    #[test]
    fn keeps_a_capped_suffix_of_an_overlong_final_line() {
        let tail = ProjectLogTail::extract(b"header\nabcdefghijklmnopqrstuvwxyz", 8, 10);

        assert_eq!(tail.text(), "stuvwxyz");
        assert!(tail.truncated());
    }

    #[test]
    fn preserves_crlf_in_the_newest_lines() {
        let tail = ProjectLogTail::extract(b"one\r\ntwo\r\nthree\r\n", 1_024, 2);

        assert_eq!(tail.text(), "two\r\nthree\r\n");
        assert!(tail.truncated());
    }

    #[test]
    fn does_not_replace_a_valid_unicode_character_cut_by_the_byte_window() {
        let input = "prefix\n🙂étail";
        let max_bytes = "🙂étail".len() - 1;
        let tail = ProjectLogTail::extract(input.as_bytes(), max_bytes, 10);

        assert_eq!(tail.text(), "étail");
        assert!(tail.truncated());
        assert!(!tail.had_invalid_utf8());
    }

    #[test]
    fn replaces_and_reports_invalid_utf8() {
        let tail = ProjectLogTail::extract(b"old\nbad:\xfftail", 1_024, 10);

        assert_eq!(tail.text(), "old\nbad:�tail");
        assert!(!tail.truncated());
        assert!(tail.had_invalid_utf8());
    }

    #[test]
    fn empty_limits_return_an_empty_truncated_tail() {
        for tail in [
            ProjectLogTail::extract(b"content", 0, 10),
            ProjectLogTail::extract(b"content", 10, 0),
        ] {
            assert_eq!(tail.text(), "");
            assert!(tail.truncated());
            assert!(!tail.had_invalid_utf8());
        }
    }

    #[test]
    fn empty_input_is_not_reported_as_truncated() {
        let tail = ProjectLogTail::extract(b"", 0, 0);

        assert_eq!(tail.text(), "");
        assert!(!tail.truncated());
        assert!(!tail.had_invalid_utf8());
    }

    #[test]
    fn lossy_output_stays_within_the_byte_limit() {
        let tail = ProjectLogTail::extract(b"\xff\xff", 2, 10);

        assert!(tail.text().len() <= 2);
        assert!(tail.truncated());
        assert!(tail.had_invalid_utf8());
    }

    #[test]
    fn lossy_byte_truncation_still_prefers_complete_lines() {
        let tail = ProjectLogTail::extract(b"\xff\xff\nkept\n", 8, 10);

        assert_eq!(tail.text(), "kept\n");
        assert!(tail.truncated());
        assert!(tail.had_invalid_utf8());
    }
}
