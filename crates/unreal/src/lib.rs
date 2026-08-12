use std::{error::Error, fmt};

const CRASH_CONTEXT_ROOT: &str = "FGenericCrashContext";

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
}
