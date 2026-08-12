use std::{collections::BTreeMap, error::Error, fmt};

use cachelane_domain::{CrashType, NormalizedValue};
use serde::Serialize;

const CRASH_CONTEXT_ROOT: &str = "FGenericCrashContext";
pub const CRASH_CONTEXT_PARSER_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CrashContextExtractionOptions {
    pub include_command_line: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CrashContextProperty {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CrashContextThread {
    pub call_stack: Option<String>,
    pub crash_marker: Option<String>,
    pub registers: Option<String>,
    pub thread_id: Option<String>,
    pub thread_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CrashContextData {
    pub parser_version: u32,
    pub crash_guid: Option<String>,
    pub crash_type: CrashType,
    pub error_message: Option<String>,
    pub build_version: Option<String>,
    pub engine_version: Option<String>,
    pub platform: Option<NormalizedValue>,
    pub architecture: Option<String>,
    pub build_configuration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    pub modules: Vec<NormalizedValue>,
    pub threads: Vec<CrashContextThread>,
    pub system_metadata: Vec<CrashContextProperty>,
    pub user_comment: Option<String>,
    pub game_data: Vec<CrashContextProperty>,
    pub unknown_fields: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

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
    #[must_use]
    pub fn extract(&self, options: CrashContextExtractionOptions) -> CrashContextData {
        let runtime = self.section("RuntimeProperties");
        let platform_properties = self.section("PlatformProperties");
        let platform =
            field_value(runtime, "PlatformName").map(|value| NormalizedValue::platform(&value));
        let module_text = field_value(runtime, "Modules");
        let modules = module_text.as_deref().map_or_else(Vec::new, |value| {
            value
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(NormalizedValue::module)
                .collect()
        });
        let mut system_metadata = section_properties(platform_properties);

        if let Some(runtime) = runtime {
            system_metadata.extend(runtime.fields().filter_map(|field| {
                let name = field.name();
                (name.starts_with("Misc.") || name.starts_with("MemoryStats."))
                    .then(|| property(field))
            }));
        }

        CrashContextData {
            parser_version: CRASH_CONTEXT_PARSER_VERSION,
            crash_guid: field_value(runtime, "CrashGUID"),
            crash_type: field_text(runtime, "CrashType")
                .map_or(CrashType::Unknown, CrashType::classify),
            error_message: field_value(runtime, "ErrorMessage"),
            build_version: field_value(runtime, "BuildVersion"),
            engine_version: field_value(runtime, "EngineVersion"),
            platform,
            architecture: first_field_value(runtime, &["Architecture", "PlatformArchitecture"]),
            build_configuration: field_value(runtime, "BuildConfiguration"),
            command_line: options
                .include_command_line
                .then(|| field_value(runtime, "CommandLine"))
                .flatten(),
            modules,
            threads: extract_threads(runtime),
            system_metadata,
            user_comment: first_field_value(runtime, &["UserDescription", "UserComment"]),
            game_data: section_properties(self.section("GameData")),
            unknown_fields: extract_unknown_fields(self),
        }
    }

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

fn field_text<'document>(
    section: Option<CrashContextSection<'document, '_>>,
    name: &str,
) -> Option<&'document str> {
    section
        .and_then(|section| section.field(name))
        .and_then(CrashContextField::value)
}

fn field_value(section: Option<CrashContextSection<'_, '_>>, name: &str) -> Option<String> {
    section
        .and_then(|section| section.field(name))
        .map(|field| field.value().unwrap_or_default().to_owned())
}

fn first_field_value(
    section: Option<CrashContextSection<'_, '_>>,
    names: &[&str],
) -> Option<String> {
    names.iter().find_map(|name| field_value(section, name))
}

fn property(field: CrashContextField<'_, '_>) -> CrashContextProperty {
    CrashContextProperty {
        name: field.name().to_owned(),
        value: field.value().unwrap_or_default().to_owned(),
    }
}

fn section_properties(section: Option<CrashContextSection<'_, '_>>) -> Vec<CrashContextProperty> {
    section.map_or_else(Vec::new, |section| section.fields().map(property).collect())
}

fn extract_unknown_fields(
    context: &CrashContext<'_>,
) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut unknown_fields: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();

    for section in context.sections() {
        for field in section.fields() {
            if is_known_field(section.name(), field.name()) {
                continue;
            }

            unknown_fields
                .entry(section.name().to_owned())
                .or_default()
                .entry(field.name().to_owned())
                .or_default()
                .push(field.value().unwrap_or_default().to_owned());
        }
    }

    unknown_fields
}

fn is_known_field(section: &str, field: &str) -> bool {
    match section {
        "GameData" | "PlatformProperties" => true,
        "RuntimeProperties" => {
            matches!(
                field,
                "CrashGUID"
                    | "CrashType"
                    | "ErrorMessage"
                    | "BuildVersion"
                    | "EngineVersion"
                    | "PlatformName"
                    | "Architecture"
                    | "PlatformArchitecture"
                    | "BuildConfiguration"
                    | "CommandLine"
                    | "Modules"
                    | "Threads"
                    | "UserDescription"
                    | "UserComment"
            ) || field.starts_with("Misc.")
                || field.starts_with("MemoryStats.")
        }
        _ => false,
    }
}

fn extract_threads(runtime: Option<CrashContextSection<'_, '_>>) -> Vec<CrashContextThread> {
    runtime
        .and_then(|section| section.field("Threads"))
        .map_or_else(Vec::new, |threads| {
            threads
                .node
                .children()
                .filter(roxmltree::Node::is_element)
                .filter(|node| node.tag_name().name() == "Thread")
                .map(|node| CrashContextThread {
                    call_stack: child_value(node, "CallStack"),
                    crash_marker: child_value(node, "IsCrashed"),
                    registers: child_value(node, "Registers"),
                    thread_id: child_value(node, "ThreadID"),
                    thread_name: child_value(node, "ThreadName"),
                })
                .collect()
        })
}

fn child_value(node: roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .filter(roxmltree::Node::is_element)
        .find(|child| child.tag_name().name() == name)
        .map(|child| child.text().unwrap_or_default().to_owned())
}

#[cfg(test)]
mod tests {
    use cachelane_domain::{CrashType, NormalizedValue};

    use super::{
        CRASH_CONTEXT_PARSER_VERSION, CrashContext, CrashContextExtractionOptions,
        CrashContextField, CrashContextParser, CrashContextProperty, CrashContextSection,
        CrashContextThread, ParseErrorKind, ProjectLogTail,
    };

    const COMPLETE_CRASH_CONTEXT: &str = r"<FGenericCrashContext>
  <RuntimeProperties>
    <CrashGUID>UECC-Windows-123</CrashGUID>
    <CrashType>Assert</CrashType>
    <ErrorMessage>Fatal error</ErrorMessage>
    <BuildVersion>++Project+Release</BuildVersion>
    <EngineVersion>5.4.4-123456</EngineVersion>
    <PlatformName>Win64</PlatformName>
    <PlatformArchitecture>x86_64</PlatformArchitecture>
    <BuildConfiguration>Shipping</BuildConfiguration>
    <CommandLine>-auth=do-not-store</CommandLine>
    <Modules>C:\Game\Project.exe
C:\Engine\Core.DLL</Modules>
    <Threads>
      <Thread>
        <CallStack>Project 0x10</CallStack>
        <IsCrashed>true</IsCrashed>
        <Registers></Registers>
        <ThreadID>42</ThreadID>
        <ThreadName>GameThread</ThreadName>
      </Thread>
      <Thread>
        <CallStack>Core 0x20</CallStack>
        <IsCrashed>false</IsCrashed>
        <ThreadID>7</ThreadID>
        <ThreadName>RenderThread</ThreadName>
      </Thread>
    </Threads>
    <Misc.OSVersionMajor>Windows 11</Misc.OSVersionMajor>
    <MemoryStats.TotalPhysical>34359738368</MemoryStats.TotalPhysical>
    <UserDescription>crashed after loading</UserDescription>
  </RuntimeProperties>
  <PlatformProperties>
    <PlatformIsRunningWindows>1</PlatformIsRunningWindows>
  </PlatformProperties>
  <GameData>
    <MapName>Arena</MapName>
  </GameData>
</FGenericCrashContext>";

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
    fn extracts_complete_crash_context_data() {
        let data = parse(COMPLETE_CRASH_CONTEXT).extract(CrashContextExtractionOptions::default());

        assert_eq!(data.parser_version, CRASH_CONTEXT_PARSER_VERSION);
        assert_eq!(data.crash_guid.as_deref(), Some("UECC-Windows-123"));
        assert_eq!(data.crash_type, CrashType::Assert);
        assert_eq!(data.error_message.as_deref(), Some("Fatal error"));
        assert_eq!(data.build_version.as_deref(), Some("++Project+Release"));
        assert_eq!(data.engine_version.as_deref(), Some("5.4.4-123456"));
        assert_eq!(data.platform, Some(NormalizedValue::platform("Win64")));
        assert_eq!(data.architecture.as_deref(), Some("x86_64"));
        assert_eq!(data.build_configuration.as_deref(), Some("Shipping"));
        assert_eq!(data.command_line, None);
        assert_eq!(
            data.modules,
            [
                NormalizedValue::module(r"C:\Game\Project.exe"),
                NormalizedValue::module(r"C:\Engine\Core.DLL"),
            ]
        );
        assert_eq!(
            data.threads,
            [
                CrashContextThread {
                    call_stack: Some("Project 0x10".to_owned()),
                    crash_marker: Some("true".to_owned()),
                    registers: Some(String::new()),
                    thread_id: Some("42".to_owned()),
                    thread_name: Some("GameThread".to_owned()),
                },
                CrashContextThread {
                    call_stack: Some("Core 0x20".to_owned()),
                    crash_marker: Some("false".to_owned()),
                    registers: None,
                    thread_id: Some("7".to_owned()),
                    thread_name: Some("RenderThread".to_owned()),
                },
            ]
        );
        assert_eq!(
            data.system_metadata,
            [
                CrashContextProperty {
                    name: "PlatformIsRunningWindows".to_owned(),
                    value: "1".to_owned(),
                },
                CrashContextProperty {
                    name: "Misc.OSVersionMajor".to_owned(),
                    value: "Windows 11".to_owned(),
                },
                CrashContextProperty {
                    name: "MemoryStats.TotalPhysical".to_owned(),
                    value: "34359738368".to_owned(),
                },
            ]
        );
        assert_eq!(data.user_comment.as_deref(), Some("crashed after loading"));
        assert_eq!(
            data.game_data,
            [CrashContextProperty {
                name: "MapName".to_owned(),
                value: "Arena".to_owned(),
            }]
        );
        assert!(data.unknown_fields.is_empty());
    }

    #[test]
    fn serializes_versioned_crash_context_data_deterministically() {
        let data = parse(COMPLETE_CRASH_CONTEXT).extract(CrashContextExtractionOptions::default());
        let first = serde_json::to_string(&data)
            .unwrap_or_else(|error| panic!("crash context data must serialize: {error}"));
        let second = serde_json::to_string(&data)
            .unwrap_or_else(|error| panic!("crash context data must serialize: {error}"));

        assert_eq!(first, second);
        assert_eq!(
            first,
            r#"{"parser_version":1,"crash_guid":"UECC-Windows-123","crash_type":"assert","error_message":"Fatal error","build_version":"++Project+Release","engine_version":"5.4.4-123456","platform":{"original":"Win64","normalized":"windows"},"architecture":"x86_64","build_configuration":"Shipping","modules":[{"original":"C:\\Game\\Project.exe","normalized":"project"},{"original":"C:\\Engine\\Core.DLL","normalized":"core"}],"threads":[{"call_stack":"Project 0x10","crash_marker":"true","registers":"","thread_id":"42","thread_name":"GameThread"},{"call_stack":"Core 0x20","crash_marker":"false","registers":null,"thread_id":"7","thread_name":"RenderThread"}],"system_metadata":[{"name":"PlatformIsRunningWindows","value":"1"},{"name":"Misc.OSVersionMajor","value":"Windows 11"},{"name":"MemoryStats.TotalPhysical","value":"34359738368"}],"user_comment":"crashed after loading","game_data":[{"name":"MapName","value":"Arena"}],"unknown_fields":{}}"#
        );
        assert!(!first.contains("command_line"));
        assert!(!first.contains("do-not-store"));
    }

    #[test]
    fn extracts_unknown_fields_in_stable_namespaced_json() {
        let data = parse(
            r"<FGenericCrashContext>
  <RuntimeProperties>
    <Zeta>first</Zeta>
    <CrashGUID>UECC-Windows-123</CrashGUID>
    <Alpha></Alpha>
    <Zeta />
    <CommandLine>-token=sensitive</CommandLine>
    <Modules>Project.exe</Modules>
    <Threads><Thread><ThreadID>42</ThreadID></Thread></Threads>
    <Misc.OSVersionMajor>Windows 11</Misc.OSVersionMajor>
    <MemoryStats.TotalPhysical>34359738368</MemoryStats.TotalPhysical>
    <UserDescription>private comment</UserDescription>
  </RuntimeProperties>
  <PlatformProperties>
    <PlatformIsRunningWindows>1</PlatformIsRunningWindows>
  </PlatformProperties>
  <GameData>
    <AccountID>private account</AccountID>
  </GameData>
  <FutureProperties>
    <Zulu>last</Zulu>
    <Alpha />
    <Zulu>again</Zulu>
  </FutureProperties>
  <AnotherSection>
    <Beta>value</Beta>
  </AnotherSection>
</FGenericCrashContext>",
        )
        .extract(CrashContextExtractionOptions::default());

        let json = serde_json::to_string(&data.unknown_fields)
            .unwrap_or_else(|error| panic!("unknown fields must serialize: {error}"));
        let record_json = serde_json::to_value(&data)
            .unwrap_or_else(|error| panic!("crash context data must serialize: {error}"));

        assert_eq!(
            json,
            r#"{"AnotherSection":{"Beta":["value"]},"FutureProperties":{"Alpha":[""],"Zulu":["last","again"]},"RuntimeProperties":{"Alpha":[""],"Zeta":["first",""]}}"#
        );
        assert_eq!(
            serde_json::to_string(&data.unknown_fields)
                .unwrap_or_else(|error| panic!("unknown fields must serialize: {error}")),
            json
        );
        assert!(!json.contains("sensitive"));
        assert!(!json.contains("private"));
        assert!(!json.contains("PlatformProperties"));
        assert!(!json.contains("GameData"));
        assert_eq!(
            record_json["unknown_fields"]["FutureProperties"]["Zulu"],
            serde_json::json!(["last", "again"])
        );
    }

    #[test]
    fn command_line_requires_explicit_inclusion() {
        let context = parse(
            r"<FGenericCrashContext><RuntimeProperties>
  <CommandLine>-token=sensitive</CommandLine>
</RuntimeProperties></FGenericCrashContext>",
        );

        assert_eq!(
            context
                .extract(CrashContextExtractionOptions::default())
                .command_line,
            None
        );
        assert_eq!(
            context
                .extract(CrashContextExtractionOptions {
                    include_command_line: true,
                })
                .command_line
                .as_deref(),
            Some("-token=sensitive")
        );

        let json = serde_json::to_string(&context.extract(CrashContextExtractionOptions {
            include_command_line: true,
        }))
        .unwrap_or_else(|error| panic!("crash context data must serialize: {error}"));

        assert!(json.contains(r#""command_line":"-token=sensitive""#));
    }

    #[test]
    fn extraction_tolerates_missing_empty_reordered_and_repeated_data() {
        let data = parse(
            r"<FGenericCrashContext>
  <GameData>
    <Mode>solo</Mode>
    <Mode>coop</Mode>
  </GameData>
  <RuntimeProperties>
    <ErrorMessage></ErrorMessage>
    <CrashGUID>first</CrashGUID>
    <CrashGUID>second</CrashGUID>
  </RuntimeProperties>
</FGenericCrashContext>",
        )
        .extract(CrashContextExtractionOptions::default());

        assert_eq!(data.crash_guid.as_deref(), Some("first"));
        assert_eq!(data.crash_type, CrashType::Unknown);
        assert_eq!(data.error_message.as_deref(), Some(""));
        assert_eq!(data.platform, None);
        assert!(data.modules.is_empty());
        assert!(data.threads.is_empty());
        assert!(data.system_metadata.is_empty());
        assert_eq!(
            data.game_data,
            [
                CrashContextProperty {
                    name: "Mode".to_owned(),
                    value: "solo".to_owned(),
                },
                CrashContextProperty {
                    name: "Mode".to_owned(),
                    value: "coop".to_owned(),
                },
            ]
        );
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
