use std::{collections::BTreeMap, error::Error, fmt};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub const FINGERPRINT_ALGORITHM: &str = "stack";
pub const FINGERPRINT_VERSION: u32 = 1;

const MAX_COMPONENT_CHARS: usize = 512;
const MAX_ERROR_INPUT_CHARS: usize = 4096;
const MAX_ERROR_TEMPLATE_CHARS: usize = 1024;
const MAX_PROJECT_FRAMES: usize = 8;
const MAX_ENGINE_FRAMES: usize = 5;
const MAX_UNRESOLVED_FRAMES: usize = 8;
const MAX_VARIANT_FRAMES: usize = 32;
const MAX_TITLE_CHARS: usize = 160;

const ENGINE_MODULES: &[&str] = &[
    "applicationcore",
    "audioengine",
    "core",
    "coreuobject",
    "d3d11rhi",
    "d3d12rhi",
    "engine",
    "inputcore",
    "metalrhi",
    "openglDrv",
    "pakfile",
    "projects",
    "rendercore",
    "rhi",
    "slate",
    "slatecore",
    "vulkanrhi",
];

const SYSTEM_MODULES: &[&str] = &[
    "amdxx64",
    "atidxx64",
    "combase",
    "d3d11",
    "d3d12",
    "dxgi",
    "gdi32",
    "igd10iumd64",
    "kernel32",
    "kernelbase",
    "msvcp140",
    "ntdll",
    "nvwgf2umx",
    "ucrtbase",
    "user32",
    "vcruntime140",
    "win32u",
    "xaudio2_9",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fingerprint {
    pub issue_fingerprint: String,
    pub variant_fingerprint: String,
    pub title: String,
    pub grouping_quality: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupingOutcome {
    Grouped(Fingerprint),
    Insufficient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupingError {
    InvalidProcessingResult,
}

impl fmt::Display for GroupingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("processing result cannot be fingerprinted")
    }
}

impl Error for GroupingError {}

#[derive(Clone, Debug, Default)]
struct Components(Vec<(&'static str, String)>);

impl Components {
    fn push(&mut self, tag: &'static str, value: impl Into<String>) {
        let value = bounded(&value.into(), MAX_COMPONENT_CHARS);
        if !value.is_empty() {
            self.0.push((tag, value));
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameCategory {
    Project,
    Engine,
    System,
    Unknown,
}

#[derive(Clone, Debug)]
struct ResolvedFrame {
    category: FrameCategory,
    component: String,
    module: String,
    function: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModuleIdentity {
    debug_id: Option<String>,
    code_id: Option<String>,
}

#[derive(Clone, Debug)]
struct UnresolvedFrame {
    category: FrameCategory,
    component: String,
    module: String,
    relative: String,
}

#[derive(Clone, Debug)]
struct FrameEvidence {
    project: Vec<ResolvedFrame>,
    engine: Vec<ResolvedFrame>,
    unresolved: Vec<UnresolvedFrame>,
    variant: Vec<String>,
}

/// Produces the versioned issue and variant fingerprints for one validated processing result.
///
/// # Errors
///
/// Returns an error when the shared processing contract is invalid.
pub fn fingerprint(result: &Value) -> Result<GroupingOutcome, GroupingError> {
    faultlane_processing::validate_processing_result(result, None)
        .map_err(|_| GroupingError::InvalidProcessingResult)?;

    let context = object_at(result, "/crash_context")?;
    let symbolication = object_at(result, "/current/symbolication")?;
    let crash_type = string_field(context, "crash_type")?;
    let mut issue = Components::default();
    issue.push("crash_type", crash_type);

    let classification = result.get("classification").and_then(Value::as_object);
    let signals = classification
        .and_then(|value| value.get("signals"))
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |values| normalized_signals(values));
    for signal in &signals {
        issue.push("signal", signal.clone());
    }

    if let Some(reason) = symbolication
        .get("exception_reason")
        .and_then(Value::as_str)
        .map(normalize_template)
        .filter(|value| !value.is_empty())
    {
        issue.push("exception", reason);
    }

    let assertion = symbolication
        .get("assertion")
        .and_then(Value::as_str)
        .map(normalize_template)
        .filter(|value| has_specific_template_token(value));
    if let Some(value) = &assertion {
        issue.push("assertion", value.clone());
    }

    let frames = frame_evidence(symbolication)?;

    for frame in &frames.project {
        issue.push("project_frame", frame.component.clone());
    }
    for frame in &frames.engine {
        issue.push("engine_frame", frame.component.clone());
    }
    for frame in &frames.unresolved {
        issue.push("unresolved_frame", frame.component.clone());
    }

    let specific_error = matches!(crash_type, "assert" | "ensure") || !signals.is_empty();
    let error_template = context
        .get("error_message")
        .and_then(Value::as_str)
        .map(normalize_template)
        .filter(|value| has_specific_template_token(value));
    if specific_error
        && assertion.is_none()
        && let Some(value) = &error_template
    {
        issue.push("error_template", value.clone());
    }

    let stable_error = assertion.is_some() || specific_error && error_template.is_some();
    if frames.project.is_empty()
        && frames.engine.is_empty()
        && frames.unresolved.is_empty()
        && !stable_error
    {
        return Ok(GroupingOutcome::Insufficient);
    }

    let platform_specific = signals.iter().any(|signal| signal == "gpu_crash")
        || frames
            .unresolved
            .first()
            .is_some_and(|frame| frame.category == FrameCategory::System);
    if platform_specific
        && let Some(platform) = context
            .get("platform")
            .and_then(|value| value.get("normalized"))
            .and_then(Value::as_str)
    {
        issue.push("platform", normalize_token(platform));
    }

    let mut variant = issue.clone();
    add_classification_variant(classification, &mut variant);
    for component in &frames.variant {
        variant.push("variant_frame", component.clone());
    }

    let title = title(
        crash_type,
        &signals,
        &frames.project,
        &frames.engine,
        &frames.unresolved,
    );
    let grouping_quality = grouping_quality(&frames, assertion.is_some(), stable_error);

    Ok(GroupingOutcome::Grouped(Fingerprint {
        issue_fingerprint: digest("faultlane:issue:stack:1", &issue),
        variant_fingerprint: digest("faultlane:variant:stack:1", &variant),
        title,
        grouping_quality,
    }))
}

fn grouping_quality(frames: &FrameEvidence, has_assertion: bool, stable_error: bool) -> i32 {
    let project = i32::try_from(frames.project.len())
        .unwrap_or(i32::MAX)
        .min(8);
    let engine = i32::try_from(frames.engine.len())
        .unwrap_or(i32::MAX)
        .min(5);
    let unresolved = i32::try_from(frames.unresolved.len())
        .unwrap_or(i32::MAX)
        .min(8);
    project * 100
        + engine * 10
        + unresolved * 5
        + i32::from(has_assertion) * 3
        + i32::from(stable_error)
}

fn frame_evidence(
    symbolication: &serde_json::Map<String, Value>,
) -> Result<FrameEvidence, GroupingError> {
    let modules = module_identities(symbolication)?;
    let frames = faulting_frames(symbolication)?;
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();
    let mut variant = Vec::new();
    for frame in frames {
        if let Some(frame) = resolved_frame(frame) {
            if variant.len() < MAX_VARIANT_FRAMES {
                variant.push(format!("resolved|{}", frame.component));
            }
            resolved.push(frame);
        } else if let Some(frame) = unresolved_frame(frame, &modules) {
            if variant.len() < MAX_VARIANT_FRAMES {
                variant.push(format!("unresolved|{}", frame.component));
            }
            unresolved.push(frame);
        }
    }
    let project = resolved
        .iter()
        .filter(|frame| frame.category == FrameCategory::Project)
        .take(MAX_PROJECT_FRAMES)
        .cloned()
        .collect::<Vec<_>>();
    let engine = if project.is_empty() {
        resolved
            .iter()
            .filter(|frame| frame.category == FrameCategory::Engine)
            .take(MAX_ENGINE_FRAMES)
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let unresolved = if project.is_empty() && engine.is_empty() {
        unresolved.into_iter().take(MAX_UNRESOLVED_FRAMES).collect()
    } else {
        Vec::new()
    };
    Ok(FrameEvidence {
        project,
        engine,
        unresolved,
        variant,
    })
}

fn add_classification_variant(
    classification: Option<&serde_json::Map<String, Value>>,
    variant: &mut Components,
) {
    let Some(classification) = classification else {
        return;
    };
    if let Some(confidence) = classification.get("confidence").and_then(Value::as_str) {
        variant.push("classification_confidence", normalize_token(confidence));
    }
    if let Some(evidence) = classification.get("evidence").and_then(Value::as_array) {
        let mut evidence = evidence
            .iter()
            .filter_map(Value::as_str)
            .map(normalize_template)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        evidence.sort();
        evidence.dedup();
        for value in evidence.into_iter().take(8) {
            variant.push("classification_evidence", value);
        }
    }
}

fn object_at<'value>(
    value: &'value Value,
    pointer: &str,
) -> Result<&'value serde_json::Map<String, Value>, GroupingError> {
    value
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or(GroupingError::InvalidProcessingResult)
}

fn string_field<'value>(
    value: &'value serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'value str, GroupingError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(GroupingError::InvalidProcessingResult)
}

fn normalized_signals(signals: &[Value]) -> Vec<String> {
    let mut values = signals
        .iter()
        .filter_map(|value| value.get("kind"))
        .filter_map(Value::as_str)
        .filter(|kind| matches!(*kind, "gpu_crash" | "out_of_memory"))
        .map(normalize_token)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn module_identities(
    symbolication: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, Vec<ModuleIdentity>>, GroupingError> {
    let modules = symbolication
        .get("modules")
        .and_then(Value::as_array)
        .ok_or(GroupingError::InvalidProcessingResult)?;
    let mut identities = BTreeMap::<String, Vec<ModuleIdentity>>::new();
    for module in modules {
        let module_name = module
            .get("module")
            .and_then(Value::as_str)
            .ok_or(GroupingError::InvalidProcessingResult)?;
        let identity = ModuleIdentity {
            debug_id: module
                .get("debug_id")
                .and_then(Value::as_str)
                .map(normalize_token)
                .filter(|value| !value.is_empty()),
            code_id: module
                .get("code_id")
                .and_then(Value::as_str)
                .map(normalize_token)
                .filter(|value| !value.is_empty()),
        };
        let entry = identities.entry(normalize_module(module_name)).or_default();
        entry.push(identity);
        entry.sort();
        entry.dedup();
    }
    Ok(identities)
}

fn faulting_frames(
    symbolication: &serde_json::Map<String, Value>,
) -> Result<&[Value], GroupingError> {
    symbolication
        .get("threads")
        .and_then(Value::as_array)
        .and_then(|threads| {
            threads
                .iter()
                .find(|thread| thread.get("faulting").and_then(Value::as_bool) == Some(true))
        })
        .and_then(|thread| thread.get("frames"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(GroupingError::InvalidProcessingResult)
}

fn resolved_frame(frame: &Value) -> Option<ResolvedFrame> {
    if frame.get("symbol_status").and_then(Value::as_str) != Some("resolved") {
        return None;
    }
    let module = normalize_module(frame.get("module")?.as_str()?);
    let function = normalize_function(frame.get("function")?.as_str()?);
    if module.is_empty() || function.is_empty() {
        return None;
    }
    let mut functions = frame
        .get("inlines")?
        .as_array()?
        .iter()
        .filter_map(|inline| inline.get("function"))
        .filter_map(Value::as_str)
        .map(normalize_function)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    functions.push(function.clone());
    let category = frame_category(
        &module,
        frame
            .get("source_file")
            .and_then(Value::as_str)
            .into_iter()
            .chain(
                frame
                    .get("inlines")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|inline| inline.get("source_file"))
                    .filter_map(Value::as_str),
            ),
    );
    Some(ResolvedFrame {
        category,
        component: format!("{module}|{}", functions.join(">")),
        module,
        function,
    })
}

fn unresolved_frame(
    frame: &Value,
    modules: &BTreeMap<String, Vec<ModuleIdentity>>,
) -> Option<UnresolvedFrame> {
    if frame.get("symbol_status").and_then(Value::as_str) == Some("resolved") {
        return None;
    }
    let module = normalize_module(frame.get("module")?.as_str()?);
    let relative = normalize_relative(frame.get("module_relative")?.as_str()?)?;
    let identities = modules.get(&module)?;
    let [identity] = identities.as_slice() else {
        return None;
    };
    if identity.debug_id.is_none() && identity.code_id.is_none() {
        return None;
    }
    let category = frame_category(&module, std::iter::empty());
    Some(UnresolvedFrame {
        category,
        component: format!(
            "{module}|{}|{}|{relative}",
            identity.debug_id.as_deref().unwrap_or(""),
            identity.code_id.as_deref().unwrap_or("")
        ),
        module,
        relative,
    })
}

fn frame_category<'path>(
    module: &str,
    source_paths: impl Iterator<Item = &'path str>,
) -> FrameCategory {
    if source_paths
        .map(normalize_path)
        .any(|path| path.starts_with("engine/source/") || path.contains("/engine/source/"))
        || module.starts_with("unrealeditor-")
        || module.starts_with("ue4editor-")
        || ENGINE_MODULES
            .iter()
            .any(|known| module.eq_ignore_ascii_case(known))
    {
        FrameCategory::Engine
    } else if SYSTEM_MODULES
        .iter()
        .any(|known| module.eq_ignore_ascii_case(known))
    {
        FrameCategory::System
    } else if module.is_empty() || module == "unknown" {
        FrameCategory::Unknown
    } else {
        FrameCategory::Project
    }
}

fn normalize_module(value: &str) -> String {
    let leaf = value
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    let value = leaf
        .strip_suffix(".dll")
        .or_else(|| leaf.strip_suffix(".exe"))
        .unwrap_or(&leaf);
    bounded(value, MAX_COMPONENT_CHARS)
}

fn normalize_function(value: &str) -> String {
    bounded(&collapse_whitespace(value), MAX_COMPONENT_CHARS)
}

fn normalize_path(value: &str) -> String {
    bounded(
        &value.replace('\\', "/").trim().to_ascii_lowercase(),
        MAX_COMPONENT_CHARS,
    )
}

fn normalize_token(value: &str) -> String {
    bounded(
        &collapse_whitespace(value).to_ascii_lowercase(),
        MAX_COMPONENT_CHARS,
    )
}

fn normalize_relative(value: &str) -> Option<String> {
    let value = value.trim();
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16)
        .ok()
        .map(|number| format!("0x{number:x}"))
}

fn normalize_template(value: &str) -> String {
    let input = bounded(value, MAX_ERROR_INPUT_CHARS);
    let characters = input.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    while index < characters.len() {
        if let Some(end) = guid_end(&characters, index) {
            push_template(&mut output, "<guid>");
            index = end;
        } else if let Some(end) = timestamp_end(&characters, index) {
            push_template(&mut output, "<timestamp>");
            index = end;
        } else if let Some(end) = address_end(&characters, index) {
            push_template(&mut output, "<address>");
            index = end;
        } else if characters[index].is_ascii_digit() {
            let mut end = index + 1;
            while end < characters.len() && characters[end].is_ascii_digit() {
                end += 1;
            }
            push_template(&mut output, "<number>");
            index = end;
        } else if characters[index].is_whitespace() {
            if !output.is_empty() && !output.ends_with(' ') {
                output.push(' ');
            }
            index += 1;
        } else if characters[index].is_control() {
            index += 1;
        } else {
            output.push(characters[index].to_ascii_lowercase());
            index += 1;
        }
    }
    bounded(output.trim(), MAX_ERROR_TEMPLATE_CHARS)
}

fn has_specific_template_token(value: &str) -> bool {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| {
            !matches!(
                token,
                "address"
                    | "allocate"
                    | "allocation"
                    | "assert"
                    | "assertion"
                    | "at"
                    | "being"
                    | "byte"
                    | "bytes"
                    | "check"
                    | "condition"
                    | "crash"
                    | "crashed"
                    | "d3d"
                    | "device"
                    | "dxgi"
                    | "ensure"
                    | "error"
                    | "failed"
                    | "failure"
                    | "fatal"
                    | "for"
                    | "gpu"
                    | "guid"
                    | "line"
                    | "lost"
                    | "memory"
                    | "number"
                    | "of"
                    | "oom"
                    | "out"
                    | "removed"
                    | "timeout"
                    | "timestamp"
                    | "unknown"
            )
        })
}

fn push_template(output: &mut String, placeholder: &str) {
    if !output.ends_with(placeholder) {
        output.push_str(placeholder);
    }
}

fn guid_end(characters: &[char], start: usize) -> Option<usize> {
    const GROUPS: &[usize] = &[8, 4, 4, 4, 12];
    let mut index = start;
    for (group_index, length) in GROUPS.iter().enumerate() {
        for _ in 0..*length {
            if !characters.get(index).is_some_and(char::is_ascii_hexdigit) {
                return None;
            }
            index += 1;
        }
        if group_index + 1 < GROUPS.len() {
            if characters.get(index) != Some(&'-') {
                return None;
            }
            index += 1;
        }
    }
    Some(index)
}

fn timestamp_end(characters: &[char], start: usize) -> Option<usize> {
    let separators = [(4, '-'), (7, '-')];
    for offset in 0..10 {
        let character = *characters.get(start + offset)?;
        if let Some((_, separator)) = separators.iter().find(|(at, _)| *at == offset) {
            if character != *separator {
                return None;
            }
        } else if !character.is_ascii_digit() {
            return None;
        }
    }
    let mut end = start + 10;
    if characters
        .get(end)
        .is_some_and(|value| matches!(value, 'T' | 't' | ' '))
    {
        end += 1;
        while characters.get(end).is_some_and(|value| {
            value.is_ascii_digit() || matches!(value, ':' | '.' | '+' | '-' | 'Z' | 'z')
        }) {
            end += 1;
        }
    }
    Some(end)
}

fn address_end(characters: &[char], start: usize) -> Option<usize> {
    if characters.get(start) != Some(&'0')
        || !characters
            .get(start + 1)
            .is_some_and(|value| matches!(value, 'x' | 'X'))
        || !characters
            .get(start + 2)
            .is_some_and(char::is_ascii_hexdigit)
    {
        return None;
    }
    let mut end = start + 3;
    while characters.get(end).is_some_and(char::is_ascii_hexdigit) {
        end += 1;
    }
    Some(end)
}

fn collapse_whitespace(value: &str) -> String {
    let mut normalized = String::new();
    for character in value.chars() {
        if character.is_whitespace() {
            if !normalized.is_empty() && !normalized.ends_with(' ') {
                normalized.push(' ');
            }
        } else if !character.is_control() {
            normalized.push(character);
        }
    }
    normalized.trim().to_owned()
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn title(
    crash_type: &str,
    signals: &[String],
    project: &[ResolvedFrame],
    engine: &[ResolvedFrame],
    unresolved: &[UnresolvedFrame],
) -> String {
    let value = if let Some(frame) = project.first().or_else(|| engine.first()) {
        format!("{} in {}", frame.function, frame.module)
    } else if let Some(frame) = unresolved.first() {
        format!("{}+{}", frame.module, frame.relative)
    } else if signals.iter().any(|value| value == "gpu_crash") {
        "GPU crash".to_owned()
    } else if signals.iter().any(|value| value == "out_of_memory") {
        "Out of memory".to_owned()
    } else {
        match crash_type {
            "assert" => "Assertion failure",
            "ensure" => "Ensure failure",
            _ => "Crash",
        }
        .to_owned()
    };
    sanitize_title(&value)
}

fn sanitize_title(value: &str) -> String {
    let mut title = String::new();
    for character in collapse_whitespace(value).chars().take(MAX_TITLE_CHARS) {
        if matches!(character, '<' | '>' | '&' | '\'' | '"') {
            title.push('_');
        } else if !character.is_control() {
            title.push(character);
        }
    }
    if title.is_empty() {
        "Crash".to_owned()
    } else {
        title
    }
}

fn digest(domain: &str, components: &Components) -> String {
    let mut hasher = Sha256::new();
    append(&mut hasher, domain.as_bytes());
    for (tag, value) in &components.0 {
        append(&mut hasher, tag.as_bytes());
        append(&mut hasher, value.as_bytes());
    }
    lower_hex(&hasher.finalize())
}

fn append(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        FINGERPRINT_ALGORITHM, FINGERPRINT_VERSION, GroupingOutcome, fingerprint,
        normalize_template,
    };

    fn frame(module: &str, function: &str, source: &str) -> Value {
        json!({
            "instruction": "0x0000000140001000",
            "module": module,
            "module_relative": "0x1000",
            "trust": "context",
            "symbol_status": "resolved",
            "function": function,
            "source_file": source,
            "source_line": 42,
            "inlines": []
        })
    }

    fn unresolved(module: &str, relative: &str) -> Value {
        json!({
            "instruction": "0x0000000140001000",
            "module": module,
            "module_relative": relative,
            "trust": "context",
            "symbol_status": "missing_pdb",
            "function": null,
            "source_file": null,
            "source_line": null,
            "inlines": []
        })
    }

    fn result(crash_type: &str, frames: &[Value]) -> Value {
        json!({
            "schema_version": 1,
            "crash_guid": "UECC-Windows-Grouping",
            "crash_context": {
                "parser_version": 1,
                "crash_guid": "UECC-Windows-Grouping",
                "crash_type": crash_type,
                "error_message": null,
                "build_version": "1.0.0",
                "engine_version": "5.8.1",
                "platform": {"original": "Win64", "normalized": "windows"},
                "architecture": "x86_64",
                "build_configuration": "Shipping",
                "modules": [],
                "threads": [],
                "system_metadata": [],
                "user_comment": null,
                "game_data": [],
                "unknown_fields": {}
            },
            "classification": {
                "crash_type": crash_type,
                "confidence": "high",
                "evidence": [],
                "signals": []
            },
            "current": {
                "processing_version": 1,
                "parser_version": 1,
                "symbolication": {
                    "schema_version": 1,
                    "symbolicator_version": "0.1.0",
                    "minidump_version": "0.27.0",
                    "minidump_processor_version": "0.27.0",
                    "minidump_unwind_version": "0.27.0",
                    "platform": "windows",
                    "architecture": "x86_64",
                    "faulting_thread_id": 7,
                    "modules": [{
                        "module": "Game.exe",
                        "base_address": "0x0000000140000000",
                        "size": 4096,
                        "code_id": "CODE-A",
                        "debug_id": "DEBUG-A",
                        "status": "matched",
                        "pe": "game.exe",
                        "pdb": "game.pdb"
                    }],
                    "threads": [{
                        "thread_id": 7,
                        "faulting": true,
                        "name": "GameThread",
                        "unwind_status": "ok",
                        "frames_truncated": false,
                        "frames": frames
                    }]
                }
            },
            "history": []
        })
    }

    fn grouped(value: &Value) -> super::Fingerprint {
        match fingerprint(value).unwrap_or_else(|error| panic!("fixture must fingerprint: {error}"))
        {
            GroupingOutcome::Grouped(value) => value,
            GroupingOutcome::Insufficient => panic!("fixture must contain stable evidence"),
        }
    }

    #[test]
    fn exposes_the_checked_algorithm_identity() {
        assert_eq!(FINGERPRINT_ALGORITHM, "stack");
        assert_eq!(FINGERPRINT_VERSION, 1);
    }

    #[test]
    fn joins_repeats_across_volatile_addresses_paths_lines_and_releases() {
        let first = result(
            "crash",
            &[frame(
                "Game.exe",
                "Arena::Tick(int)",
                r"D:\\first\\Game\\Source\\Arena.cpp",
            )],
        );
        let mut second = first.clone();
        second["crash_guid"] = json!("UECC-Windows-Other");
        second["crash_context"]["crash_guid"] = json!("UECC-Windows-Other");
        second["crash_context"]["build_version"] = json!("2.0.0");
        second["current"]["symbolication"]["threads"][0]["frames"][0]["instruction"] =
            json!("0x0000000140ABCDEF");
        second["current"]["symbolication"]["threads"][0]["frames"][0]["source_file"] =
            json!(r"E:\\relocated\\Game\\Source\\Arena.cpp");
        second["current"]["symbolication"]["threads"][0]["frames"][0]["source_line"] = json!(9001);

        let first = grouped(&first);
        let second = grouped(&second);
        assert_eq!(first.issue_fingerprint, second.issue_fingerprint);
        assert_eq!(first.variant_fingerprint, second.variant_fingerprint);
        assert_eq!(first.title, "Arena::Tick(int) in game");
        assert_eq!(first.grouping_quality, 100);
    }

    #[test]
    fn splits_different_classes_project_frames_and_assertions() {
        let first = result(
            "crash",
            &[frame("Game.exe", "Arena::Tick()", "Game/Source/Arena.cpp")],
        );
        let different_frame = result(
            "crash",
            &[frame("Game.exe", "Arena::Load()", "Game/Source/Arena.cpp")],
        );
        let different_class = result(
            "assert",
            &[frame("Game.exe", "Arena::Tick()", "Game/Source/Arena.cpp")],
        );
        assert_ne!(
            grouped(&first).issue_fingerprint,
            grouped(&different_frame).issue_fingerprint
        );
        assert_ne!(
            grouped(&first).issue_fingerprint,
            grouped(&different_class).issue_fingerprint
        );

        let mut first_assert = different_class.clone();
        first_assert["crash_context"]["error_message"] =
            json!("check Player != nullptr at line 100");
        let mut second_assert = different_class;
        second_assert["crash_context"]["error_message"] =
            json!("check World != nullptr at line 200");
        assert_ne!(
            grouped(&first_assert).issue_fingerprint,
            grouped(&second_assert).issue_fingerprint
        );
    }

    #[test]
    fn unresolved_build_identities_split_and_exact_repeats_join() {
        let first = result("crash", &[unresolved("Game.exe", "0x1000")]);
        let repeat = first.clone();
        let mut other = first.clone();
        other["current"]["symbolication"]["modules"][0]["debug_id"] = json!("DEBUG-B");
        assert_eq!(
            grouped(&first).issue_fingerprint,
            grouped(&repeat).issue_fingerprint
        );
        assert_ne!(
            grouped(&first).issue_fingerprint,
            grouped(&other).issue_fingerprint
        );
    }

    #[test]
    fn consumes_version_two_exception_and_assertion_fields() {
        let mut first = result(
            "assert",
            &[frame("Game.exe", "Arena::Tick()", "Game/Source/Arena.cpp")],
        );
        first["current"]["processing_version"] = json!(2);
        first["current"]["symbolication"]["schema_version"] = json!(2);
        first["current"]["symbolication"]["exception_reason"] = json!("EXCEPTION_BREAKPOINT");
        first["current"]["symbolication"]["assertion"] = json!("Player != nullptr at line 100");
        let mut volatile_repeat = first.clone();
        volatile_repeat["current"]["symbolication"]["assertion"] =
            json!("Player != nullptr at line 900");
        let mut different = first.clone();
        different["current"]["symbolication"]["assertion"] = json!("World != nullptr at line 100");

        assert_eq!(
            grouped(&first).issue_fingerprint,
            grouped(&volatile_repeat).issue_fingerprint
        );
        assert_ne!(
            grouped(&first).issue_fingerprint,
            grouped(&different).issue_fingerprint
        );
    }

    #[test]
    fn stack_poor_generic_crashes_are_not_grouped() {
        let value = result("crash", &[]);
        assert_eq!(
            fingerprint(&value).unwrap_or_else(|error| panic!("fixture must fingerprint: {error}")),
            GroupingOutcome::Insufficient
        );
    }

    #[test]
    fn gpu_and_oom_specific_templates_do_not_collapse_broadly() {
        let mut gpu = result("crash", &[]);
        gpu["classification"]["signals"] = json!([{
            "kind": "gpu_crash",
            "confidence": "high",
            "evidence": ["DXGI device removed"]
        }]);
        gpu["crash_context"]["error_message"] =
            json!("DXGI_ERROR_DEVICE_HUNG while presenting Arena viewport at 0xABC");
        let mut other_gpu = gpu.clone();
        other_gpu["crash_context"]["error_message"] =
            json!("DXGI_ERROR_DRIVER_INTERNAL_ERROR while uploading Arena texture");
        let mut oom = gpu.clone();
        oom["classification"]["signals"][0]["kind"] = json!("out_of_memory");
        oom["crash_context"]["error_message"] =
            json!("ArenaPool allocation failed for 1048576 bytes");
        assert_ne!(
            grouped(&gpu).issue_fingerprint,
            grouped(&other_gpu).issue_fingerprint
        );
        assert_ne!(
            grouped(&gpu).issue_fingerprint,
            grouped(&oom).issue_fingerprint
        );
    }

    #[test]
    fn generic_stack_poor_errors_are_not_grouped() {
        let mut gpu = result("crash", &[]);
        gpu["classification"]["signals"] = json!([{
            "kind": "gpu_crash",
            "confidence": "high",
            "evidence": ["crash_context.crash_type_gpu"]
        }]);
        gpu["crash_context"]["error_message"] = json!("GPU crash at 0xABC");
        let mut assertion = result("assert", &[]);
        assertion["crash_context"]["error_message"] = json!("Assertion failed at line 42");

        for value in [gpu, assertion] {
            assert_eq!(
                fingerprint(&value)
                    .unwrap_or_else(|error| panic!("fixture must fingerprint: {error}")),
                GroupingOutcome::Insufficient
            );
        }
    }

    #[test]
    fn templates_replace_volatile_values_with_typed_placeholders() {
        let first = normalize_template(
            "Failure 123 at 0xABCDEF, guid 01234567-89ab-cdef-0123-456789abcdef, 2026-08-14T12:30:45Z",
        );
        let second = normalize_template(
            "Failure 999 at 0x123456, guid fedcba98-7654-3210-fedc-ba9876543210, 2027-01-01T00:00:00Z",
        );
        assert_eq!(first, second);
        assert_eq!(
            first,
            "failure <number> at <address>, guid <guid>, <timestamp>"
        );
    }

    #[test]
    fn titles_are_bounded_and_remove_markup_characters() {
        let value = result(
            "crash",
            &[frame(
                "Game.exe",
                "<script>alert('x')</script>",
                "Game/Source/Arena.cpp",
            )],
        );
        let title = grouped(&value).title;
        assert!(!title.contains(['<', '>', '&', '\'', '"']));
        assert!(title.chars().count() <= super::MAX_TITLE_CHARS);
    }

    #[test]
    fn golden_fingerprint_is_stable() {
        let value = result(
            "crash",
            &[frame("Game.exe", "Arena::Tick()", "Game/Source/Arena.cpp")],
        );
        let grouped = grouped(&value);
        assert_eq!(
            grouped.issue_fingerprint,
            "521191c0ddf9079c8cae745230b896c8f8f86735401c2bd82f7751407ca7ce40"
        );
        assert_eq!(
            grouped.variant_fingerprint,
            "d0d81da600a95e7012d35735685f4c074b45fee9c7850298150131db52131d02"
        );
    }
}
