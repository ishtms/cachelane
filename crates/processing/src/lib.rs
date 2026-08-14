use std::{error::Error, fmt, io::Read, path::Path};

use faultlane_symbols::{
    SymCacheArtifact, SymbolicationError, SymbolicationLimits, SymbolicationResult,
    symbolicate_minidump_bytes, symbolicate_minidump_bytes_with_symcaches,
};
use faultlane_unreal::{
    CRASH_CONTEXT_PARSER_VERSION, CrashClassification, CrashContextData,
    CrashContextExtractionOptions, CrashContextParser, CrashRequestError, CrashRequestLimits,
    CrashRequestLog, CrashRequestManifest, ParseError, read_crash_request,
};
use serde::Serialize;
use serde_json::Value;

pub const RESULT_SCHEMA_VERSION: u32 = 1;
pub const PROCESSING_VERSION: u32 = 2;
pub const MAX_PROCESSING_HISTORY: usize = 16;
const MAX_CRASH_CONTEXT_NODES: u32 = 100_000;

#[derive(Debug)]
pub enum CrashProcessingError {
    Request(CrashRequestError),
    Parse(ParseError),
    Symbolicate(SymbolicationError),
    MissingCrashContext,
    MissingMinidump,
    Result(ProcessingResultError),
}

impl fmt::Display for CrashProcessingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(formatter),
            Self::Parse(error) => error.fmt(formatter),
            Self::Symbolicate(error) => error.fmt(formatter),
            Self::MissingCrashContext => formatter.write_str("crash request has no crash context"),
            Self::MissingMinidump => formatter.write_str("crash request has no minidump"),
            Self::Result(error) => error.fmt(formatter),
        }
    }
}

impl Error for CrashProcessingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Symbolicate(error) => Some(error),
            Self::Result(error) => Some(error),
            Self::MissingCrashContext | Self::MissingMinidump => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviousProcessing {
    current: Value,
    history: Vec<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingResultError {
    MissingCrashIdentity,
    InvalidPrevious,
    UnsupportedPreviousSchema,
    UnsupportedPreviousProcessing,
    PreviousIdentityMismatch,
    PreviousHistoryTooLong,
    Serialize,
}

impl fmt::Display for ProcessingResultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingCrashIdentity => "crash context has no usable crash identity",
            Self::InvalidPrevious => "invalid previous processing result",
            Self::UnsupportedPreviousSchema => "unsupported previous result schema version",
            Self::UnsupportedPreviousProcessing => "unsupported previous processing version",
            Self::PreviousIdentityMismatch => "previous result crash identity does not match",
            Self::PreviousHistoryTooLong => "previous processing history limit exceeded",
            Self::Serialize => "failed to serialize processing result",
        })
    }
}

impl Error for ProcessingResultError {}

#[derive(Serialize)]
struct ProcessingAttempt<'result> {
    processing_version: u32,
    parser_version: u32,
    symbolication: &'result SymbolicationResult,
}

#[derive(Serialize)]
struct ProcessingResult<'result> {
    schema_version: u32,
    crash_guid: &'result str,
    crash_context: &'result CrashContextData,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<&'result CrashRequestManifest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<&'result CrashClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log: Option<&'result CrashRequestLog>,
    current: &'result Value,
    history: &'result [Value],
}

/// Processes one complete UE crash request into the shared versioned result.
///
/// # Errors
///
/// Returns an error when the request, crash context, minidump, symbols, cache inputs, or previous
/// result are invalid or exceed their configured limits.
pub fn process_crash_request<R: Read>(
    reader: R,
    symbols: &Path,
    symcaches: &[SymCacheArtifact],
    previous: Option<&[u8]>,
) -> Result<Value, CrashProcessingError> {
    let contents = read_crash_request(reader, CrashRequestLimits::default())
        .map_err(CrashProcessingError::Request)?;
    let xml = contents
        .crash_context
        .as_deref()
        .ok_or(CrashProcessingError::MissingCrashContext)?;
    let parsed = CrashContextParser::new(MAX_CRASH_CONTEXT_NODES)
        .parse(xml)
        .map_err(CrashProcessingError::Parse)?;
    let classification = parsed.classification();
    let crash_context = parsed.extract(CrashContextExtractionOptions::default());
    let previous = previous
        .map(|bytes| parse_previous_processing(bytes, crash_guid(&crash_context)?))
        .transpose()
        .map_err(CrashProcessingError::Result)?;
    let minidump = contents
        .minidump
        .ok_or(CrashProcessingError::MissingMinidump)?;
    let symbolication = if symcaches.is_empty() {
        symbolicate_minidump_bytes(minidump, symbols, SymbolicationLimits::default())
    } else {
        symbolicate_minidump_bytes_with_symcaches(
            minidump,
            symbols,
            symcaches,
            SymbolicationLimits::default(),
        )
    }
    .map_err(CrashProcessingError::Symbolicate)?;

    build_processing_result(
        &crash_context,
        &symbolication,
        previous,
        Some(&contents.manifest),
        Some(&classification),
        contents.log.as_ref(),
    )
    .map_err(CrashProcessingError::Result)
}

/// Composes normalized crash context and symbolication into the shared result contract.
///
/// # Errors
///
/// Returns an error when crash identity is missing, history exceeds its limit, or serialization
/// fails.
pub fn build_processing_result(
    crash_context: &CrashContextData,
    symbolication: &SymbolicationResult,
    previous: Option<PreviousProcessing>,
    request: Option<&CrashRequestManifest>,
    classification: Option<&CrashClassification>,
    log: Option<&CrashRequestLog>,
) -> Result<Value, ProcessingResultError> {
    let crash_guid = crash_guid(crash_context)?;
    let current = serde_json::to_value(ProcessingAttempt {
        processing_version: PROCESSING_VERSION,
        parser_version: crash_context.parser_version,
        symbolication,
    })
    .map_err(|_| ProcessingResultError::Serialize)?;
    let mut history = previous
        .as_ref()
        .map_or_else(Vec::new, |result| result.history.clone());

    if let Some(previous) = previous
        && previous.current != current
    {
        if history.len() == MAX_PROCESSING_HISTORY {
            return Err(ProcessingResultError::PreviousHistoryTooLong);
        }
        history.push(previous.current);
    }

    serde_json::to_value(ProcessingResult {
        schema_version: RESULT_SCHEMA_VERSION,
        crash_guid,
        crash_context,
        request,
        classification,
        log,
        current: &current,
        history: &history,
    })
    .map_err(|_| ProcessingResultError::Serialize)
}

/// Validates a prior result and extracts its bounded processing history.
///
/// # Errors
///
/// Returns an error when the result schema, processing version, crash identity, or history is
/// invalid.
pub fn parse_previous_processing(
    bytes: &[u8],
    crash_guid: &str,
) -> Result<PreviousProcessing, ProcessingResultError> {
    let result: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingResultError::InvalidPrevious)?;
    validate_processing_result(&result, Some(crash_guid))?;
    let result = result
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    let current = result
        .get("current")
        .cloned()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    let history = result
        .get("history")
        .and_then(Value::as_array)
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    Ok(PreviousProcessing {
        current,
        history: history.clone(),
    })
}

/// Validates the shared result schema and optional expected crash identity.
///
/// # Errors
///
/// Returns an error when required fields, versions, nested result structure, or identity are
/// invalid.
pub fn validate_processing_result(
    result: &Value,
    expected_crash_guid: Option<&str>,
) -> Result<(), ProcessingResultError> {
    validate_processing_contract(result, expected_crash_guid, false)
}

/// Validates a newly emitted result and requires the current processing contract.
///
/// # Errors
///
/// Returns an error when the result is historical or any shared contract field is invalid.
pub fn validate_current_processing_result(
    result: &Value,
    expected_crash_guid: Option<&str>,
) -> Result<(), ProcessingResultError> {
    validate_processing_contract(result, expected_crash_guid, true)
}

fn validate_processing_contract(
    result: &Value,
    expected_crash_guid: Option<&str>,
    require_current: bool,
) -> Result<(), ProcessingResultError> {
    let result = result
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if !only_keys(
        result,
        &[
            "schema_version",
            "crash_guid",
            "crash_context",
            "request",
            "classification",
            "log",
            "current",
            "history",
        ],
    ) {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    match result.get("schema_version").and_then(Value::as_u64) {
        Some(version) if version == u64::from(RESULT_SCHEMA_VERSION) => {}
        Some(_) => return Err(ProcessingResultError::UnsupportedPreviousSchema),
        None => return Err(ProcessingResultError::InvalidPrevious),
    }
    let crash_guid = result
        .get("crash_guid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if expected_crash_guid.is_some_and(|expected| expected != crash_guid) {
        return Err(ProcessingResultError::PreviousIdentityMismatch);
    }
    let history = result
        .get("history")
        .and_then(Value::as_array)
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if history.len() > MAX_PROCESSING_HISTORY {
        return Err(ProcessingResultError::PreviousHistoryTooLong);
    }
    let current = result
        .get("current")
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if require_current
        && current.get("processing_version").and_then(Value::as_u64)
            != Some(u64::from(PROCESSING_VERSION))
    {
        return Err(ProcessingResultError::UnsupportedPreviousProcessing);
    }
    validate_attempt(current)?;
    for attempt in history {
        validate_attempt(attempt)?;
    }
    let context = result
        .get("crash_context")
        .and_then(Value::as_object)
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if context.get("crash_guid").and_then(Value::as_str) != Some(crash_guid) {
        return Err(ProcessingResultError::PreviousIdentityMismatch);
    }
    validate_crash_context(context)?;
    if result
        .get("current")
        .and_then(|current| current.get("parser_version"))
        .and_then(Value::as_u64)
        != context.get("parser_version").and_then(Value::as_u64)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    if let Some(request) = result.get("request") {
        validate_request(request)?;
    }
    if let Some(classification) = result.get("classification") {
        validate_classification(classification)?;
    }
    if let Some(log) = result.get("log") {
        validate_log(log)?;
    }
    Ok(())
}

fn validate_crash_context(
    context: &serde_json::Map<String, Value>,
) -> Result<(), ProcessingResultError> {
    if !matches!(context.len(), 15 | 16)
        || !only_keys(
            context,
            &[
                "parser_version",
                "crash_guid",
                "crash_type",
                "error_message",
                "build_version",
                "engine_version",
                "platform",
                "architecture",
                "build_configuration",
                "command_line",
                "modules",
                "threads",
                "system_metadata",
                "user_comment",
                "game_data",
                "unknown_fields",
            ],
        )
        || context.get("parser_version").and_then(Value::as_u64)
            != Some(u64::from(CRASH_CONTEXT_PARSER_VERSION))
        || !context.get("crash_guid").is_some_and(nullable_string)
        || !context
            .get("crash_type")
            .and_then(Value::as_str)
            .is_some_and(valid_crash_type)
        || [
            "error_message",
            "build_version",
            "engine_version",
            "architecture",
            "build_configuration",
            "user_comment",
        ]
        .iter()
        .any(|field| {
            context
                .get(*field)
                .is_none_or(|value| !nullable_string(value))
        })
        || context
            .get("command_line")
            .is_some_and(|value| !value.is_string())
        || context
            .get("platform")
            .is_none_or(|value| !value.is_null() && validate_normalized_value(value).is_err())
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    validate_array(context, "modules", validate_normalized_value)?;
    validate_array(context, "threads", validate_context_thread)?;
    validate_array(context, "system_metadata", validate_property)?;
    validate_array(context, "game_data", validate_property)?;
    validate_unknown_fields(
        context
            .get("unknown_fields")
            .ok_or(ProcessingResultError::InvalidPrevious)?,
    )
}

fn validate_normalized_value(value: &Value) -> Result<(), ProcessingResultError> {
    validate_string_object(value, &["original", "normalized"])
}

fn validate_property(value: &Value) -> Result<(), ProcessingResultError> {
    validate_string_object(value, &["name", "value"])
}

fn validate_string_object(value: &Value, fields: &[&str]) -> Result<(), ProcessingResultError> {
    let object = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if object.len() != fields.len()
        || !only_keys(object, fields)
        || fields
            .iter()
            .any(|field| object.get(*field).is_none_or(|value| !value.is_string()))
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_context_thread(value: &Value) -> Result<(), ProcessingResultError> {
    let thread = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    let fields = [
        "call_stack",
        "crash_marker",
        "registers",
        "thread_id",
        "thread_name",
    ];
    if thread.len() != fields.len()
        || !only_keys(thread, &fields)
        || fields.iter().any(|field| {
            thread
                .get(*field)
                .is_none_or(|value| !nullable_string(value))
        })
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_unknown_fields(value: &Value) -> Result<(), ProcessingResultError> {
    let sections = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    for fields in sections.values() {
        let fields = fields
            .as_object()
            .ok_or(ProcessingResultError::InvalidPrevious)?;
        if fields.values().any(|values| {
            values
                .as_array()
                .is_none_or(|values| values.iter().any(|value| !value.is_string()))
        }) {
            return Err(ProcessingResultError::InvalidPrevious);
        }
    }
    Ok(())
}

fn validate_request(value: &Value) -> Result<(), ProcessingResultError> {
    let request = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if request.len() != 7
        || !only_keys(
            request,
            &[
                "schema_version",
                "envelope",
                "directory_name",
                "archive_name",
                "compressed_size",
                "expanded_size",
                "files",
            ],
        )
        || request.get("schema_version").and_then(Value::as_u64) != Some(1)
        || request.get("envelope").and_then(Value::as_str) != Some("cr1")
        || ["directory_name", "archive_name"]
            .iter()
            .any(|field| request.get(*field).and_then(Value::as_str).is_none())
        || ["compressed_size", "expanded_size"]
            .iter()
            .any(|field| request.get(*field).and_then(Value::as_u64).is_none())
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    validate_array(request, "files", validate_request_file)
}

fn validate_request_file(value: &Value) -> Result<(), ProcessingResultError> {
    let file = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if file.len() != 4
        || !only_keys(file, &["index", "name", "size", "kind"])
        || file.get("index").and_then(Value::as_u64).is_none()
        || file.get("name").and_then(Value::as_str).is_none()
        || file.get("size").and_then(Value::as_u64).is_none()
        || !file
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "crash_context" | "minidump" | "log" | "unknown"))
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_classification(value: &Value) -> Result<(), ProcessingResultError> {
    let classification = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if classification.len() != 4
        || !only_keys(
            classification,
            &["crash_type", "confidence", "evidence", "signals"],
        )
        || !classification
            .get("crash_type")
            .and_then(Value::as_str)
            .is_some_and(valid_crash_type)
        || !classification
            .get("confidence")
            .and_then(Value::as_str)
            .is_some_and(valid_confidence)
        || !classification.get("evidence").is_some_and(string_array)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    validate_array(classification, "signals", validate_signal)
}

fn validate_signal(value: &Value) -> Result<(), ProcessingResultError> {
    let signal = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if signal.len() != 3
        || !only_keys(signal, &["kind", "confidence", "evidence"])
        || !signal
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|kind| matches!(kind, "gpu_crash" | "out_of_memory"))
        || !signal
            .get("confidence")
            .and_then(Value::as_str)
            .is_some_and(valid_confidence)
        || !signal.get("evidence").is_some_and(string_array)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_log(value: &Value) -> Result<(), ProcessingResultError> {
    let log = value
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if log.len() != 2
        || !only_keys(log, &["name", "tail"])
        || log.get("name").and_then(Value::as_str).is_none()
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    let tail = log
        .get("tail")
        .and_then(Value::as_object)
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if tail.len() != 3
        || !only_keys(tail, &["text", "truncated", "invalid_utf8"])
        || tail.get("text").and_then(Value::as_str).is_none()
        || tail.get("truncated").and_then(Value::as_bool).is_none()
        || tail.get("invalid_utf8").and_then(Value::as_bool).is_none()
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_array(
    object: &serde_json::Map<String, Value>,
    field: &str,
    validator: fn(&Value) -> Result<(), ProcessingResultError>,
) -> Result<(), ProcessingResultError> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    for value in values {
        validator(value)?;
    }
    Ok(())
}

fn nullable_string(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

fn valid_crash_type(value: &str) -> bool {
    matches!(value, "crash" | "assert" | "ensure" | "unknown")
}

fn valid_confidence(value: &str) -> bool {
    matches!(value, "high" | "medium" | "low")
}

fn string_array(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|values| values.iter().all(Value::is_string))
}

/// Returns the required stable crash identity.
///
/// # Errors
///
/// Returns an error when the normalized crash context has no usable identity.
pub fn crash_guid(crash_context: &CrashContextData) -> Result<&str, ProcessingResultError> {
    crash_context
        .crash_guid
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or(ProcessingResultError::MissingCrashIdentity)
}

fn validate_attempt(attempt: &Value) -> Result<(), ProcessingResultError> {
    let attempt = attempt
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if attempt.len() != 3
        || !attempt.contains_key("parser_version")
        || !attempt.get("symbolication").is_some_and(Value::is_object)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    let processing_version = match attempt.get("processing_version").and_then(Value::as_u64) {
        Some(version) if (1..=u64::from(PROCESSING_VERSION)).contains(&version) => {
            u32::try_from(version).map_err(|_| ProcessingResultError::InvalidPrevious)?
        }
        Some(_) => return Err(ProcessingResultError::UnsupportedPreviousProcessing),
        None => return Err(ProcessingResultError::InvalidPrevious),
    };
    if !attempt.get("parser_version").is_some_and(Value::is_u64) {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    validate_symbolication(
        attempt
            .get("symbolication")
            .ok_or(ProcessingResultError::InvalidPrevious)?,
        processing_version,
    )?;
    Ok(())
}

fn validate_symbolication(
    symbolication: &Value,
    processing_version: u32,
) -> Result<(), ProcessingResultError> {
    let symbolication = symbolication
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    validate_symbolication_header(symbolication, processing_version)?;
    validate_modules(
        symbolication
            .get("modules")
            .and_then(Value::as_array)
            .ok_or(ProcessingResultError::InvalidPrevious)?,
    )?;
    validate_threads(
        symbolication
            .get("threads")
            .and_then(Value::as_array)
            .ok_or(ProcessingResultError::InvalidPrevious)?,
    )
}

fn validate_symbolication_header(
    symbolication: &serde_json::Map<String, Value>,
    processing_version: u32,
) -> Result<(), ProcessingResultError> {
    let mut fields = vec![
        "schema_version",
        "symbolicator_version",
        "minidump_version",
        "minidump_processor_version",
        "minidump_unwind_version",
        "platform",
        "architecture",
        "faulting_thread_id",
        "modules",
        "threads",
    ];
    let expected_schema = if processing_version == 1 {
        1
    } else {
        fields.extend(["exception_reason", "assertion"]);
        2
    };
    if symbolication.len() != fields.len()
        || !only_keys(symbolication, &fields)
        || symbolication.get("schema_version").and_then(Value::as_u64) != Some(expected_schema)
        || symbolication.get("platform").and_then(Value::as_str) != Some("windows")
        || symbolication.get("architecture").and_then(Value::as_str) != Some("x86_64")
        || !symbolication.get("modules").is_some_and(Value::is_array)
        || !symbolication.get("threads").is_some_and(Value::is_array)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    if processing_version == 2
        && ["exception_reason", "assertion"].iter().any(|field| {
            symbolication
                .get(*field)
                .is_none_or(|value| !nullable_string(value))
        })
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    for field in [
        "symbolicator_version",
        "minidump_version",
        "minidump_processor_version",
        "minidump_unwind_version",
    ] {
        if symbolication
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(ProcessingResultError::InvalidPrevious);
        }
    }
    let faulting_thread = symbolication
        .get("faulting_thread_id")
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if !faulting_thread.is_null() && !faulting_thread.is_u64() {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_modules(modules: &[Value]) -> Result<(), ProcessingResultError> {
    for module in modules {
        validate_module(module)?;
    }
    Ok(())
}

fn validate_module(module: &Value) -> Result<(), ProcessingResultError> {
    let module = module
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if !only_keys(
        module,
        &[
            "module",
            "base_address",
            "size",
            "code_id",
            "debug_id",
            "status",
            "pe",
            "pdb",
            "symcache_format",
        ],
    ) || !matches!(module.len(), 8 | 9)
        || module.get("module").and_then(Value::as_str).is_none()
        || module.get("base_address").and_then(Value::as_str).is_none()
        || module.get("size").and_then(Value::as_u64).is_none()
        || !module
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| {
                matches!(
                    status,
                    "matched" | "missing_pe" | "missing_pdb" | "mismatched" | "missing_identity"
                )
            })
        || ["code_id", "debug_id", "pe", "pdb"].iter().any(|field| {
            module
                .get(*field)
                .is_none_or(|value| !value.is_null() && !value.is_string())
        })
        || module
            .get("symcache_format")
            .is_some_and(|value| !value.is_u64())
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    Ok(())
}

fn validate_threads(threads: &[Value]) -> Result<(), ProcessingResultError> {
    for thread in threads {
        validate_thread(thread)?;
    }
    Ok(())
}

fn validate_thread(thread: &Value) -> Result<(), ProcessingResultError> {
    let thread = thread
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if thread.len() != 6
        || !only_keys(
            thread,
            &[
                "thread_id",
                "faulting",
                "name",
                "unwind_status",
                "frames_truncated",
                "frames",
            ],
        )
        || thread.get("thread_id").and_then(Value::as_u64).is_none()
        || thread.get("faulting").and_then(Value::as_bool).is_none()
        || thread
            .get("name")
            .is_none_or(|value| !value.is_null() && !value.is_string())
        || !thread
            .get("unwind_status")
            .and_then(Value::as_str)
            .is_some_and(|status| {
                matches!(
                    status,
                    "ok" | "missing_context"
                        | "missing_memory"
                        | "unsupported_cpu"
                        | "dump_thread_skipped"
                )
            })
        || thread
            .get("frames_truncated")
            .and_then(Value::as_bool)
            .is_none()
        || !thread.get("frames").is_some_and(Value::is_array)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    for frame in thread["frames"]
        .as_array()
        .ok_or(ProcessingResultError::InvalidPrevious)?
    {
        validate_frame(frame)?;
    }
    Ok(())
}

fn validate_frame(frame: &Value) -> Result<(), ProcessingResultError> {
    let frame = frame
        .as_object()
        .ok_or(ProcessingResultError::InvalidPrevious)?;
    if frame.len() != 9
        || !only_keys(
            frame,
            &[
                "instruction",
                "module",
                "module_relative",
                "trust",
                "symbol_status",
                "function",
                "source_file",
                "source_line",
                "inlines",
            ],
        )
        || frame.get("instruction").and_then(Value::as_str).is_none()
        || frame
            .get("trust")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !frame
            .get("symbol_status")
            .and_then(Value::as_str)
            .is_some_and(|status| {
                matches!(
                    status,
                    "resolved"
                        | "unresolved"
                        | "missing_pe"
                        | "missing_pdb"
                        | "mismatched"
                        | "missing_identity"
                        | "unknown_module"
                )
            })
        || ["module", "module_relative", "function", "source_file"]
            .iter()
            .any(|field| {
                frame
                    .get(*field)
                    .is_none_or(|value| !value.is_null() && !value.is_string())
            })
        || frame
            .get("source_line")
            .is_none_or(|value| !value.is_null() && !value.is_u64())
        || !frame.get("inlines").is_some_and(Value::is_array)
    {
        return Err(ProcessingResultError::InvalidPrevious);
    }
    for inline in frame["inlines"]
        .as_array()
        .ok_or(ProcessingResultError::InvalidPrevious)?
    {
        let inline = inline
            .as_object()
            .ok_or(ProcessingResultError::InvalidPrevious)?;
        if inline.len() != 3
            || !only_keys(inline, &["function", "source_file", "source_line"])
            || inline.get("function").and_then(Value::as_str).is_none()
            || inline
                .get("source_file")
                .is_none_or(|value| !value.is_null() && !value.is_string())
            || inline
                .get("source_line")
                .is_none_or(|value| !value.is_null() && !value.is_u64())
        {
            return Err(ProcessingResultError::InvalidPrevious);
        }
    }
    Ok(())
}

fn only_keys(object: &serde_json::Map<String, Value>, allowed: &[&str]) -> bool {
    object.keys().all(|key| allowed.contains(&key.as_str()))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        ProcessingResultError, validate_current_processing_result, validate_processing_result,
    };

    fn result() -> Value {
        json!({
            "schema_version": 1,
            "crash_guid": "UECC-Windows-Validation",
            "crash_context": {
                "parser_version": 1,
                "crash_guid": "UECC-Windows-Validation",
                "crash_type": "crash",
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
                    "faulting_thread_id": null,
                    "modules": [],
                    "threads": []
                }
            },
            "history": []
        })
    }

    #[test]
    fn validates_the_versioned_processor_contract() {
        let valid = result();
        assert_eq!(
            validate_processing_result(&valid, Some("UECC-Windows-Validation")),
            Ok(())
        );

        let mut unknown = valid.clone();
        unknown["unexpected"] = json!(true);
        assert_eq!(
            validate_processing_result(&unknown, None),
            Err(ProcessingResultError::InvalidPrevious)
        );

        let mut nested_unknown = valid.clone();
        nested_unknown["crash_context"]["unexpected"] = json!(true);
        assert_eq!(
            validate_processing_result(&nested_unknown, None),
            Err(ProcessingResultError::InvalidPrevious)
        );

        let mut wrong_nested_type = valid.clone();
        wrong_nested_type["crash_context"]["threads"] = json!([{"thread_id": 1}]);
        assert_eq!(
            validate_processing_result(&wrong_nested_type, None),
            Err(ProcessingResultError::InvalidPrevious)
        );

        let mut wrong_identity = valid;
        wrong_identity["crash_context"]["crash_guid"] = json!("UECC-Windows-Other");
        assert_eq!(
            validate_processing_result(&wrong_identity, None),
            Err(ProcessingResultError::PreviousIdentityMismatch)
        );
    }

    #[test]
    fn accepts_version_one_history_but_requires_version_two_for_new_results() {
        let historical = result();
        assert_eq!(validate_processing_result(&historical, None), Ok(()));
        assert_eq!(
            validate_current_processing_result(&historical, None),
            Err(ProcessingResultError::UnsupportedPreviousProcessing)
        );

        let mut current = historical;
        current["current"]["processing_version"] = json!(2);
        current["current"]["symbolication"]["schema_version"] = json!(2);
        current["current"]["symbolication"]["exception_reason"] =
            json!("EXCEPTION_ACCESS_VIOLATION_READ");
        current["current"]["symbolication"]["assertion"] = Value::Null;
        assert_eq!(validate_current_processing_result(&current, None), Ok(()));

        current["current"]["symbolication"]["schema_version"] = json!(1);
        assert_eq!(
            validate_processing_result(&current, None),
            Err(ProcessingResultError::InvalidPrevious)
        );
    }
}
