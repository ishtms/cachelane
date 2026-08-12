use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashType {
    Crash,
    Assert,
    Ensure,
    Unknown,
}

impl CrashType {
    #[must_use]
    pub fn classify(error_type: &str) -> Self {
        match error_type {
            "Crash" => Self::Crash,
            "Assert" => Self::Assert,
            "Ensure" => Self::Ensure,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NormalizedValue {
    pub original: String,
    pub normalized: String,
}

impl NormalizedValue {
    #[must_use]
    pub fn path(value: &str) -> Self {
        Self {
            original: value.to_owned(),
            normalized: value.replace('\\', "/"),
        }
    }

    #[must_use]
    pub fn module(value: &str) -> Self {
        let file_name = value
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(value)
            .to_ascii_lowercase();
        let normalized = file_name
            .strip_suffix(".dll")
            .or_else(|| file_name.strip_suffix(".exe"))
            .unwrap_or(&file_name)
            .to_owned();

        Self {
            original: value.to_owned(),
            normalized,
        }
    }

    #[must_use]
    pub fn function(value: &str) -> Self {
        Self {
            original: value.to_owned(),
            normalized: value.trim().to_owned(),
        }
    }

    #[must_use]
    pub fn platform(value: &str) -> Self {
        let identifier = value.trim().to_ascii_lowercase();
        let normalized = match identifier.as_str() {
            "win64" | "windows" | "windowsnoeditor" => "windows".to_owned(),
            _ => identifier,
        };

        Self {
            original: value.to_owned(),
            normalized,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingState {
    Received,
    Stored,
    Parsed,
    AwaitingSymbols,
    Symbolicating,
    Processed,
    Failed,
    Quarantined,
}

#[cfg(test)]
mod tests {
    use super::{CrashType, NormalizedValue, ProcessingState};

    #[test]
    fn crash_type_classifies_structured_values() {
        assert_eq!(CrashType::classify("Crash"), CrashType::Crash);
        assert_eq!(CrashType::classify("Assert"), CrashType::Assert);
        assert_eq!(CrashType::classify("Ensure"), CrashType::Ensure);
    }

    #[test]
    fn crash_type_treats_other_values_as_unknown() {
        for value in ["", "crash", "OOM", " Crash "] {
            assert_eq!(CrashType::classify(value), CrashType::Unknown);
        }
    }

    #[test]
    fn crash_type_uses_api_representation() {
        for (crash_type, expected) in [
            (CrashType::Crash, "\"crash\""),
            (CrashType::Assert, "\"assert\""),
            (CrashType::Ensure, "\"ensure\""),
            (CrashType::Unknown, "\"unknown\""),
        ] {
            let value = serde_json::to_string(&crash_type)
                .unwrap_or_else(|error| panic!("crash type must serialize: {error}"));

            assert_eq!(value, expected);
        }
    }

    #[test]
    fn processing_state_uses_api_representation() {
        let value = serde_json::to_string(&ProcessingState::AwaitingSymbols)
            .unwrap_or_else(|error| panic!("state must serialize: {error}"));

        assert_eq!(value, "\"awaiting_symbols\"");
    }

    #[test]
    fn path_normalization_preserves_the_source() {
        let value = NormalizedValue::path(r"C:\Game\\Content\..\Maps\Arena.umap");

        assert_eq!(value.original, r"C:\Game\\Content\..\Maps\Arena.umap");
        assert_eq!(value.normalized, "C:/Game//Content/../Maps/Arena.umap");
    }

    #[test]
    fn module_normalization_uses_the_file_stem() {
        for (original, expected) in [
            (r"C:\Game/Binaries\Win64\PROJECT.DLL", "project"),
            ("/opt/game/Runner.ExE", "runner"),
            ("Core", "core"),
            ("", ""),
        ] {
            let value = NormalizedValue::module(original);

            assert_eq!(value.original, original);
            assert_eq!(value.normalized, expected);
        }
    }

    #[test]
    fn function_normalization_only_trims_surrounding_whitespace() {
        let value = NormalizedValue::function("  FÜber::Run(int value)\n");

        assert_eq!(value.original, "  FÜber::Run(int value)\n");
        assert_eq!(value.normalized, "FÜber::Run(int value)");
    }

    #[test]
    fn platform_normalization_canonicalizes_windows_names() {
        for original in ["Win64", "WINDOWS", " windowsNoEditor "] {
            let value = NormalizedValue::platform(original);

            assert_eq!(value.original, original);
            assert_eq!(value.normalized, "windows");
        }
    }

    #[test]
    fn platform_normalization_handles_unknown_and_empty_names() {
        for (original, expected) in [(" LINUX-ARM64 ", "linux-arm64"), ("", "")] {
            let value = NormalizedValue::platform(original);

            assert_eq!(value.original, original);
            assert_eq!(value.normalized, expected);
        }
    }

    #[test]
    fn normalized_value_uses_stable_json_fields() {
        let value = NormalizedValue::platform("Win64");
        let json = serde_json::to_string(&value)
            .unwrap_or_else(|error| panic!("normalized value must serialize: {error}"));

        assert_eq!(json, r#"{"original":"Win64","normalized":"windows"}"#);
    }
}
