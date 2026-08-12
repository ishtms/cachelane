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
    use super::{CrashType, ProcessingState};

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
}
