use serde::{Deserialize, Serialize};

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
    use super::ProcessingState;

    #[test]
    fn processing_state_uses_api_representation() {
        let value = serde_json::to_string(&ProcessingState::AwaitingSymbols)
            .unwrap_or_else(|error| panic!("state must serialize: {error}"));

        assert_eq!(value, "\"awaiting_symbols\"");
    }
}
