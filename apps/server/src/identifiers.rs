pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::valid_uuid;

    #[test]
    fn accepts_postgres_uuid_text_shape() {
        assert!(valid_uuid("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"));
        assert!(valid_uuid("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"));
        assert!(!valid_uuid("../../outside"));
        assert!(!valid_uuid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }
}
