// Very simple payload sanitizer to prevent terminal escape sequence injections
// Removes all non-printable ASCII characters

pub fn sanitize_payload(payload: &[u8]) -> String {
    payload
        .iter()
        .take(128) // Only take first 128 bytes to prevent excessive processing on large payloads
        .filter(|&&b| b >= 32 && b <= 126) // Printable ASCII range
        .map(|&b| b as char)
        .collect()
}
