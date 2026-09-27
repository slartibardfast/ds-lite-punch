//! The daemon's own identity: the PEM files a TLS client presents, kept as DER until a TLS stack consumes them.

/// The DER a PEM file carries, or the reason it cannot be read.
pub fn der_from_pem(text: &str) -> Result<Vec<u8>, String> {
    let body: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return Err("the file carries no base64 between its PEM markers".to_string());
    }
    crate::dp::base64_decode(&body).ok_or_else(|| "the PEM body is not base64".to_string())
}

/// Reads a PEM file and returns its DER, naming the path in the reason when it cannot be read.
pub fn der_from_file(path: &str) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    der_from_pem(&text).map_err(|e| format!("{}: {}", path, e))
}

/// Loads both halves of the daemon's identity, so a bad file is a refusal at startup rather than a surprise at the first push.
pub fn load_identity(cert: &str, key: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let chain = der_from_file(cert)?;
    let key = der_from_file(key)?;
    Ok((chain, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pem_body_decodes_to_its_bytes() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAECAwQ=\n-----END CERTIFICATE-----\n";
        assert_eq!(der_from_pem(pem).unwrap(), vec![0u8, 1, 2, 3, 4]);
    }

    #[test]
    fn markers_and_spacing_do_not_reach_the_decoder() {
        let wrapped = "-----BEGIN CERTIFICATE-----\nAAEC\nAwQ=\n-----END CERTIFICATE-----\n";
        assert_eq!(der_from_pem(wrapped).unwrap(), vec![0u8, 1, 2, 3, 4]);
    }

    #[test]
    fn an_empty_or_unencoded_file_is_refused() {
        let markers_only = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
        assert!(der_from_pem(markers_only).is_err());
        assert!(der_from_pem("-----BEGIN CERTIFICATE-----\nnot base64!\n").is_err());
    }

    #[test]
    fn a_missing_file_names_itself_in_the_reason() {
        let e = der_from_file("/nonexistent/front-door/identity.pem").unwrap_err();
        assert!(e.contains("identity.pem"), "the reason names the path: {e}");
    }
}