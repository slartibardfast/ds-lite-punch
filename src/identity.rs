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

/// Builds the TLS client configuration the daemon calls the front with: the identity it presents, and the authority it accepts.
pub fn client_config(cert: &str, key: &str, anchor: &str) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    let anchor_der = der_from_file(anchor)?;
    roots
        .add(rustls::pki_types::CertificateDer::from(anchor_der))
        .map_err(|e| format!("{}: {e}", anchor))?;
    let chain = read_chain(cert)?;
    let key = read_key(key)?;
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("the TLS versions: {e}"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|e| format!("the identity: {e}"))
}

fn read_chain(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(file);
    let chain: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate between the PEM markers", path));
    }
    Ok(chain)
}

fn read_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {}", path, e))?;
    let mut reader = std::io::BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader).map_err(|e| format!("{}: {e}", path))?;
    key.ok_or_else(|| format!("{}: no private key between the PEM markers", path))
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

    fn fixtures() -> std::path::PathBuf {
        // One build per process: four tests running in parallel rewrote this one directory, and a reader then verified a certificate signed by the other run's authority, which rustls reports as BadSignature.
        static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        DIR.get_or_init(fixtures_once).clone()
    }

    fn fixtures_once() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dslp-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let run = |args: &[&str]| {
            let ok = std::process::Command::new("openssl")
                .args(args)
                .current_dir(&dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("openssl runs")
                .success();
            assert!(ok, "openssl {args:?}");
        };
        run(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
              "-subj", "/CN=the front", "-keyout", "front.key", "-out", "front.crt"]);
        run(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
              "-subj", "/CN=another authority", "-keyout", "other.key", "-out", "other.crt"]);
        run(&["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=the daemon",
              "-keyout", "daemon.key", "-out", "daemon.csr"]);
        std::fs::write(
            dir.join("daemon.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n",
        )
        .expect("the extension file");
        run(&["x509", "-req", "-in", "daemon.csr", "-CA", "front.crt", "-CAkey", "front.key",
              "-CAcreateserial", "-days", "1", "-extfile", "daemon.ext", "-out", "daemon.crt"]);
        run(&["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
              "-keyout", "server.key", "-out", "server.csr"]);
        std::fs::write(
            dir.join("server.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
        )
        .expect("the extension file");
        run(&["x509", "-req", "-in", "server.csr", "-CA", "front.crt", "-CAkey", "front.key",
              "-CAcreateserial", "-days", "1", "-extfile", "server.ext", "-out", "server.crt"]);
        dir
    }

    fn path_in(dir: &std::path::Path, name: &str) -> String {
        dir.join(name).to_string_lossy().into_owned()
    }

    #[test]
    fn the_client_carries_the_identity_and_accepts_the_anchor() {
        let dir = fixtures();
        let built = client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &path_in(&dir, "front.crt"),
        );
        assert!(built.is_ok(), "an identity and its anchor build: {:?}", built.err());
    }

    #[test]
    fn a_key_that_does_not_match_its_certificate_is_refused() {
        let dir = fixtures();
        let built = client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "other.key"),
            &path_in(&dir, "front.crt"),
        );
        let e = built.err().expect("a mismatched key is refused");
        assert!(e.starts_with("the identity:"), "the refusal names the pairing: {e}");
    }

    #[test]
    fn the_client_trusts_a_server_the_anchor_signed_and_refuses_another() {
        use std::io::{Read, Write};
        let dir = fixtures();
        let chain = read_chain(&path_in(&dir, "server.crt")).expect("the server's chain");
        let key = read_key(&path_in(&dir, "server.key")).expect("the server's key");
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the protocol versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("the server's identity");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let addr = listener.local_addr().expect("its address");
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let Ok((sock, _)) = listener.accept() else {
                    return;
                };
                let conn =
                    rustls::ServerConnection::new(std::sync::Arc::new(server.clone())).expect("a session");
                let mut stream = rustls::StreamOwned::new(conn, sock);
                let mut buf = [0u8; 1];
                if stream.read(&mut buf).is_ok() {
                    let _ = stream.write_all(b"ok");
                }
            }
        });
        let name = || rustls::pki_types::ServerName::try_from("localhost").expect("a name");

        let config = client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &path_in(&dir, "front.crt"),
        )
        .expect("the client's configuration");
        let conn =
            rustls::ClientConnection::new(std::sync::Arc::new(config), name()).expect("a session");
        let sock = std::net::TcpStream::connect(addr).expect("a connection");
        let mut stream = rustls::StreamOwned::new(conn, sock);
        stream
            .write_all(b"hello")
            .expect("the client reaches a server the anchor signed");
        let mut back = [0u8; 2];
        let _ = stream.read(&mut back);

        let stranger = client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &path_in(&dir, "other.crt"),
        )
        .expect("a configuration over an unrelated anchor");
        let conn =
            rustls::ClientConnection::new(std::sync::Arc::new(stranger), name()).expect("a session");
        let sock = std::net::TcpStream::connect(addr).expect("a second connection");
        let mut stream = rustls::StreamOwned::new(conn, sock);
        assert!(
            stream.write_all(b"hello").is_err(),
            "a server the anchor did not sign is refused"
        );
        handle.join().expect("the server thread");
    }

    #[test]
    fn an_anchor_that_is_not_a_certificate_is_refused() {
        let dir = fixtures();
        let not_a_cert = dir.join("not-a-cert.pem");
        std::fs::write(&not_a_cert, "-----BEGIN CERTIFICATE-----\nAAECAwQ=\n-----END CERTIFICATE-----\n")
            .expect("the scratch file");
        let built = client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &not_a_cert.to_string_lossy(),
        );
        assert!(built.is_err(), "an anchor that is not a certificate is refused");
    }
}