//! The control channel: one HTTPS push of the routing table to the front, sent whole again whenever it fails.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;

/// The table the daemon pushes: one line per held slot, its inner port, its protocol and the carrier's tuple for it.
pub fn table(entries: &[(u16, u8, String)]) -> String {
    let mut out = String::new();
    for (slot, proto, tuple) in entries {
        out.push_str(&format!("{} {} {}\n", slot, proto, tuple));
    }
    out
}

/// Splits `host:port`, which is the only form an endpoint takes here.
fn split_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let (host, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| format!("{}: expects host:port", endpoint))?;
    let port: u16 = port
        .parse()
        .map_err(|e| format!("{}: {}", endpoint, e))?;
    if host.is_empty() {
        return Err(format!("{}: no host", endpoint));
    }
    Ok((host.to_string(), port))
}

/// Sends the body to the endpoint over TLS, verifying the peer against the configured anchor, and returns the response's first line.
pub fn push(
    endpoint: &str,
    name: &str,
    path: &str,
    body: &str,
    config: &rustls::ClientConfig,
) -> Result<String, String> {
    let (host, port) = split_endpoint(endpoint)?;
    let sock = std::net::TcpStream::connect((host.as_str(), port))
        .map_err(|e| format!("{}: {}", endpoint, e))?;
    let server_name: ServerName<'static> = ServerName::try_from(name.to_string())
        .map_err(|e| format!("{}: {}", name, e))?;
    let conn = rustls::ClientConnection::new(Arc::new(config.clone()), server_name)
        .map_err(|e| format!("{}: {}", endpoint, e))?;
    let mut stream = rustls::StreamOwned::new(conn, sock);
    let request = format!(
        "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Length: {}\r\n\r\n{}",
        path,
        name,
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("{}: {}", endpoint, e))?;
    let mut response = String::new();
    let mut buf = [0u8; 512];
    while !response.contains('\n') {
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("{}: {}", endpoint, e))?;
        if n == 0 {
            break;
        }
        response.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    Ok(response.lines().next().unwrap_or_default().to_string())
}

/// Pushes the table whole, and on any failure sends the whole table again, so a reconnect repairs what was missed.
pub fn push_whole(
    endpoint: &str,
    name: &str,
    path: &str,
    body: &str,
    config: &rustls::ClientConfig,
    attempts: u32,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..attempts.max(1) {
        match push(endpoint, name, path, body, config) {
            Ok(line) if line.contains("200") || line.contains("204") => return Ok(line),
            Ok(line) => last = format!("{}: {}", endpoint, line),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_lines_are_stable() {
        let t = table(&[(40000, 17, "37.228.213.83:59348".to_string())]);
        assert_eq!(t, "40000 17 37.228.213.83:59348\n");
    }

    #[test]
    fn the_table_render_is_one_line_per_slot() {
        table_lines_are_stable();
        let t = table(&[
            (40000, 17, "a:1".to_string()),
            (40001, 6, "a:2".to_string()),
        ]);
        assert_eq!(t.lines().count(), 2);
    }

    #[test]
    fn an_endpoint_without_a_port_or_a_host_is_refused() {
        assert!(split_endpoint("example.com").is_err());
        assert!(split_endpoint(":443").is_err());
        assert_eq!(split_endpoint("example.com:443").unwrap(), ("example.com".to_string(), 443));
    }

    fn fixtures() -> std::path::PathBuf {
        // One build per process: two tests running in parallel rewrote this one directory, and a reader then verified a certificate signed by the other run's authority, which rustls reports as BadSignature.
        static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        DIR.get_or_init(fixtures_once).clone()
    }

    fn fixtures_once() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dslp-front-{}", std::process::id()));
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
              "-subj", "/CN=the front", "-keyout", "ca.key", "-out", "ca.crt"]);
        run(&["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
              "-keyout", "server.key", "-out", "server.csr"]);
        std::fs::write(dir.join("server.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
            .expect("the server's extensions");
        run(&["x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
              "-CAcreateserial", "-days", "1", "-extfile", "server.ext", "-out", "server.crt"]);
        run(&["req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=the daemon",
              "-keyout", "daemon.key", "-out", "daemon.csr"]);
        std::fs::write(dir.join("daemon.ext"),
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n")
            .expect("the daemon's extensions");
        run(&["x509", "-req", "-in", "daemon.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
              "-CAcreateserial", "-days", "1", "-extfile", "daemon.ext", "-out", "daemon.crt"]);
        dir
    }

    fn path_in(dir: &std::path::Path, name: &str) -> String {
        dir.join(name).to_string_lossy().into_owned()
    }

    fn server_config(dir: &std::path::Path) -> Arc<rustls::ServerConfig> {
        let chain = crate::identity::der_from_file(&path_in(dir, "server.crt")).expect("the chain");
        let key = crate::identity::der_from_file(&path_in(dir, "server.key")).expect("the key");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(chain)],
                rustls::pki_types::PrivateKeyDer::try_from(key).expect("a key"),
            )
            .expect("the server's identity");
        Arc::new(config)
    }

    fn answer_one(listener: &std::net::TcpListener, config: Arc<rustls::ServerConfig>, reply: Option<&str>) -> String {
        let (sock, _) = listener.accept().expect("a connection");
        let conn = rustls::ServerConnection::new(config).expect("a session");
        let mut stream = rustls::StreamOwned::new(conn, sock);
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap_or(0);
        if let Some(reply) = reply {
            let _ = stream.write_all(reply.as_bytes());
        }
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[test]
    fn the_push_reaches_a_server_the_anchor_signed() {
        let dir = fixtures();
        let config = server_config(&dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let endpoint = format!("127.0.0.1:{}", listener.local_addr().expect("an address").port());
        let handle = std::thread::spawn(move || answer_one(&listener, config, Some("HTTP/1.0 204 No Content\r\n\r\n")));
        let client = crate::identity::client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &path_in(&dir, "ca.crt"),
        )
        .expect("the client's configuration");
        let out = push(&endpoint, "localhost", "/table", "40000 17 a:1\n", &client);
        assert!(out.expect("the push answers").contains("204"));
        let request = handle.join().expect("the server thread");
        assert!(request.contains("40000 17 a:1"), "the body arrives whole: {request}");
    }

    #[test]
    fn a_failed_push_sends_the_whole_table_again() {
        let dir = fixtures();
        let config = server_config(&dir);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let endpoint = format!("127.0.0.1:{}", listener.local_addr().expect("an address").port());
        let second = config.clone();
        let handle = std::thread::spawn(move || {
            let first = answer_one(&listener, config, None);
            let again = answer_one(&listener, second, Some("HTTP/1.0 204 No Content\r\n\r\n"));
            (first, again)
        });
        let client = crate::identity::client_config(
            &path_in(&dir, "daemon.crt"),
            &path_in(&dir, "daemon.key"),
            &path_in(&dir, "ca.crt"),
        )
        .expect("the client's configuration");
        let body = table(&[(40000, 17, "a:1".to_string())]);
        let out = push_whole(&endpoint, "localhost", "/table", &body, &client, 3);
        assert!(out.expect("the retry answers").contains("204"));
        let (first, again) = handle.join().expect("the server thread");
        assert_eq!(first, again, "the second attempt carries the whole table, not a delta");
    }
}