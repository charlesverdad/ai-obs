//! Minimal loopback HTTP/1.1 client — avoids a heavyweight HTTP dependency
//! for what is only ever "POST small JSON to 127.0.0.1".

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub fn post_json(port: u16, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    request(port, "POST", path, Some(body))
}

pub fn get_json(port: u16, path: &str) -> Result<serde_json::Value> {
    request(port, "GET", path, None)
}

fn request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(800))
        .with_context(|| format!("daemon not reachable on {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_millis(2500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(2500)))?;

    let payload = body.map(|b| b.to_string()).unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        bail!("malformed HTTP response");
    };
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        bail!("daemon returned HTTP {status}");
    }
    // Chunked responses: axum uses content-length for small JSON, but be
    // permissive — find the first { or [ and parse from there.
    let start = body.find(['{', '[']).unwrap_or(0);
    // Strip possible chunked-encoding trailer by parsing leniently.
    let mut de = serde_json::Deserializer::from_str(&body[start..]);
    let v = serde_json::Value::deserialize(&mut de)?;
    Ok(v)
}
