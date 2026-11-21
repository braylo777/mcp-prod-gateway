//! Minimal HTTP/1.1 binding (port of `mcpgw/http.py`): a strict request parser, a response
//! writer, a blocking server thread and a tiny client for tests. std only.
//!
//! The gateway is single-threaded (`Rc`), so the server builds it *inside* its thread from a
//! `Send` factory and handles one connection at a time. `Connection: close` on every response.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};

use crate::gateway::{Gateway, Headers};

pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_BODY: usize = 1024 * 1024;
pub const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// Header names keep their original case; duplicates keep the first value.
    pub headers: Headers,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Need more bytes.
    Incomplete,
    HeadTooLarge,
    BodyTooLarge,
    BadRequestLine,
    BadHeader,
    BadContentLength,
    /// `Transfer-Encoding` (chunked) is not supported; 501.
    Unsupported,
    BadStatusLine,
}

impl ParseError {
    pub fn status(&self) -> u16 {
        match self {
            ParseError::HeadTooLarge => 431,
            ParseError::BodyTooLarge => 413,
            ParseError::Unsupported => 501,
            _ => 400,
        }
    }
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_headers(lines: &[&str]) -> Result<(Headers, Option<usize>), ParseError> {
    let mut headers = Headers::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(ParseError::BadHeader); // obs-fold
        }
        let (name, value) = line.split_once(':').ok_or(ParseError::BadHeader)?;
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(ParseError::BadHeader);
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|b| b < 0x20 && b != b'\t' || b == 0x7f) {
            return Err(ParseError::BadHeader);
        }
        let lname = name.to_ascii_lowercase();
        if lname == "transfer-encoding" {
            return Err(ParseError::Unsupported);
        }
        if lname == "content-length" {
            if value.is_empty() || value.len() > 10 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseError::BadContentLength);
            }
            let n: usize = value.parse().map_err(|_| ParseError::BadContentLength)?;
            if content_length.is_some_and(|c| c != n) {
                return Err(ParseError::BadContentLength);
            }
            content_length = Some(n);
        }
        if !headers.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            headers.insert(name.to_string(), value.to_string());
        }
    }
    Ok((headers, content_length))
}

/// Parse one request from the front of `buf`. Returns the request and the bytes consumed.
pub fn parse_request(buf: &[u8]) -> Result<(Request, usize), ParseError> {
    let Some(end) = find_head_end(&buf[..buf.len().min(MAX_HEAD + 4)]) else {
        return Err(if buf.len() > MAX_HEAD {
            ParseError::HeadTooLarge
        } else {
            ParseError::Incomplete
        });
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| ParseError::BadRequestLine)?;
    if !head.is_ascii() {
        return Err(ParseError::BadRequestLine);
    }
    let mut lines = head.split("\r\n");
    let rl = lines.next().ok_or(ParseError::BadRequestLine)?;
    let parts: Vec<&str> = rl.split(' ').collect();
    if parts.len() != 3 {
        return Err(ParseError::BadRequestLine);
    }
    let (method, path, version) = (parts[0], parts[1], parts[2]);
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(ParseError::BadRequestLine);
    }
    if !path.starts_with('/') || path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(ParseError::BadRequestLine);
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(ParseError::BadRequestLine);
    }
    let rest: Vec<&str> = lines.collect();
    let (headers, cl) = parse_headers(&rest)?;
    let n = cl.unwrap_or(0);
    if n > MAX_BODY {
        return Err(ParseError::BodyTooLarge);
    }
    let start = end + 4;
    if buf.len() < start + n {
        return Err(ParseError::Incomplete);
    }
    let req = Request {
        method: method.into(),
        path: path.into(),
        headers,
        body: buf[start..start + n].to_vec(),
    };
    Ok((req, start + n))
}

/// Parse a response produced by [`write_response`] (used by the test client).
pub fn parse_response(buf: &[u8]) -> Result<(u16, Headers, Vec<u8>), ParseError> {
    let end = find_head_end(buf).ok_or(ParseError::Incomplete)?;
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| ParseError::BadStatusLine)?;
    let mut lines = head.split("\r\n");
    let sl = lines.next().ok_or(ParseError::BadStatusLine)?;
    let mut it = sl.splitn(3, ' ');
    let (v, code) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
    if !v.starts_with("HTTP/1.") || code.len() != 3 {
        return Err(ParseError::BadStatusLine);
    }
    let status: u16 = code.parse().map_err(|_| ParseError::BadStatusLine)?;
    let rest: Vec<&str> = lines.collect();
    let (headers, cl) = parse_headers(&rest)?;
    let start = end + 4;
    let n = cl.unwrap_or(buf.len() - start);
    if buf.len() < start + n {
        return Err(ParseError::Incomplete);
    }
    Ok((status, headers, buf[start..start + n].to_vec()))
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        _ => "Unknown",
    }
}

pub fn write_response(status: u16, headers: &Headers, body: &Value) -> Vec<u8> {
    let data = serde_json::to_vec(body).unwrap();
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\n",
        reason(status)
    );
    for (k, v) in headers {
        // header injection guard: never emit CR/LF from gateway-supplied values
        if k.bytes().all(is_tchar) && !v.contains(['\r', '\n']) {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        data.len()
    ));
    let mut bytes = out.into_bytes();
    bytes.extend(data);
    bytes
}

fn parse_error_body() -> Value {
    json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "parse error"}})
}

/// Route one parsed request to the gateway.
pub fn route(gw: &mut Gateway, req: &Request) -> (u16, Headers, Value) {
    match req.method.as_str() {
        "GET" if req.path == WELL_KNOWN => (200, Headers::new(), gw.well_known()),
        "GET" => (404, Headers::new(), json!({"error": "not found"})),
        "POST" => match serde_json::from_slice::<Value>(&req.body) {
            Ok(body) => gw.handle_http(&req.headers, &body),
            Err(_) => (400, Headers::new(), parse_error_body()),
        },
        _ => (405, Headers::new(), json!({"error": "method not allowed"})),
    }
}

fn handle_conn(gw: &mut Gateway, mut s: TcpStream) -> io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let resp = loop {
        match parse_request(&buf) {
            Ok((req, _)) => {
                let (st, h, b) = route(gw, &req);
                break write_response(st, &h, &b);
            }
            Err(ParseError::Incomplete) => {
                let n = s.read(&mut chunk)?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(e) => {
                let body = if e == ParseError::BadContentLength {
                    parse_error_body()
                } else {
                    json!({"error": format!("{e:?}")})
                };
                break write_response(e.status(), &Headers::new(), &body);
            }
        }
    };
    s.write_all(&resp)?;
    s.flush()
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ServerHandle {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub fn shutdown(mut self) {
        self.stop_inner();
    }
    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr); // unblock accept()
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Bind `addr` (use port 0 for a free port) and serve the gateway built by `make`.
pub fn serve<F>(addr: &str, make: F) -> io::Result<ServerHandle>
where
    F: FnOnce() -> Gateway + Send + 'static,
{
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut gw = make();
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            if let Ok(s) = conn {
                let _ = handle_conn(&mut gw, s);
            }
        }
    });
    Ok(ServerHandle {
        addr: local,
        stop,
        thread: Some(thread),
    })
}

/// Blocking one-shot client: send a request, read the whole response.
pub fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> io::Result<(u16, Headers, Vec<u8>)> {
    let mut s = TcpStream::connect(addr)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let body = body.unwrap_or(b"");
    let mut out = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    s.write_all(out.as_bytes())?;
    s.write_all(body)?;
    let mut buf = vec![];
    s.read_to_end(&mut buf)?;
    parse_response(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
}

/// Client helper: POST JSON, decode JSON.
pub fn post_json(
    addr: SocketAddr,
    headers: &[(&str, &str)],
    body: &Value,
) -> io::Result<(u16, Headers, Value)> {
    let mut h = vec![("Content-Type", "application/json")];
    h.extend_from_slice(headers);
    let (st, hd, b) = request(
        addr,
        "POST",
        "/",
        &h,
        Some(&serde_json::to_vec(body).unwrap()),
    )?;
    let v = serde_json::from_slice(&b).unwrap_or(Value::Null);
    Ok((st, hd, v))
}
