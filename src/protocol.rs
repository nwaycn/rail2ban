//! Client/server wire protocol.
//!
//! rail2ban uses a line-delimited JSON protocol over a Unix socket. Each
//! request is a single JSON object terminated by `\n`; each response is a
//! single JSON object terminated by `\n`.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;

/// Default socket path.
pub const DEFAULT_SOCKET: &str = "/var/run/rail2ban/rail2ban.sock";

/// Default connection timeout (seconds).
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A request from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Command arguments, e.g. `["status", "sshd"]`.
    pub args: Vec<String>,
}

impl Request {
    /// Build a new request from an iterator of arguments.
    pub fn new<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            args: args.into_iter().map(|s| s.into()).collect(),
        }
    }
}

/// A response from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Whether the command succeeded.
    pub ok: bool,
    /// Optional message (error message when `!ok`, informational text otherwise).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The data payload, when the command returns structured data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl Response {
    /// Build a successful response with text.
    pub fn ok<S: Into<String>>(msg: S) -> Self {
        Self {
            ok: true,
            message: Some(msg.into()),
            data: None,
        }
    }

    /// Build a successful response with structured data.
    pub fn ok_data(value: serde_json::Value) -> Self {
        Self {
            ok: true,
            message: None,
            data: Some(value),
        }
    }

    /// Build a failure response.
    pub fn err<S: Into<String>>(msg: S) -> Self {
        Self {
            ok: false,
            message: Some(msg.into()),
            data: None,
        }
    }
}

/// A client connection to a running `rail2ban-server`.
#[cfg(unix)]
pub struct Client {
    stream: StdUnixStream,
}

#[cfg(unix)]
impl Client {
    /// Connect to the given socket path.
    pub fn connect(path: &str) -> Result<Self> {
        let stream = StdUnixStream::connect(path).map_err(|e| {
            Error::Protocol(format!(
                "unable to connect to server socket {path}: {e}.\n\
                 Is rail2ban-server running?"
            ))
        })?;
        Ok(Self { stream })
    }

    /// Send a request and read a single response.
    pub fn request(&mut self, req: &Request) -> Result<Response> {
        let json = serde_json::to_string(req)?;
        writeln!(self.stream, "{json}")?;
        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.is_empty() {
            return Err(Error::Protocol(
                "server closed connection without response".into(),
            ));
        }
        let resp: Response = serde_json::from_str(line.trim())?;
        Ok(resp)
    }
}

/// Send a single request to a Unix socket server, with a timeout.
#[cfg(unix)]
pub fn send_request(socket: &str, req: &Request, timeout: Duration) -> Result<Response> {
    let stream = StdUnixStream::connect(socket)
        .map_err(|e| Error::Protocol(format!("connect {socket}: {e}")))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut client = Client { stream };
    client.request(req)
}

/// Send a request to the server. On non-Unix platforms this always returns
/// an error because Unix sockets are unavailable.
#[cfg(not(unix))]
pub fn send_request(_socket: &str, _req: &Request, _timeout: Duration) -> Result<Response> {
    Err(Error::Protocol(
        "Unix sockets are not available on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request() {
        let r = Request::new(["status", "sshd"]);
        let s = serde_json::to_string(&r).unwrap();
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.args, vec!["status".to_string(), "sshd".to_string()]);
    }

    #[test]
    fn roundtrip_response_ok() {
        let r = Response::ok("pong");
        let s = serde_json::to_string(&r).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(back.ok);
        assert_eq!(back.message.as_deref(), Some("pong"));
    }

    #[test]
    fn roundtrip_response_err() {
        let r = Response::err("no such jail");
        let s = serde_json::to_string(&r).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert!(!back.ok);
        assert_eq!(back.message.as_deref(), Some("no such jail"));
    }
}
