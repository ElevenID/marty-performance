//! Disposable local gateway contract used to verify the k6 runner.

use std::{
    env,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
};

fn main() -> std::io::Result<()> {
    let address = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:28080".to_owned());
    let listener = TcpListener::bind(&address)?;
    println!("mock gateway listening on {address}");
    for connection in listener.incoming() {
        respond(connection?)?;
    }
    Ok(())
}

fn respond(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = [0_u8; 2048];
    let length = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..length]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let (status, body) = match path {
        "/health" => ("200 OK", r#"{"status":"healthy","service":"api-gateway"}"#),
        "/ready" => (
            "200 OK",
            r#"{"status":"ready","service":"api-gateway","services":{}}"#,
        ),
        _ => ("404 Not Found", r#"{"detail":"Not found"}"#),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}
