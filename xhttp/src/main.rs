use std::convert::Infallible;
use std::io::ErrorKind;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::xproto::XProto;

mod xproto;

const HTTP_PORT: u16 = 8888;
const WEB_SERVER_PATH: &'static str = "/srv/tasks/xhttp";

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(run_server())
}

async fn run_server() -> anyhow::Result<()> {
    let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], HTTP_PORT))).await?;
    while let Ok((client, addr)) = listener.accept().await {
        println!("Got incoming connection from {addr}");
        let io = TokioIo::new(XProto::new(client));
        tokio::spawn(async move {
            match http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, service_fn(serve_website))
                .await
            {
                Ok(_) => {
                    println!("Connection with {addr} ended successfully");
                }
                Err(e) => {
                    println!("Connection with {addr} ended with error: {e}");
                }
            }
        });
    }
    Ok(())
}

async fn serve_website(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = match req.uri().path() {
        "/" => "/index.html",
        path => path,
    };
    let path = std::path::Path::new(path).
    if let Err(e) = path {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let path = path.unwrap();
    let path = std::path::Path::new(WEB_SERVER_PATH).join(&path.to_string_lossy()[1..]);
    println!("Getting path: {path:?}");
    let stream = File::open(&path).await;
    if let Err(e) = stream {
        return error_response(match e.kind() {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }, e.to_string());
    }
    let mut stream = stream.unwrap();
    let content_type = match path.extension().map(|x| x.to_str()) {
        Some(Some("html")) | Some(Some("htm")) => "text/html",
        Some(Some("css")) => "text/css",
        Some(Some("js")) => "text/javascript",
        Some(Some("txt")) => "text/plain",
        _ => "application/octet-stream"
    };
    let mut data = Vec::with_capacity(4096); // 4k buf is fine for start
    if let Err(e) = stream.read_to_end(&mut data).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let rb = Response::builder().header("content-type", content_type).body(Full::from(Bytes::from(data)));
    if let Err(e) = rb {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    Ok(rb.unwrap())
}

#[inline]
fn error_response(code: StatusCode, error: String) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut r = Response::new(Full::from(Bytes::from(error)));
    *r.status_mut() = code;
    Ok(r)
}