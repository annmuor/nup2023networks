use std::convert::Infallible;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use http_body_util::Full;
use hyper::body::{Body, Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::xproto::XProto;

mod xproto;

const HTTP_PORT: u16 = 8888;
const WEB_SERVER_PATH: &str = "/srv/tasks/xhttp";

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
                .serve_connection(io, service_fn(serve_and_log_req))
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
    let path = std::path::Path::new(WEB_SERVER_PATH).join(normalize_path(path));
    let stream = File::open(&path).await;
    if let Err(e) = stream {
        return error_response(
            match e.kind() {
                ErrorKind::NotFound => StatusCode::NOT_FOUND,
                ErrorKind::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            e.to_string(),
        );
    }
    let mut stream = stream.unwrap();
    let content_type = match path.extension().map(|x| x.to_str()) {
        Some(Some("html")) | Some(Some("htm")) => "text/html",
        Some(Some("css")) => "text/css",
        Some(Some("js")) => "text/javascript",
        Some(Some("txt")) => "text/plain",
        _ => "application/octet-stream",
    };
    let mut data = Vec::with_capacity(4096); // 4k buf is fine for start
    if let Err(e) = stream.read_to_end(&mut data).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let rb = Response::builder()
        .header("content-type", content_type)
        .body(Full::from(Bytes::from(data)));
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

#[inline]
fn normalize_path(path: &str) -> String {
    path.split('/')
        .filter(|part| (part.ne(&"..") && part.ne(&".") && !part.is_empty()))
        .collect::<Vec<&str>>()
        .join("/")
}

#[inline]
async fn serve_and_log_req(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let head = format!(
        "{} {}",
        req.method().as_str(),
        req.uri()
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or_else(|| req.uri().path())
    );
    let result = serve_website(req).await.unwrap();
    let tail = format!(
        "{} {}b",
        result.status().as_u16(),
        result.body().size_hint().lower()
    );
    println!(
        "[{:}] -- {head} -- {tail}",
        SystemTime::now()
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs()
    );
    Ok(result)
}
