mod flag;

use {
    http_body_util::{BodyExt, Full},
    hyper::{
        body::Bytes, server::conn::http1::Builder, service::service_fn, Method, Request, Response,
    },
    hyper_util::rt::TokioIo,
    rand::random,
    std::{convert::Infallible, net::IpAddr, process::exit},
    tokio::net::TcpListener,
};
#[tokio::main]
async fn main() {
    let port = 1024 + (random::<u16>() % 64000);
    let Ok(listener) = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), port)).await else {
        eprintln!("Can't listen on port {port}, please try again");
        exit(-1);
    };
    println!("HTTP server is listening on http://127.0.0.1:{port} @ version H/1.1337");
    loop {
        let Ok((cli, from)) = listener.accept().await else {
            eprintln!("Can't accept incoming connection");
            continue;
        };
        // Builder::new().serve_connection(stream)
        println!("Accepted connection from {from}");
        let hyper_io = TokioIo::new(cli);
        tokio::task::spawn(async move {
            // Handle the connection from the client using HTTP1 and pass any
            // HTTP requests received on that connection to the `hello` function
            if let Err(err) = Builder::new()
                .keep_alive(false)
                .serve_connection(hyper_io, service_fn(routing_function))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn routing_function(
    req: Request<impl hyper::body::Body>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match *req.method() {
        Method::GET => match req.uri().path() {
            "/" => Ok(redirect_elsewhere("/get_my_flag")),
            "/get_my_flag" => Ok(return_message("Now POST to the same URI!")),
            _ => Ok(return_404("Try starting from /")),
        },
        Method::POST => match req.uri().path() {
            "/get_my_flag" => {
                let Ok(body) = req.collect().await else {
                    return Ok(return_500("body read failed"));
                };
                let body = body.to_bytes().to_vec();
                if body.eq(b"give_me_flag_please!") {
                    Ok(return_message(&String::from_utf8_lossy(&flag::get_flag())))
                } else {
                    Ok(return_message("Now POST body \"give_me_flag_please!\""))
                }
            }
            _ => Ok(return_405("Try starting from GET /")),
        },
        _ => Ok(return_405("Try starting from GET /")),
    }
}

fn redirect_elsewhere(path: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::new()));
    *r.status_mut() = hyper::StatusCode::FOUND;
    r.headers_mut().insert("Location", path.parse().unwrap());
    r
}

fn return_message(msg: &str) -> Response<Full<Bytes>> {
    Response::new(Full::new(Bytes::from(msg.as_bytes().to_vec())))
}

fn return_404(msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.as_bytes().to_vec())));
    *r.status_mut() = hyper::StatusCode::NOT_FOUND;
    r
}

fn return_405(msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.as_bytes().to_vec())));
    *r.status_mut() = hyper::StatusCode::METHOD_NOT_ALLOWED;
    r
}

fn return_500(msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.as_bytes().to_vec())));
    *r.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
    r
}
