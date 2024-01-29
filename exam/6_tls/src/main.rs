#![allow(unused)]
use rand::random;
use rcgen::{Certificate, CertificateParams, PKCS_RSA_SHA384};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::SignatureAlgorithm::RSA;
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme, SupportedProtocolVersion,
};
use std::io::{sink, Read, Write};
use std::net::{IpAddr, TcpListener};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

mod flag;
#[derive(Debug)]
enum AppError {
    Error(String),
}

impl<T> From<T> for AppError
where
    T: std::error::Error,
{
    fn from(value: T) -> Self {
        Self::Error(value.to_string())
    }
}
fn main() -> Result<(), AppError> {
    let names = vec![
        gen_zone_name(),
        gen_zone_name(),
        gen_zone_name(),
        gen_zone_name(),
        gen_zone_name(),
    ];
    let cert = rcgen::generate_simple_self_signed(names.clone())?;
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 4888))?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();
    println!("Listening on 127.0.0.1:4888 with name {}", names[0]);
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(CCV(names.clone())))
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der)),
        )?;
    let config = Arc::new(config);
    loop {
        let Ok((mut client, peer)) = listener.accept() else {
            eprintln!("Client accept failed");
            continue;
        };
        println!("Accepted connection from {peer}");
        let mut conn = rustls::ServerConnection::new(config.clone())?;
        let Ok(_) = conn.complete_io(&mut client) else {
            eprintln!("TLS connection failed");
            conn.send_close_notify();
            continue;
        };
        match conn.server_name() {
            None => {
                let _ = conn.writer().write(b"Please specify a server name\n");
                conn.send_close_notify();
                let _ = conn.complete_io(&mut client);
                continue;
            }
            Some(name) => {
                if name.eq(names.iter().last().unwrap().as_str()) {
                    let _ = conn.writer().write(b"Fine, now send me the command\n");
                    let _ = conn.complete_io(&mut client);
                    let mut buf = Box::new([0u8; 1024]);
                    let size = loop {
                        let _ = conn.complete_io(&mut client);
                        let Ok(size) = conn.reader().read(buf.as_mut_slice()) else {
                            sleep(Duration::from_millis(100));
                            continue;
                        };
                        break size;
                    };
                    if buf[..size].eq(b"getflag") {
                        let flag = flag::get_flag();
                        conn.writer().write(b"\n\n\n");
                        let _ = conn.writer().write(&flag);
                        conn.writer().write(b"\n\n\n");
                        let _ = conn.complete_io(&mut client);
                        println!("Flag was sent");
                        let size = loop {
                            let _ = conn.complete_io(&mut client);
                            let Ok(size) = conn.reader().read(buf.as_mut_slice()) else {
                                sleep(Duration::from_millis(100));
                                continue;
                            };
                            break size;
                        };
                        if size > 0 {
                            conn.send_close_notify();
                            let _ = conn.complete_io(&mut client);
                        }
                    } else {
                        let _ = conn
                            .writer()
                            .write(b"Not getflag command. Have you put CRLF? You shouldn't\n");
                        conn.send_close_notify();
                        let _ = conn.complete_io(&mut client);
                    }
                    continue;
                } else {
                    let _ = conn
                        .writer()
                        .write(b"This server name doesn't have flags, try another one\n");
                    conn.send_close_notify();
                    let _ = conn.complete_io(&mut client);
                    continue;
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct CCV(Vec<String>);

impl ClientCertVerifier for CCV {
    fn offer_client_auth(&self) -> bool {
        false
    }

    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn gen_zone_name() -> String {
    let mut s = (0..15).fold(String::new(), |mut s, _| loop {
        let ch = random::<char>();
        if ch.is_ascii_alphabetic() {
            s.push(ch.to_ascii_lowercase());
            break s;
        }
    });
    s.push_str(".nup23.local");
    s
}
