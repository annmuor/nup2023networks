use {
    anyhow::anyhow,
    hickory_server::{
        authority::MessageResponseBuilder,
        proto::{
            op::{Header, MessageType, OpCode, ResponseCode},
            rr::{
                rdata::{A, CNAME, NULL, SOA, SRV, TXT},
                LowerName, Name, RData, Record, RecordType,
            },
        },
        server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
        ServerFuture,
    },
    rand::random,
    std::{
        net::{IpAddr, Ipv4Addr},
        str::FromStr,
        time::Duration,
    },
    tokio::net::{TcpListener, UdpSocket},
};

mod flag;

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
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let root_zone_name = gen_zone_name();
    let mut real_server = ServerFuture::new(RootHandler(root_zone_name.clone()));
    real_server.register_socket(UdpSocket::bind((IpAddr::from([127, 0, 0, 1]), 6053)).await?);
    real_server.register_listener(
        TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 6053)).await?,
        Duration::from_secs(1),
    );
    println!("[+] DNS server is ready to accept requests");
    println!("[+] Your root zone is {root_zone_name}");
    println!("[+] Server is listening: UDP 127.0.0.1:6053");
    println!("[+] You may need HEX2ASCII tool also :)");
    real_server.block_until_done().await.map_err(|x| anyhow!(x))
}

struct RootHandler(String);
struct FakeHandler;

#[async_trait::async_trait]
impl RequestHandler for FakeHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        req: &Request,
        mut sender: R,
    ) -> ResponseInfo {
        let mut h = Header::new();
        h.set_response_code(ResponseCode::ServFail);
        h.set_id(req.id());
        let b = MessageResponseBuilder::from_message_request(req);
        let mr = b.build(h, &[], &[], &[], &[]);
        sender
            .send_response(mr)
            .await
            .unwrap_or_else(|_| Header::new().into())
    }
}

#[async_trait::async_trait]
impl RequestHandler for RootHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        sender: R,
    ) -> ResponseInfo {
        let res = self.do_handle_request(request, sender).await;
        if let Ok(res) = res {
            res
        } else if let Err((error, mut sender)) = res {
            eprintln!("Query error: {error}");
            let mut header = Header::response_from_request(request.header());
            header.set_response_code(ResponseCode::ServFail);
            header.set_authoritative(true);
            let mut name = request.query().name().to_string();
            name.insert_str(0, "error.");
            let name = Name::from_str(&name).unwrap();
            let b = MessageResponseBuilder::from_message_request(request);
            let rdata = RData::TXT(TXT::new(vec![error.to_string()]));
            let records = vec![Record::from_rdata(name, 60, rdata)];
            let mr = b.build(header, &[], &[], &[], records.iter());
            sender
                .send_response(mr)
                .await
                .unwrap_or_else(|_| Header::new().into())
        } else {
            unreachable!()
        }
    }
}

type RootHandlerError<R> = (anyhow::Error, R);
impl RootHandler {
    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut sender: R,
    ) -> Result<ResponseInfo, RootHandlerError<R>> {
        if request.op_code() != OpCode::Query {
            return Err((anyhow!("op_code != Query"), sender));
        }
        if request.message_type() != MessageType::Query {
            return Err((anyhow!("message_type != Query"), sender));
        }
        let root_zone = LowerName::from({
            let Ok(n) = Name::from_str(self.0.as_str()) else {
                return Err((anyhow!("Name is invalid"), sender));
            };
            n
        });
        println!(
            "Got message of type {} for name {} with query {}",
            request.message_type(),
            request.query().name(),
            request.query().query_type()
        );
        if !request.query().name().zone_of(&root_zone) {
            return Err((anyhow!("Invalid zone!"), sender));
        }
        let header = Header::response_from_request(request.header());
        let builder = MessageResponseBuilder::from_message_request(request);
        let records = match request.query().query_type() {
            RecordType::A => {
                let rdata = RData::A(A(Ipv4Addr::from([1, 2, 3, 4])));
                vec![Record::from_rdata(request.query().name().into(), 60, rdata)]
            }
            RecordType::AXFR => {
                let srv = RData::SRV(SRV::new(
                    0,
                    0,
                    6053,
                    Name::from_str(&format!("_tcp._axfr.{}", self.0)).unwrap(),
                ));
                let a = RData::A(A(Ipv4Addr::from([1, 2, 3, 4])));
                let cname = RData::CNAME(CNAME(Name::from_str("google.com").unwrap()));
                let txt = RData::TXT(TXT::new(vec![String::from("SRV is the key")]));
                let soa = RData::SOA(SOA::new(
                    Name::from_str(&self.0).unwrap(),
                    Name::from_str(&self.0).unwrap(),
                    random::<u32>(),
                    3600,
                    300,
                    7200,
                    60,
                ));
                let flag = RData::Unknown {
                    code: RecordType::Unknown(31337),
                    rdata: NULL::with(flag::get_flag()),
                };

                vec![
                    Record::from_rdata(request.query().name().into(), 60, soa.clone()),
                    Record::from_rdata(request.query().name().into(), 60, a),
                    Record::from_rdata(request.query().name().into(), 60, cname),
                    Record::from_rdata(request.query().name().into(), 60, txt),
                    Record::from_rdata(request.query().name().into(), 60, srv),
                    Record::from_rdata(request.query().name().into(), 60, flag),
                    Record::from_rdata(request.query().name().into(), 60, soa),
                ]
            }
            RecordType::CNAME => {
                let rdata = RData::CNAME(CNAME(Name::from_str("google.com").unwrap()));
                vec![Record::from_rdata(request.query().name().into(), 60, rdata)]
            }
            RecordType::SRV => {
                let rdata = RData::SRV(SRV::new(
                    0,
                    0,
                    6053,
                    Name::from_str(&format!("_tcp._axfr.{}", self.0)).unwrap(),
                ));
                vec![Record::from_rdata(request.query().name().into(), 60, rdata)]
            }
            RecordType::TXT => {
                let rdata = RData::TXT(TXT::new(vec![String::from("SRV is the key")]));
                vec![Record::from_rdata(request.query().name().into(), 60, rdata)]
            }
            RecordType::Unknown(31337) => {
                let flag = RData::Unknown {
                    code: RecordType::Unknown(31337),
                    rdata: NULL::with(flag::get_flag()),
                };
                vec![Record::from_rdata(request.query().name().into(), 60, flag)]
            }
            _ => return Err((anyhow!("Invalid query type"), sender)),
        };
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        sender
            .send_response(response)
            .await
            .map_err(|e| (anyhow!(e), sender))
    }
}
