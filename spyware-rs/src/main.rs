use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::exit;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::RwLock;
use tokio::{select, spawn};

/**
 * Thisisnotreal
 **/
const MSG: [&str; 4] = [
    "http://8255344e21fcaf7b.annmuor.im/spyware",
    "http://8255344e21fcaf7b.annmuor.im/register",
    "http://8255344e21fcaf7b.annmuor.im/flag",
    "http://8255344e21fcaf7b.annmuor.im/botfather",
];
const PORTS: [u16; 10] = [1111, 3341, 3223, 9212, 4291, 5491, 3401, 9945, 42311, 56321];

const CCS: [[u8; 4]; 4] = [
    [79, 137, 74, 224],
    [79, 137, 74, 224],
    [79, 137, 74, 224],
    [79, 137, 74, 224],
];

#[derive(Debug)]
enum PeerState {
    Inactive,
    Connected([u8; 16]),
}

#[derive(Debug)]
struct Peer {
    addr: IpAddr,
    port: u16,
    state: PeerState,
}

type PeerDB = Arc<RwLock<HashMap<u64, Peer>>>;

static KEY: OnceLock<[u8; 16]> = OnceLock::new();

#[tokio::main]
async fn main() {
    KEY.get_or_init(|| {
        let mut buf = [0u8; 16];
        for i in 0..16 {
            buf[i] = random::<u8>()
        }
        buf
    });
    let mut tries = 0usize;
    let seed = random::<u64>();
    let (tcp, udp, port) = loop {
        let port = PORTS[random::<usize>() % PORTS.len()];
        let tcp = TcpListener::bind((IpAddr::from([0, 0, 0, 0]), port)).await;
        let udp = UdpSocket::bind((IpAddr::from([0, 0, 0, 0]), port)).await;
        match (tcp, udp) {
            (Ok(s1), Ok(s2)) => break (s1, s2, port),
            _ => tries += 1,
        };
        if tries > 10 {
            eprintln!("Failed to bind any port, exiting");
            exit(-1);
        }
    };
    let peers = Arc::new(RwLock::new(HashMap::new()));
    spawn(udp_broadcast_myself(port, seed));
    spawn(listen_udp_broadcasts(seed, port, udp, peers.clone()));
    // Find my ipaddress via UDP trick
    spawn(register_myself_http(seed, port, peers.clone()));
    spawn(dns_peer_lookup(port, seed, peers.clone()));
    spawn(listen_tcp_peers(seed, peers.clone(), tcp));
    spawn(connect_unconnected_peers(seed, peers.clone()));
    loop {
        tokio::time::sleep(Duration::from_secs(90)).await;
        let active_peers = peers
            .read()
            .await
            .iter()
            .filter(|x| x.1.state != PeerState::Inactive)
            .count();
        let inactive_peers = peers
            .read()
            .await
            .iter()
            .filter(|x| x.1.state == PeerState::Inactive)
            .count();
        println!(
            "[-] we have {active_peers} active peers and {inactive_peers} inactive peers known"
        );
        try_find_flag(peers.clone()).await;
    }
}

#[derive(Serialize, Deserialize)]
struct BotMessage {
    message: Vec<u8>,
}

async fn support_dialogue(peers: PeerDB, seed: u64, mut stream: TcpStream, key: [u8; 16]) {
    let mut timeout = tokio::time::interval(Duration::from_secs(10));
    loop {
        let data = MSG[random::<usize>() % MSG.len()].as_bytes();
        let mut v = Vec::from(data);
        for _ in 0..(16 - (data.len() % 16)) {
            v.push(0);
        }
        assert_eq!(v.len() % 16, 0);
        for i in 0..v.len() {
            v[i] = v[i] ^ key[i % 16]
        }
        let Ok(msg) = rmp_serde::to_vec(&BotMessage { message: v }) else {
            continue;
        };
        let mut error = false;
        let mut buf = Box::new([0u8; 1024]);
        select! {
            _ = timeout.tick() => {
                if stream.write(&msg).await.is_err() {
                    error = true
                }
            },
            res = stream.read(buf.as_mut_slice()) => {
                if res.is_err() {
                    error = true
                } else {
                    let size = res.unwrap();
                    let key = KEY.get().unwrap();
                    if let Ok(mut msg) = rmp_serde::from_slice::<BotMessage>(&buf[..size]) {
                        for i in 0..msg.message.len() {
                            msg.message[i] = msg.message[i] ^ key[i % 16]
                        }
                    } else {
                        error = true
                    }
                }
            }
        };
        if error {
            eprintln!("Connection with {seed} failed, resetting");
            peers
                .write()
                .await
                .entry(seed)
                .and_modify(|x| x.state = PeerState::Inactive);
            return;
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TcpHandshake {
    seed: u64,
    key: [u8; 16],
}

impl PartialEq for PeerState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PeerState::Inactive, PeerState::Inactive) => true,
            (PeerState::Connected(key), PeerState::Connected(key1)) => key1.eq(key),
            _ => false,
        }
    }
}

async fn try_find_flag(peer: PeerDB) {
    let mut url = [
        104, 116, 116, 122, 125, 186, 177, 131, 97, 110, 110, 103, 123, 239, 236, 130, 105, 109,
        47, 36, 125, 179, 238, 159, 97, 99, 101, 111, 124, 225, 253, 223, 116, 101, 101, 120, 122,
        243,
    ];
    let key: u64 = peer
        .read()
        .await
        .iter()
        .map(|(x, _)| *x)
        .fold(43192983212u64, |x, y| x | y);
    let bytes = key.to_be_bytes();
    for idx in 0..url.len() {
        url[idx] = bytes[idx % bytes.len()] ^ url[idx];
    }
    let Ok(s) = String::from_utf8(Vec::from(url)) else {
        println!("[----] Flag encryption protocol failed: too many peers known");
        return;
    };
    let Ok(r) = reqwest::get(s).await else {
        println!("[----] Flag encryption protocol failed: network access failed");
        return;
    };
    let Ok(b) = r.bytes().await else {
        println!("[----] Flag encryption protocol failed: network read failed");
        return;
    };
    println!("[++++] Your flag is {}", String::from_utf8_lossy(&b));
}

async fn connect_unconnected_peers(my_seed: u64, peers: PeerDB) {
    loop {
        let new_peers: Vec<(IpAddr, u16)> = peers
            .read()
            .await
            .iter()
            .filter(|x| x.1.state == PeerState::Inactive)
            .map(|x| (x.1.addr, x.1.port))
            .collect();
        for (ip, port) in new_peers {
            println!("[+] trying to connect to {ip}:{port}...");
            let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((ip, port))).await
            else {
                continue;
            };
            // send our handshake and key
            let mh = TcpHandshake {
                seed: my_seed,
                key: KEY.get().unwrap().clone(),
            };
            let Ok(v) = rmp_serde::to_vec(&mh) else {
                continue;
            };
            let Ok(_) = stream.write(&v).await else {
                continue;
            };
            let mut buf = Box::new([0u8; 1024]);
            let Ok(size) = stream.read(buf.as_mut_slice()).await else {
                continue;
            };
            let Ok(h) = rmp_serde::from_slice::<TcpHandshake>(&buf[..size]) else {
                continue;
            };
            peers
                .write()
                .await
                .entry(h.seed)
                .and_modify(|e| e.state = PeerState::Connected(h.key));
            spawn(support_dialogue(peers.clone(), h.seed, stream, h.key));
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn listen_tcp_peers(seed: u64, peers: PeerDB, tcp: TcpListener) {
    loop {
        let Ok((mut stream, addr)) = tcp.accept().await else {
            continue;
        };
        println!("[+] accepted connection from {addr}...");
        let mut buf = Box::new([0u8; 1024]);
        let Ok(size) = stream.read(buf.as_mut_slice()).await else {
            continue;
        };
        let Ok(h) = rmp_serde::from_slice::<TcpHandshake>(&buf[..size]) else {
            continue;
        };
        // send our handshake and key
        let mh = TcpHandshake {
            seed,
            key: KEY.get().unwrap().clone(),
        };
        let Ok(v) = rmp_serde::to_vec(&mh) else {
            continue;
        };
        let Ok(_) = stream.write(&v).await else {
            continue;
        };
        peers
            .write()
            .await
            .entry(h.seed)
            .and_modify(|e| e.state = PeerState::Connected(h.key))
            .or_insert_with(|| Peer {
                addr: addr.ip(),
                port: addr.port(),
                state: PeerState::Connected(h.key),
            });
        spawn(support_dialogue(peers.clone(), h.seed, stream, h.key));
    }
}

async fn dns_peer_lookup(port: u16, seed: u64, peers: PeerDB) {
    loop {
        tokio::time::sleep(Duration::from_secs(random::<u64>() % 30)).await;
        let Ok(addrs) = ("bots.nup23.annmuor.im", 80).to_socket_addrs() else {
            continue;
        };
        // try to start UDP connection
        let Ok(udp) = UdpSocket::bind((IpAddr::from([0, 0, 0, 0]), 0)).await else {
            continue;
        };
        let msg = IAmHereMessage { port, seed };
        if let Ok(msg) = rmp_serde::to_vec(&msg) {
            for addr in addrs {
                for port in PORTS {
                    let _ = udp.send_to(&msg, (addr.ip(), port)).await;
                }
            }
        }
        let _peers = peers.clone();
        let _ = tokio::time::timeout(Duration::from_secs(10), async move {
            let mut buf = Box::new([0u8; 1024]);
            loop {
                let Ok((size, from)) = udp.recv_from(buf.as_mut_slice()).await else {
                    return;
                };
                let Ok(m) = rmp_serde::from_slice::<IAmHereMessage>(&buf.as_slice()[..size]) else {
                    return;
                };
                if m.seed == seed {
                    return;
                }
                _peers.write().await.entry(m.seed).or_insert_with(|| Peer {
                    addr: from.ip(),
                    port: m.port,
                    state: PeerState::Inactive,
                });
                println!("[+] Found new peer via DNS discovery");
            }
        })
        .await;
    }
}

async fn register_myself_http(seed: u64, port: u16, peers: PeerDB) {
    loop {
        let mut stream = None;
        for ip in CCS {
            match TcpStream::connect((IpAddr::from(ip), 80)).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) => {
                    continue;
                }
            }
        }
        match stream {
            None => eprintln!("[!] can't register myself in HTTP server"),
            Some(stream) => {
                register_myself_with_stream(seed, port, stream, peers.clone()).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

#[derive(Serialize, Deserialize)]
struct PeerRequest {
    addr: IpAddr,
    port: u16,
    seed: u64,
}

async fn register_myself_with_stream(seed: u64, port: u16, mut stream: TcpStream, peers: PeerDB) {
    let Ok(my_addr) = stream.local_addr() else {
        return;
    };
    let req = PeerRequest {
        addr: my_addr.ip(),
        port,
        seed,
    };
    let Ok(req) = serde_json::to_string(&req) else {
        return;
    };
    let req = format!(
        r#"PUT /nup23/register HTTP/1.1
Host: spyware.nup23.local
Content-Type: application/json
Content-Length: {}
Connection: close

{req}
"#,
        req.len()
    );
    let Ok(_) = stream.write(req.as_bytes()).await else {
        return;
    };
    let mut s = String::new();
    let Ok(_) = stream.read_to_string(&mut s).await else {
        return;
    };
    let Some(start_index) = s.find('[') else {
        return;
    };
    let Ok(data) = serde_json::from_str::<Vec<PeerRequest>>(&s[start_index..]) else {
        return;
    };
    println!("[+] registered via control center");
    for peer_request in data {
        if peer_request.seed == seed {
            continue;
        }
        if peer_request.addr == my_addr.ip() {
            continue;
        }
        peers
            .write()
            .await
            .entry(peer_request.seed)
            .or_insert_with(|| Peer {
                addr: peer_request.addr,
                port: peer_request.port,
                state: PeerState::Inactive,
            });
    }
}

#[derive(Serialize, Deserialize)]
struct IAmHereMessage {
    port: u16,
    seed: u64,
}

async fn listen_udp_broadcasts(seed: u64, port: u16, udp: UdpSocket, peers: PeerDB) {
    let mut buf = Box::new([0u8; 1024]);
    loop {
        let Ok((size, from)) = udp.recv_from(buf.as_mut_slice()).await else {
            continue;
        };
        let Ok(m) = rmp_serde::from_slice::<IAmHereMessage>(&buf.as_slice()[..size]) else {
            continue;
        };
        if m.seed == seed {
            continue;
        }
        peers.write().await.entry(seed).or_insert_with(|| Peer {
            addr: from.ip(),
            port: m.port,
            state: PeerState::Inactive,
        });
        // send response with our seed
        let msg = IAmHereMessage { port, seed };
        if let Ok(msg) = rmp_serde::to_vec(&msg) {
            let _ = udp.send_to(&msg, from).await;
        }
    }
}

async fn udp_broadcast_myself(port: u16, seed: u64) {
    let Ok(udp) = UdpSocket::bind((IpAddr::from([0, 0, 0, 0]), 0)).await else {
        return;
    };
    let Ok(_) = udp.set_broadcast(true) else {
        return;
    };
    let msg = IAmHereMessage { port, seed };
    let Ok(msg) = rmp_serde::to_vec(&msg) else {
        return;
    };
    println!("[+] started broadcast service");
    loop {
        for port in PORTS {
            let _ = udp
                .send_to(&msg, (IpAddr::from([255, 255, 255, 255]), port))
                .await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
