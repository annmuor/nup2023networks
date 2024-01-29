use {
    clap::Parser,
    etherparse::PacketBuilder,
    pcap_file::pcap::{PcapPacket, PcapWriter},
    rand::random,
    std::{fs::File, net::Ipv4Addr, process::exit, time::SystemTime},
};

#[derive(Clone)]
struct BroadcastMessage {
    magic: u8,
    id: u64,
    port: u16,
    key: [u8; 16],
}

#[derive(Clone)]
struct HelloMessage {
    magic: u8,
    from_id: u64,
    to_id: u64,
    caller_key: [u8; 16],
    hello_iv: [u8; 16],
}

#[derive(Clone)]
struct HelloReply {
    magic: u8,
    from_id: u64,
    to_id: u64,
    hello_reply: [u8; 16],
}

#[derive(Clone)]
struct Message<'a> {
    magic: u8,
    len: u16,
    from_id: u64,
    to_id: u64,
    message: &'a [u8],
}

enum MessageType {
    Broadcast = 0xFF,
    Hello = 0x1F,
    HelloReply = 0x2F,
    Flag = 0x3f,
    Todo1 = 0x4f,
    Todo2 = 0x5f,
    Todo3 = 0x6f,
    Todo4 = 0x7f,
    Todo5 = 0x8f,
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        value as u8
    }
}

impl From<BroadcastMessage> for Vec<u8> {
    fn from(value: BroadcastMessage) -> Self {
        [
            [value.magic].as_slice(),
            value.id.to_be_bytes().as_slice(),
            value.port.to_be_bytes().as_slice(),
            value.key.as_slice(),
        ]
        .concat()
    }
}

impl From<HelloMessage> for Vec<u8> {
    fn from(value: HelloMessage) -> Self {
        [
            [value.magic].as_slice(),
            value.from_id.to_be_bytes().as_slice(),
            value.to_id.to_be_bytes().as_slice(),
            value.caller_key.as_slice(),
            value.hello_iv.as_slice(),
        ]
        .concat()
    }
}

impl From<HelloReply> for Vec<u8> {
    fn from(value: HelloReply) -> Self {
        [
            [value.magic].as_slice(),
            value.from_id.to_be_bytes().as_slice(),
            value.to_id.to_be_bytes().as_slice(),
            value.hello_reply.as_slice(),
        ]
        .concat()
    }
}

impl From<Message<'_>> for Vec<u8> {
    fn from(value: Message) -> Self {
        [
            [value.magic].as_slice(),
            value.len.to_be_bytes().as_slice(),
            value.from_id.to_be_bytes().as_slice(),
            value.to_id.to_be_bytes().as_slice(),
            value.message,
        ]
        .concat()
    }
}

impl BroadcastMessage {
    fn random() -> Self {
        Self {
            magic: MessageType::Broadcast.into(),
            id: random(),
            port: random(),
            key: random(),
        }
    }
}

#[derive(Parser)]
struct App {
    flag: String,
    #[arg(default_value = "out.pcap")]
    outfile: String,
}

fn main() {
    let app = App::parse();
    if !app.flag.starts_with("EXAM{") || !app.flag.ends_with('}') || app.flag.len() != 38 {
        eprintln!("Flag must start with EXAM{{ and end with }} and be 38 bytes length");
        exit(-1)
    }
    let Ok(fd) = File::create(&app.outfile) else {
        eprintln!("File {} creation error", app.outfile);
        exit(1);
    };
    let Ok(mut writer) = PcapWriter::new(fd) else {
        eprintln!("Pcap writer open failed");
        exit(1);
    };
    // let's say we have 3 peers
    // 1. They send broadcasts - 3 of them each
    // 2. They connect each other ( 3 connections )
    // 3. They send messages
    // 4. One of the messages is flag
    // PROFIT
    let mut macs = [
        random::<[u8; 6]>(),
        random::<[u8; 6]>(),
        random::<[u8; 6]>(),
    ];
    // Set unicast
    for mac in &mut macs {
        mac[0] &= 0xfe;
    }
    let ips = [
        Ipv4Addr::from([192, 168, random(), random()]),
        Ipv4Addr::from([192, 168, random(), random()]),
        Ipv4Addr::from([192, 168, random(), random()]),
    ];
    let bcasts = [
        BroadcastMessage::random(),
        BroadcastMessage::random(),
        BroadcastMessage::random(),
    ];
    let (tmac, tip) = (
        [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        Ipv4Addr::from([192, 168, 255, 255]),
    );
    // let's send broadcasts
    for i in 0..3 {
        let msg: Vec<u8> = bcasts[i].clone().into();
        let pb = PacketBuilder::ethernet2(macs[i], tmac)
            .ipv4(ips[i].octets(), tip.octets(), 64)
            .udp(random(), 25655);
        let mut data = Vec::with_capacity(pb.size(msg.len()));
        let _ = pb.write(&mut data, &msg);
        let _ = writer.write_packet(&PcapPacket::new(
            SystemTime::now().elapsed().unwrap(),
            data.len() as u32,
            &data,
        ));
    }
    // let's create connections
    for i in 0..3 {
        for j in 0..3 {
            if i == j {
                continue;
            }
            let mut random_bytes = random::<[u8; 16]>();
            encrypt_bytes(&mut random_bytes, &bcasts[j].key);
            let hello_msg: Vec<u8> = HelloMessage {
                magic: MessageType::Hello.into(),
                from_id: bcasts[i].id,
                to_id: bcasts[j].id,
                caller_key: bcasts[i].key,
                hello_iv: random_bytes,
            }
            .into();
            encrypt_bytes(&mut random_bytes, &bcasts[j].key);
            encrypt_bytes(&mut random_bytes, &bcasts[i].key);
            let hello_reply: Vec<u8> = HelloReply {
                magic: MessageType::HelloReply.into(),
                from_id: bcasts[j].id,
                to_id: bcasts[i].id,
                hello_reply: random_bytes,
            }
            .into();
            let pb = PacketBuilder::ethernet2(macs[i], macs[j])
                .ipv4(ips[i].octets(), ips[j].octets(), 64)
                .udp(bcasts[i].port, bcasts[j].port);
            let mut data = Vec::with_capacity(pb.size(hello_msg.len()));
            let _ = pb.write(&mut data, &hello_msg);
            let _ = writer.write_packet(&PcapPacket::new(
                SystemTime::now().elapsed().unwrap(),
                data.len() as u32,
                &data,
            ));
            let pb = PacketBuilder::ethernet2(macs[j], macs[i])
                .ipv4(ips[j].octets(), ips[i].octets(), 64)
                .udp(bcasts[j].port, bcasts[i].port);
            let mut data = Vec::with_capacity(pb.size(hello_reply.len()));
            let _ = pb.write(&mut data, &hello_reply);
            let _ = writer.write_packet(&PcapPacket::new(
                SystemTime::now().elapsed().unwrap(),
                data.len() as u32,
                &data,
            ));
        }
    }
    // let's send messages and send flag once :-)
    let mut have_flag = false;
    while !have_flag {
        for _i in 0..10 + (random::<u8>() % 240) {
            let from_id = random::<usize>() % 3;
            let to_id = loop {
                let id = random::<usize>() % 3;
                if id != from_id {
                    break id;
                }
            };
            let msg_type = {
                match random::<u16>() % 6 {
                    0 => {
                        if have_flag {
                            MessageType::Todo3
                        } else {
                            MessageType::Flag
                        }
                    }
                    1 => MessageType::Todo1,
                    2 => MessageType::Todo2,
                    3 => MessageType::Todo3,
                    4 => MessageType::Todo4,
                    _ => MessageType::Todo5,
                }
            };
            let mut data = match msg_type {
                MessageType::Flag => {
                    have_flag = true;
                    app.flag.as_bytes().to_vec()
                }
                _ => {
                    let len = 5 + (random::<usize>() % 255);
                    let mut v = Vec::with_capacity(len);
                    for _i in 0..len {
                        v.push(random::<u8>());
                    }
                    v
                }
            };
            encrypt_bytes(&mut data, &bcasts[to_id].key);
            let msg: Vec<u8> = Message {
                magic: msg_type.into(),
                len: data.len() as u16,
                from_id: bcasts[from_id].id,
                to_id: bcasts[to_id].id,
                message: &data,
            }
            .into();
            let pb = PacketBuilder::ethernet2(macs[from_id], macs[to_id])
                .ipv4(ips[from_id].octets(), ips[to_id].octets(), 64)
                .udp(bcasts[from_id].port, bcasts[to_id].port);
            let mut data = Vec::with_capacity(pb.size(msg.len()));
            let _ = pb.write(&mut data, &msg);
            let _ = writer.write_packet(&PcapPacket::new(
                SystemTime::now().elapsed().unwrap(),
                data.len() as u32,
                &data,
            ));
        }
    }
}

fn encrypt_bytes(msg: &mut [u8], key: &[u8; 16]) {
    for (idx, item) in msg.iter_mut().enumerate() {
        let key_idx = idx % 16;
        *item ^= key[key_idx]
    }
}
