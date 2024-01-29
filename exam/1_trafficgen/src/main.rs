// 1. Generating packets
// 2. Once generating FLAG packet with invalid checksum
// 3. Putting the flag into random 5 byte header and 1 byte footer

use {
    clap::Parser,
    etherparse::PacketBuilder,
    pcap_file::pcap::{PcapPacket, PcapWriter},
    rand::random,
    std::{fs::File, process::exit, time::SystemTime},
};

enum ByRand {
    TcpUnicast,
    UdpUnicast,
    ICMPUnicast,
    UdpBroadcast,
    UdpMulticast,
}

impl ByRand {
    fn is_broadcast(&self) -> bool {
        matches!(self, ByRand::UdpBroadcast)
    }

    fn is_multicast(&self) -> bool {
        matches!(self, ByRand::UdpMulticast)
    }

    fn is_tcp(&self) -> bool {
        matches!(self, ByRand::TcpUnicast)
    }

    fn is_icmp(&self) -> bool {
        matches!(self, ByRand::ICMPUnicast)
    }
}

impl From<u64> for ByRand {
    fn from(value: u64) -> Self {
        if value % 3 == 0 {
            Self::UdpUnicast
        } else if value % 5 == 0 {
            Self::ICMPUnicast
        } else if value % 7 == 0 {
            Self::TcpUnicast
        } else if value % 11 == 0 {
            Self::UdpMulticast
        } else {
            Self::UdpBroadcast
        }
    }
}

const SIZE: u64 = 100_000;
#[derive(Parser)]
struct App {
    flag: String,
    #[arg(default_value = "out.pcap")]
    outfile: String,
}
fn main() {
    let size = SIZE + (random::<u64>() % SIZE); // from 1x to 2x size
    let app = App::parse();
    let flag = app.flag;
    println!("new flag = {flag}");
    let Ok(fd) = File::create(&app.outfile) else {
        eprintln!("File {} creation error", app.outfile);
        exit(1);
    };
    let Ok(mut writer) = PcapWriter::new(fd) else {
        eprintln!("Pcap writer open failed");
        exit(1);
    };
    let mut flag_written = false;
    for i in 0..size {
        let packet = gen_packet(i.into());
        if let Err(e) = writer.write_packet(&packet) {
            eprintln!("Pcap error: {e}");
            exit(-1);
        }
        if !flag_written && i > SIZE / 2 && random::<u8>() % 33 == 0 {
            let flag = gen_flag(&flag);
            flag_written = true;
            if let Err(e) = writer.write_packet(&flag) {
                eprintln!("Pcap error: {e}");
                exit(-1);
            }
        }
    }
    if !flag_written {
        eprintln!("Flag failed to be written ,please try again!");
    } else {
        println!("{} is ready!", app.outfile)
    }
}

fn gen_packet(what: ByRand) -> PcapPacket<'static> {
    let src_mac = random::<[u8; 6]>();
    let mut dst_mac = random::<[u8; 6]>();
    let src_ip = random::<[u8; 4]>();
    let mut dst_ip = random::<[u8; 4]>();
    if what.is_broadcast() {
        for i in 0..(random::<u8>() % 4) {
            dst_ip[(3 - i) as usize] = 255;
        }
    } else if what.is_multicast() {
        dst_ip[0] = 224 + (random::<u8>() % 16)
    }
    if what.is_multicast() {
        dst_mac[0] |= 0x1
    } else {
        dst_mac[0] &= 0xfe
    }
    let mut data = Vec::with_capacity(256);
    let b1 = PacketBuilder::ethernet2(src_mac, dst_mac).ipv4(src_ip, dst_ip, 64);
    if what.is_icmp() {
        let payload = gen_random_data(64, 128);
        if random::<bool>() {
            let seq = random::<u16>();
            let id = random::<u16>();
            b1.icmpv4_echo_request(seq, id)
                .write(&mut data, &payload)
                .expect("ICMP write works");
        } else {
            let seq = random::<u16>();
            let id = random::<u16>();
            b1.icmpv4_echo_reply(seq, id)
                .write(&mut data, &payload)
                .expect("ICMP write works");
        }
    } else if what.is_tcp() {
        let src_port = random::<u16>();
        let dst_port = random::<u16>();
        let seq = random::<u32>();
        let win = random::<u16>();
        let mut b1 = b1.tcp(src_port, dst_port, seq, win);
        if random::<u8>() % 3 == 0 {
            let ack = random::<u32>();
            b1 = b1.ack(ack);
        }
        if random::<u8>() % 17 == 0 {
            b1 = b1.fin();
        }
        if random::<u8>() % 31 == 0 {
            b1 = b1.syn();
        }
        let payload = gen_random_data(0, 175);
        b1.write(&mut data, &payload).expect("it shall work");
    } else {
        let src_port = random::<u16>();
        let dst_port = random::<u16>();
        let payload = gen_random_data(10, 200);
        b1.udp(src_port, dst_port)
            .write(&mut data, &payload)
            .expect("It shall work");
    }

    // crop SOME checksums for unicast / broadcast packages
    if random::<u8>() % 3 == 0 && !what.is_multicast() {
        data[24] = random::<u8>();
        data[25] = random::<u8>();
    }

    PcapPacket::new_owned(
        SystemTime::now().elapsed().unwrap(),
        data.len() as u32,
        data,
    )
}

fn gen_random_data(min: usize, max: usize) -> Vec<u8> {
    let size = min + random::<usize>() % (max - min);
    let mut data = Vec::with_capacity(size);
    for _ in 0..size {
        data.push(random())
    }
    data
}

fn gen_flag(flag: &str) -> PcapPacket<'static> {
    // Multicast - 224.x.x.x
    // UDP
    // Broken IP checksum
    let src_mac = random::<[u8; 6]>();
    let mut dst_mac = random::<[u8; 6]>();
    let src_ip = random::<[u8; 4]>();
    let mut dst_ip = random::<[u8; 4]>();
    dst_ip[0] = 224 + (random::<u8>() % 16);
    dst_mac[0] |= 0x1;
    let src_port = random::<u16>();
    let dst_port = random::<u16>();
    let b = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let flag = flag.as_bytes();
    let mut data = Vec::with_capacity(b.size(flag.len()));
    if let Err(e) = b.write(&mut data, flag) {
        eprintln!("Writing flag packed failed: {e}");
        exit(-1);
    }
    // change checksum to invalid
    // 24 & 25
    data[24] = random::<u8>();
    data[25] = random::<u8>();
    PcapPacket::new_owned(
        SystemTime::now().elapsed().unwrap(),
        data.len() as u32,
        data,
    )
}
