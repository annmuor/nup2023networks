use {
    anyhow::anyhow,
    const_crc32::crc32,
    etherparse::PacketBuilder,
    pcap_file::{
        pcap::{PcapHeader, PcapPacket, PcapWriter},
        DataLink,
    },
    rand::random,
    rc4::{KeyInit, Rc4, StreamCipher},
    std::{env::args, fs::File, time::Duration},
};

struct IEEE802_11Frame {
    fc1: u8,
    fc2: u8,
    duration: u16,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
    seq_ctrl: u16,
    wep_iv: [u8; 3],
    wep_key_id: u8,
    body: Vec<u8>,
}

impl IEEE802_11Frame {
    fn ap_data_frame(
        from_ap: bool,
        bss: [u8; 6],
        from: [u8; 6],
        to: [u8; 6],
        data: Vec<u8>,
        key: [u8; 5],
    ) -> Self {
        let fc1: u8 = 0b0000_10_00;
        let fc2: u8 = match from_ap {
            true => 0b0_1_0_0_0_0_1_0,
            false => 0b0_1_0_0_0_0_0_1,
        };
        let duration = 32767u16;
        let iv = random::<[u8; 3]>();
        let mut cipher =
            Rc4::new(&[iv[0], iv[1], iv[2], key[0], key[1], key[2], key[3], key[4]].into());
        let crc32 = crc32(&data);
        let mut data = [&data, crc32.to_le_bytes().as_slice()].concat();
        cipher.apply_keystream(&mut data);
        // FROM AP: Dest (to) / BSSS  (AP) / SA (from)
        // TO AP: BSS (AP) / Source (STA)  / Dest (AP)
        IEEE802_11Frame {
            fc1,
            fc2,
            duration,
            addr1: match from_ap {
                true => to,
                false => bss,
            },
            addr2: match from_ap {
                true => bss,
                false => from,
            },
            addr3: match from_ap {
                true => from,
                false => to,
            },
            seq_ctrl: 0,
            wep_iv: iv,
            wep_key_id: 0,
            body: data,
        }
    }
}

impl From<IEEE802_11Frame> for Vec<u8> {
    fn from(value: IEEE802_11Frame) -> Self {
        [
            value.fc1.to_ne_bytes().as_slice(),
            value.fc2.to_ne_bytes().as_slice(),
            value.duration.to_ne_bytes().as_slice(),
            value.addr1.as_slice(),
            value.addr2.as_slice(),
            value.addr3.as_slice(),
            value.seq_ctrl.to_be_bytes().as_slice(),
            value.wep_iv.as_slice(),
            &[value.wep_key_id],
            value.body.as_slice(),
        ]
        .concat()
    }
}
fn main() -> anyhow::Result<()> {
    let flag: String = args()
        .nth(1)
        .ok_or_else(|| anyhow!("Usage: app <FLAG> <FILE>"))?;
    let file: String = args()
        .nth(2)
        .ok_or_else(|| anyhow!("Usage: app <FLAG> <FILE>"))?;
    let fd = File::create(file)?;
    let mut pcap_header = PcapHeader::default();
    pcap_header.datalink = DataLink::IEEE802_11;
    let mut wr = PcapWriter::with_header(fd, pcap_header)?;
    let key = {
        let mut k = [0u8; 5];
        for i in 0..5 {
            let c = loop {
                let x = random::<u8>();
                if x >= b'0' && x <= b'9' {
                    break x;
                }
            };
            k[i] = c;
        }
        k
    };
    let bss = random_mac();
    let stations: Vec<[u8; 6]> = (0..16).map(|_| random_mac()).collect();
    let stations_ip: Vec<[u8; 4]> = (0..16).map(|_| random_ip()).collect();
    for i in 0..10000 {
        // in the middle
        if i >= 2454 && i < 2456 {
            // 1. Send REQUEST from 192.168.0.1 to 255.255.255.255 - SHARE YOUR FLAG
            // 2. Each of the persons shares part of the flag
            // 3. SEND ACK
            let source_ip = [192, 168, 0, 1];
            let payload = b"SHARE YOUR FLAG NOW";
            let builder = PacketBuilder::ipv4(source_ip, [255, 255, 255, 255], 64);
            let builder = builder.udp(24555, 24555);
            let mut ipv4_packet = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut ipv4_packet, payload)?;
            let from_ap: Vec<u8> = IEEE802_11Frame::ap_data_frame(
                true,
                bss,
                bss,
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                [
                    &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00u8],
                    ipv4_packet.as_slice(),
                ]
                .concat(), // LLC header + IPv4,
                key,
            )
            .into();
            wr.write_packet(&PcapPacket::new(
                Duration::from_millis(i as u64),
                from_ap.len() as u32,
                &from_ap,
            ))?;
        } else if i >= 2456 && i < 2472 {
            let client_idx = i - 2456;
            let flag_b = flag.as_bytes();
            let size = flag_b.len() / 15;
            let flag_part = if client_idx == 15 {
                &flag_b[client_idx * size..]
            } else {
                &flag_b[client_idx * size..client_idx * size + (size)]
            };
            let payload: Vec<u8> = [b"MY FLAG PART IS: ", flag_part].concat();
            let builder = PacketBuilder::ipv4(stations_ip[client_idx], [192, 168, 0, 1], 64);
            let builder = builder.udp(24555, 24555);
            let mut ipv4_packet = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut ipv4_packet, &payload)?;
            let to_ap: Vec<u8> = IEEE802_11Frame::ap_data_frame(
                false,
                bss,
                stations[client_idx],
                bss,
                [
                    &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00u8],
                    ipv4_packet.as_slice(),
                ]
                .concat(), // LLC header + IPv4,
                key,
            )
            .into();
            wr.write_packet(&PcapPacket::new(
                Duration::from_millis(i as u64),
                to_ap.len() as u32,
                &to_ap,
            ))?;
        } else {
            let source_mac = stations[i % 8];
            let destination_mac = match i % 6 == 0 {
                true => [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                false => stations[8 + i % 8],
            };
            let source_ip = stations_ip[i % 8];
            let destination_ip = match i % 6 == 0 {
                true => [255, 255, 255, 255],
                false => stations_ip[8 + i % 8],
            };
            let builder = PacketBuilder::ipv4(source_ip, destination_ip, 64);
            let builder = builder.udp(24555, 24555);
            let payload = random_payload();
            let mut ipv4_packet = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut ipv4_packet, payload)?;

            let to_ap: Vec<u8> = IEEE802_11Frame::ap_data_frame(
                false,
                bss,
                source_mac,
                destination_mac,
                [
                    &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00u8],
                    ipv4_packet.as_slice(),
                ]
                .concat(), // LLC header + IPv4,
                key,
            )
            .into();
            let from_ap: Vec<u8> = IEEE802_11Frame::ap_data_frame(
                true,
                bss,
                source_mac,
                destination_mac,
                [
                    &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00u8],
                    ipv4_packet.as_slice(),
                ]
                .concat(), // LLC header + IPv4,
                key,
            )
            .into();
            wr.write_packet(&PcapPacket::new(
                Duration::from_millis(i as u64),
                to_ap.len() as u32,
                &to_ap,
            ))?;
            wr.write_packet(&PcapPacket::new(
                Duration::from_millis(i as u64),
                from_ap.len() as u32,
                &from_ap,
            ))?;
        }
    }
    Ok(())
}

fn random_mac() -> [u8; 6] {
    let mut m = random::<[u8; 6]>();
    m[0] &= 0xFE;
    m
}

fn random_ip() -> [u8; 4] {
    let mut i = random::<[u8; 4]>();
    i[0] = 192;
    i[1] = 168;
    i
}

const PAYLOADS: [&'static [u8]; 22] = [
    b"Incoming message operation started",
    b"Failed to process message",
    b"Outgoing message processed",
    b"Operation cancelled",
    b"Operation succeeded",
    b"No",
    b"Yes",
    b"Roses are red",
    b"Violets are blue",
    b"I'm cloacked",
    b"And waiting for you",
    b"0001001000100011100110011001100100100111",
    b"We're no strangers to love",
    b"You know the rules and so do I (do I)",
    b"A full commitment's what I'm thinking of",
    b"You wouldn't get",
    b"0xDEADBEEF0xDEADBEEF0xDEADBEEF0xDEADBEEF0xDEADBEEF0xDEAFBEEF",
    b"Flag is not here",
    b"Almost ready",
    b"Roger that",
    b"Shoot'em all",
    b"This is IEEE_802_11_WEP_LLC_IPv4_UDP generator",
];
fn random_payload() -> &'static [u8] {
    PAYLOADS[random::<usize>() % PAYLOADS.len()]
}
