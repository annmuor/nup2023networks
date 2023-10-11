use std::env::args;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::anyhow;
use mac_address::{mac_address_by_name, MacAddress};
use tokio::spawn;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::time::sleep;

fn main() {
    let mut args = args();
    let interface = {
        if args.len() < 2 {
            match pcap::Device::list() {
                Ok(devices) => devices
                    .iter()
                    .filter(|x| {
                        !x.addresses.is_empty() && x.flags.is_up() && !x.flags.is_loopback()
                    })
                    .next()
                    .map(|x| x.name.to_owned()),
                Err(e) => {
                    eprintln!("pcap device list error: {e}");
                    None
                }
            }
        } else {
            args.nth(1)
        }
    };
    if interface.is_none() {
        println!("Usage: {} [interface name]", args.nth(0).unwrap());
        return;
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match rt {
        Ok(rt) => {
            if let Err(e) = rt.block_on(start_broadcast(interface.unwrap())) {
                eprintln!("Broadcast service start failed: {e}");
            }
        }
        Err(e) => {
            eprintln!("Tokio runtime creation failed: {e}");
        }
    };
}

#[derive(Clone)]
struct Sender {
    ip: Option<(IpAddr, IpAddr)>,
    mac: Option<MacAddress>,
}
async fn start_broadcast(interface: String) -> anyhow::Result<()> {
    let device = pcap::Device::list()?
        .into_iter()
        .find(|x| x.name.eq(&interface))
        .ok_or_else(|| anyhow!("Device {interface} not found"))?;
    let sender = {
        let ip = device
            .addresses
            .iter()
            .filter(|x| x.addr.is_ipv4() && x.broadcast_addr.is_some())
            .next()
            .map(|x| (x.addr.clone(), x.broadcast_addr.clone().unwrap()));
        let mac = mac_address_by_name(&device.name)?;
        Sender { ip, mac }
    };

    let mut capture = pcap::Capture::from_device(device)?
        .immediate_mode(true)
        .open()?;
    let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
    spawn(gen_packages_ip(sender.clone(), 253, tx.clone()));
    spawn(gen_packages_udp(sender, 12345, tx));

    while let Some(packet) = rx.recv().await {
        capture.sendpacket(packet)?;
    }

    Ok(())
}

async fn gen_packages_udp(
    sender: Sender,
    port: u16,
    tx: UnboundedSender<Vec<u8>>,
) -> anyhow::Result<()> {
    // generate package
    let src_mac = sender
        .mac
        .map(|x| x.bytes())
        .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xffu8];
    let (src_ip, dst_ip) = sender.ip.unwrap_or((
        IpAddr::from([0xff, 0xff, 0xff, 0xff]),
        IpAddr::from([0xff, 0xff, 0xff, 0xff]),
    ));
    let src_ip = match src_ip {
        IpAddr::V4(x) => x.octets(),
        IpAddr::V6(_) => [0xff, 0xff, 0xff, 0xff],
    };
    let dst_ip = match dst_ip {
        IpAddr::V4(x) => x.octets(),
        IpAddr::V6(_) => [0xff, 0xff, 0xff, 0xff],
    };
    let payload = "NUP23{I_g0t_bro4dc4s7_udp_m3ss4g3}";
    loop {
        let packet = etherparse::PacketBuilder::ethernet2(src_mac, dst_mac)
            .ipv4(src_ip, dst_ip, 255)
            .udp(port - 1, port);
        let mut data = Vec::new();
        packet.write(&mut data, payload.as_bytes())?;
        tx.send(data)?;
        println!("Sent UDP packet!");
        sleep(Duration::from_secs(3)).await;
    }
}

async fn gen_packages_ip(
    sender: Sender,
    protocol: u8,
    tx: UnboundedSender<Vec<u8>>,
) -> anyhow::Result<()> {
    let src_mac = sender
        .mac
        .map(|x| x.bytes())
        .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xffu8];
    let (src_ip, dst_ip) = sender.ip.unwrap_or((
        IpAddr::from([0xff, 0xff, 0xff, 0xff]),
        IpAddr::from([0xff, 0xff, 0xff, 0xff]),
    ));
    let src_ip = match src_ip {
        IpAddr::V4(x) => x.octets(),
        IpAddr::V6(_) => [0xff, 0xff, 0xff, 0xff],
    };
    let dst_ip = match dst_ip {
        IpAddr::V4(x) => x.octets(),
        IpAddr::V6(_) => [0xff, 0xff, 0xff, 0xff],
    };
    let payload = "NUP23{I_g0t_bro4dc4s7_1p_d4t4}";
    loop {
        let packet =
            etherparse::PacketBuilder::ethernet2(src_mac, dst_mac).ipv4(src_ip, dst_ip, 255);
        let mut data = Vec::new();
        packet.write(&mut data, protocol, payload.as_bytes())?;
        tx.send(data)?;
        println!("Sent IPv4 packet!");
        sleep(Duration::from_secs(3)).await;
    }
}
