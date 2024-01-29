// 1. Listen on ipv6
// 2. Same port shall be evident
// 3. Timeout is ~0.1S
// 4. Fine!

mod flag;

use {
    crate::flag::get_flag,
    rand::random,
    std::{
        io::{Read, Write},
        net::{Ipv6Addr, Shutdown, TcpListener},
        time::Duration,
    },
};

fn main() {
    let port = 1025 + (random::<u16>() % 64000);
    let Ok(l) = TcpListener::bind((Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), port)) else {
        eprintln!("Can't bind IPv6 ::1:{port}");
        return;
    };
    loop {
        let Ok((mut s, f)) = l.accept() else {
            eprintln!("Incoming connection failed");
            continue;
        };
        println!("[+] Incoming connection from {f}");
        if f.port() != port {
            eprintln!("[-] port is not the same, killing the connection");
            let _ = s.shutdown(Shutdown::Both);
            continue;
        }
        let e1 = s.set_read_timeout(Some(Duration::from_millis(100)));
        let e2 = s.set_write_timeout(Some(Duration::from_millis(100)));
        if e1.is_err() || e2.is_err() {
            eprintln!("[-] r/w timeouts failed, killing the connection");
            let _ = s.shutdown(Shutdown::Both);
            continue;
        }
        println!("[+] read/write timeouts set to 100ms");
        let mut read_buf = Box::new([0u8; 1024]);
        let Ok(size) = s.read(read_buf.as_mut_slice()) else {
            eprintln!("[-] read failed ( timeout ? ), killing the connection");
            let _ = s.shutdown(Shutdown::Both);
            continue;
        };
        if !read_buf[..size].eq(b"getflag") {
            eprintln!("[-] unknown command, killing the connection");
            let _ = s.shutdown(Shutdown::Both);
            continue;
        }
        let flag = get_flag();
        let Ok(_size) = s.write(&flag) else {
            eprintln!("[-] write failed ( timeout ? ), killing the connection");
            let _ = s.shutdown(Shutdown::Both);
            continue;
        };
        println!("[+] Flag was sent!");
    }
}
