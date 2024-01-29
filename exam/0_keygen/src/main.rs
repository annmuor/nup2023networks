use {
    blowfish::Blowfish,
    cipher::{block_padding::ZeroPadding, BlockDecrypt, BlockEncrypt, InvalidLength, KeyInit},
    clap::Parser,
    rand::random,
    std::{fmt::Write, process::exit},
};
#[derive(clap::Parser)]
struct App {
    task_id: u64,
    flag: Option<String>,
}

fn main() {
    let app = App::parse();
    match app.flag {
        None => {
            println!("{}", gen_key(app.task_id));
        }
        Some(key) => match check_key(&key, app.task_id) {
            true => println!("valid"),
            false => {
                println!("invalid");
                exit(1);
            }
        },
    }
}

fn gen_key(task_id: u64) -> String {
    let rnd_u64 = random::<u64>();
    // use LE always
    let rnd_block: [u8; 8] = rnd_u64.to_be_bytes();
    let mut task_id_block: [u8; 8] = task_id.to_be_bytes();
    let Ok(bf): Result<Blowfish<byteorder::BE>, InvalidLength> =
        Blowfish::new_from_slice(&task_id_block)
    else {
        eprintln!("Blowfish key error");
        exit(-1);
    };
    for i in 0..8 {
        task_id_block[i] ^= rnd_block[i];
    }
    let data = [rnd_block, task_id_block].concat();
    let data = bf.encrypt_padded_vec::<ZeroPadding>(&data);
    format!(
        "EXAM{{{}}}",
        data.into_iter().fold(String::new(), |mut col, f| {
            let _ = write!(col, "{:02x}", f);
            col
        })
    )
}

fn check_key(key: &str, task_id: u64) -> bool {
    if key.len() != 32 + 5 + 1 {
        return false;
    }
    if key[5..].len() != 33 {
        return false;
    }
    let _key = &key[5..37];

    let data = (0..32)
        .step_by(2)
        .filter_map(|x| u8::from_str_radix(&_key[x..x + 2], 16).ok())
        .collect::<Vec<u8>>();
    let task_id_block: [u8; 8] = task_id.to_be_bytes();
    let Ok(bf): Result<Blowfish<byteorder::BE>, InvalidLength> =
        Blowfish::new_from_slice(&task_id_block)
    else {
        eprintln!("Blowfish key error");
        exit(-1);
    };
    let Ok(mut data) = bf.decrypt_padded_vec::<ZeroPadding>(&data) else {
        eprintln!("Blowfish decrypt error");
        exit(-1);
    };
    for _ in data.len()..16 {
        data.push(0)
    }
    for i in 0..8 {
        data[i + 8] ^= data[i];
    }
    data[8..].eq(&task_id_block)
}
