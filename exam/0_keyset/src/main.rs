use rand::random;
use std::env::args;
use std::fs::{read, File};
use std::io::Write;
use std::process::exit;

static X: [u8; 64] = [
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 0, 0,
];

fn main() {
    let args = args().collect::<Vec<String>>();
    if args.len() != 4 {
        eprintln!(
            "Usage: {} <template-binary> <flag-to-encode> <output-binary>",
            &args[0]
        );
        exit(-1);
    }
    let Ok(flag) = get_flag(&args[2]) else {
        eprintln!("Bad flag format");
        exit(-1);
    };
    let Ok(origin) = read(&args[1]) else {
        eprintln!("Failed to read original file {}", &args[1]);
        exit(-1);
    };
    let Ok(mut target) = File::create(&args[3]) else {
        eprintln!("Failed to create write file {}", &args[3]);
        exit(-1);
    };
    let Some(idx) = origin.windows(64).position(|x| x.eq(&X)) else {
        eprintln!("Position of X not found. Do you have clean unpacked binary here?");
        exit(-1);
    };
    println!("Position of X found at {idx}, starting putting flag into");
    let mut new_x = (0..64).map(|_| random::<u8>()).collect::<Vec<u8>>();
    (0..16).for_each(|idx| new_x[idx * 4] = flag[idx]);
    target.write(&origin[..idx]).expect("write 1/2 failed");
    target.write(&new_x).expect("newX write failed");
    target.write(&origin[idx + 64..]).expect("write 2/2 failed");
    println!("{} was written successfully, go and try it", &args[3]);
    //let flag
}

fn get_flag(key: &str) -> Result<Vec<u8>, &'static str> {
    if key.len() != 38 {
        return Err("Flag len != 38");
    }
    let _key = &key[5..37];

    Ok((0..32)
        .step_by(2)
        .filter_map(|x| u8::from_str_radix(&_key[x..x + 2], 16).ok())
        .collect::<Vec<u8>>())
}
