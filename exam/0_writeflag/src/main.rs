use std::env::{self, VarError};
use std::io;

#[derive(Debug)]
enum Error {
    FlagNotFound,
    IOError,
}

impl From<VarError> for Error {
    fn from(_value: VarError) -> Self {
        Self::FlagNotFound
    }
}

impl From<io::Error> for Error {
    fn from(_value: io::Error) -> Self {
        Self::IOError
    }
}

fn main() -> Result<(), Error> {
    let flag = env::var("FLAG")?;
    println!(
        r#"
#[inline(always)]
pub fn get_flag() -> Vec<u8> {{
    let mut flag = "EXAM{{48564e3d6e272ccde24733285a85979f}}".as_bytes().to_vec();
    (0..64).step_by(4).for_each(|x| {{
        let idx = 5 + (x / 2);
        let b = format!("{{:02x}}", X[x]);
        flag[idx] = b.as_bytes()[0];
        flag[idx + 1] = b.as_bytes()[1];
    }});
    flag
}}
static X: [u8; 64] = [

"#
    );
    for i in 0..64 {
        if i % 4 == 0 {
            let idx = 5 + (i / 2);
            let var = u8::from_str_radix(&flag[idx..idx + 2], 16).expect("hex data");
            print!("{}", var);
        } else {
            print!("{}", rand::random::<u8>());
        }
        if i != 63 {
            print!(", ");
        } else {
            print!("\n];\n\n");
        }
    }
    Ok(())
}
