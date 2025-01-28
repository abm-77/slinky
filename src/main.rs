use std::{
    fs::File,
    io::{self, Read},
};

use nom::AsBytes;
use slinky::elf::ElfFile;

fn main() -> io::Result<()> {
    let mut f = File::open("data/math.o")?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let elf = ElfFile::parse(buffer.as_bytes()).unwrap();
    println!("{:#?}", elf);
    Ok(())
}
