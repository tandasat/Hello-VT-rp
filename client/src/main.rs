use std::{arch::global_asm, env};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Specify a linear address to protect using HLAT.");
        println!("eg, >client.exe 0 0x12345");
        return;
    }

    let number = u64::from_str_radix(args[1].trim_start_matches("0x"), 10).unwrap();
    let rdx: u64 = u64::from_str_radix(args[2].trim_start_matches("0x"), 16).unwrap();
    println!("{number} 0x{rdx:x?}");
    let ok = unsafe { vmcall(number, rdx, 0, 0) };
    println!("hohoho: {ok}");
}

extern "C" {
    fn vmcall(number: u64, rdx: u64, r8: u64, r9: u64) -> u64;
}
global_asm!(include_str!("vmcall.S"));
