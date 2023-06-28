use std::{arch::global_asm, env};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 1 {
        println!("Specify a hypercall number and up to 3 parameters as needed.");
        println!("  >{} <hypercall_number> [parameter [...]]", args[0]);
        return;
    }

    let params: Vec<u64> = args
        .iter()
        .skip(1)
        .map(|arg| {
            u64::from_str_radix(arg.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("'{arg}' cannot be converted to u64"))
        })
        .collect();

    let number = params[0];
    let rdx = *params.get(1).unwrap_or(&0);
    let r8 = *params.get(2).unwrap_or(&0);
    let r9 = *params.get(3).unwrap_or(&0);

    let status_code = unsafe { vmcall(number, rdx, r8, r9) };
    println!("VMCALL({number}, {rdx:#x?}, {r8:#x?}, {r9:#x?}) => {status_code:#x?}");
}

extern "C" {
    fn vmcall(number: u64, rdx: u64, r8: u64, r9: u64) -> u64;
}
global_asm!(include_str!("vmcall.S"));
