#![no_main]
#![no_std]

extern crate alloc;

mod shell;

use alloc::vec::Vec;
use core::arch::global_asm;
use uefi::prelude::*;
use uefi_services::println;

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();

    let args = shell::get_args();
    if args.len() == 1 {
        println!("Specify a hypercall number and up to 3 parameters as needed.");
        println!("  >{} <hypercall_number> [parameter [...]]", args[0]);
        return Status::INVALID_PARAMETER;
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
    println!("VMCALL({number}, 0x{rdx:x?}, 0x{r8:x?}, 0x{r9:x?}) => 0x{status_code:x?}");
    Status::SUCCESS
}

extern "C" {
    fn vmcall(number: u64, rdx: u64, r8: u64, r9: u64) -> u64;
}
global_asm!(include_str!("vmcall.S"));
