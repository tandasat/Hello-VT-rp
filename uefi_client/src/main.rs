#![no_main]
#![no_std]

extern crate alloc;

mod shell;

use log::{error, info};
use uefi::prelude::*;
use x86::{
    cpuid::cpuid,
    msr::{rdmsr, wrmsr},
};

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();

    // Get command line parameters.
    let args = shell::get_args();
    if args.len() != 2 {
        error!("Usage> uefi_client.efi <address>");
        return Status::INVALID_PARAMETER;
    }

    let addr = u64::from_str_radix(args[1].trim_start_matches("0x"), 16).unwrap();
    info!("0x{addr:x?}");
    enable_hfi(addr);

    Status::SUCCESS
}

fn enable_hfi(addr: u64) {
    let regs = cpuid!(6);
    assert!((regs.eax & 1 << 19) != 0, "Hardware Feedback Interface must be supported");

    assert!(addr.trailing_zeros() >= 12, "Address must be 4KB aligned");

    unsafe {
        wrmsr(0x1b1, rdmsr(0x1b1) & !(1 << 26));
        wrmsr(0x17d0, addr | 1); // IA32_HW_FEEDBACK_PTR <= addr | Valid
        wrmsr(0x17d1, 1); // IA32_HW_FEEDBACK_CONFIG <= Enable
    };
}
