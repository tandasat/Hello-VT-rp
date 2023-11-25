#![no_main]
#![no_std]

extern crate alloc;

mod paging_structures;
mod shell;

use alloc::{alloc::handle_alloc_error, vec::Vec};
use core::{alloc::Layout, arch::global_asm};
use uefi::prelude::*;
use uefi_services::println;
use x86::{
    controlregs::{cr0, cr0_write, cr3, Cr0},
    current::paging::BASE_PAGE_SHIFT,
};

use crate::paging_structures::{LargePage, Pd, Pdpt, Pml4};

#[entry]
fn main(image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();

    let args = shell::get_args();
    if args.len() == 1 {
        println!("Specify a hypercall number and up to 3 parameters as needed.");
        println!("  >{} <hypercall_number> [parameter [...]]", args[0]);
        println!("  >{} alias <gpa>", args[0]);
        return Status::INVALID_PARAMETER;
    }

    if args[1] == "alias" {
        demo_aliasing(u64::from_str_radix(args[2].trim_start_matches("0x"), 16).unwrap());
        return Status::SUCCESS;
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
    if status_code != 0 {
        println!("VMCALL({number}, {rdx:#x?}, {r8:#x?}, {r9:#x?}) => {status_code:#x?}");
    }
    Status::SUCCESS
}

fn demo_aliasing(gpa: u64) {
    let layout = Layout::new::<LargePage>();
    let alias_ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if alias_ptr.is_null() {
        handle_alloc_error(layout);
    }

    let alias = alias_ptr as usize;
    let i4 = alias >> 39 & 0b1_1111_1111;
    let i3 = alias >> 30 & 0b1_1111_1111;
    let i2 = alias >> 21 & 0b1_1111_1111;

    // Locate PML4e, PDPTe and PDe used to translate the LA of RuntimeServices.
    let pml4 = (unsafe { cr3() } & !0xfff) as *mut Pml4;
    let pml4 = unsafe { &mut *pml4 };
    let pdpt = (pml4.0.entries[i4].pfn() << BASE_PAGE_SHIFT) as *mut Pdpt;
    let pdpt = unsafe { &mut *pdpt };
    let pd = (pdpt.0.entries[i3].pfn() << BASE_PAGE_SHIFT) as *mut Pd;
    let pd = unsafe { &mut *pd };
    let pde = &mut pd.0.entries[i2];
    assert!(pde.large());

    // Update the PFN of the leaf entry to point to the specified GPA. Disable
    // write-protection as the paging structures are read-only on modern UEFI.
    unsafe {
        let cr0 = cr0();
        cr0_write(cr0 & !Cr0::CR0_WRITE_PROTECT);
        pde.set_pfn(gpa >> BASE_PAGE_SHIFT);
        cr0_write(cr0);
        x86::tlb::flush(alias);
    }

    println!("Aliased GPA {gpa:#x?} onto LA {alias_ptr:#x?}");
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("[PANIC]: {}", info);
    loop {
        unsafe {
            x86::irq::disable();
            x86::halt();
        };
    }
}

extern "C" {
    fn vmcall(number: u64, rdx: u64, r8: u64, r9: u64) -> u64;
}
global_asm!(include_str!("vmcall.S"));
