#![doc = include_str!("../README.md")]
#![no_main]
#![no_std]
#![allow(clippy::cast_possible_truncation)]

extern crate alloc;

mod allocator;
mod hypervisor;
mod intel_vt;
mod paging_structures;
mod serial_logger;
mod switch_stack;
mod x86_instructions;

use core::arch::global_asm;
use log::{debug, error, info};
use uefi::prelude::*;
use x86::{cpuid::cpuid, current::paging::BASE_PAGE_SIZE};

use crate::{
    hypervisor::{CPUID_VENDOR_AND_MAX_FUNCTIONS, HLAT_VENDOR_NAME},
    switch_stack::virtualize_system,
};

#[entry]
fn main(image_handle: Handle, system_table: SystemTable<Boot>) -> Status {
    serial_logger::init(log::LevelFilter::Debug);
    info!("Loading vt-rp.efi...");

    allocator::init(&system_table);

    if is_hlat_hypervisor_present() {
        error!("The HLAT hypervisor is already present");
        return Status::ABORTED;
    }

    if x86::cpuid::CpuId::new().get_vendor_info().unwrap().as_str() != "GenuineIntel" {
        error!("The system is not on the Intel processor");
        return Status::ABORTED;
    }

    // Capture the register values to be used as an initial state of the VM.
    let mut regs = GuestRegisters::default();
    unsafe { capture_registers(&mut regs) };

    // Since we captured RIP just above, the VM will start running from here.
    // Check if our hypervisor is already loaded. If so, done, otherwise, continue
    // installing the hypervisor.
    if !is_hlat_hypervisor_present() {
        debug!("Virtualizing the system");
        virtualize_system(&regs, &system_table);
    }
    info!("The HLAT hypervisor has been installed successfully🔥");
    Status::SUCCESS
}

/// Checks if this hypervisor is already installed.
fn is_hlat_hypervisor_present() -> bool {
    let regs = cpuid!(CPUID_VENDOR_AND_MAX_FUNCTIONS);
    (regs.ebx == regs.ecx) && (regs.ecx == regs.edx) && (regs.edx == HLAT_VENDOR_NAME)
}

extern "efiapi" {
    /// Captures current general purpose registers, RFLAGS, RSP, and RIP.
    fn capture_registers(registers: &mut GuestRegisters);
}
global_asm!(include_str!("capture_registers.S"));

/// The structure representing a single memory page (4KB).
//
// This does not _always_ have to be allocated at the page aligned address, but
// very often it is, so let us specify the alignment.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct Page([u8; BASE_PAGE_SIZE]);

/// The collection of the guest general purpose register values.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
struct GuestRegisters {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rflags: u64,
    rsp: u64,
    rip: u64,
}

/// Handles panic.
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo<'_>) -> ! {
    error!("{info}");
    loop {
        unsafe {
            x86::irq::disable();
            x86::halt();
        };
    }
}
