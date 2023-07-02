use alloc::alloc::handle_alloc_error;
use core::{alloc::Layout, arch::global_asm};
use log::debug;
use uefi::{
    proto::loaded_image::LoadedImage,
    table::{Boot, SystemTable},
};

use crate::{hypervisor::start_hypervisor, GuestRegisters, Page};

/// Installs the hypervisor on the current processor.
pub(crate) fn virtualize_system(regs: &GuestRegisters, system_table: &SystemTable<Boot>) -> ! {
    let bs = system_table.boot_services();
    let loaded_image = bs
        .open_protocol_exclusive::<LoadedImage>(bs.image_handle())
        .unwrap();
    let (image_base, image_size) = loaded_image.info();
    let image_base = image_base as usize;
    let image_range = image_base..image_base + image_size as usize;
    debug!("Image range: {image_range:#x?}");

    // Prevent relocation by zapping the Relocation Table in the PE header. UEFI
    // keeps the list of runtime drivers and applies patches into their code and
    // data according with relocation information, as address translation switches
    // from physical-mode to virtual-mode when the OS starts. This causes a problem
    // with us because the host part keeps running under physical-mode, as the
    // host has its own page tables. Relocation ends up breaking the host code.
    // The easiest way is prevent this from happening is to nullify the relocation
    // table.
    unsafe {
        *((image_base + 0x128) as *mut u32) = 0;
        *((image_base + 0x12c) as *mut u32) = 0;
    }

    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();
    let stack = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + layout.size() as u64 - 0x10;
    debug!("Stack range: {:#x?}", (stack_base..stack as u64));

    unsafe { switch_stack(regs, start_hypervisor as usize, stack_base) };
}

extern "efiapi" {
    /// Jumps to the landing code with the new stack pointer.
    fn switch_stack(regs: &GuestRegisters, landing_code: usize, stack_base: u64) -> !;
}
global_asm!(include_str!("switch_stack.S"));
