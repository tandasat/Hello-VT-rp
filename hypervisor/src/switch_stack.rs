use alloc::alloc::handle_alloc_error;
use core::{alloc::Layout, arch::global_asm};
use log::debug;
use uefi::proto::loaded_image::LoadedImage;

use crate::{
    hypervisor::start_hypervisor, system_table::system_table_unsafe, GuestRegisters, Page,
};

pub(crate) fn virtualize_system(regs: &GuestRegisters) -> ! {
    let st = unsafe { system_table_unsafe() };
    let bs = st.boot_services();
    let loaded_image = bs
        .open_protocol_exclusive::<LoadedImage>(bs.image_handle())
        .unwrap();
    let (image_base, image_size) = loaded_image.info();
    let image_base = image_base as usize;
    let image_range = image_base..image_base + image_size as usize;
    debug!("Image range: {image_range:#x?}");

    // Allocate separate stack space. This is never freed.
    let layout = Layout::array::<Page>(0x10).unwrap();
    let stack = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if stack.is_null() {
        handle_alloc_error(layout);
    }
    let stack_base = stack as u64 + 0x10000 - 0x10;
    debug!("Stack range: {:#x?}", (stack_base..stack as u64));

    // Jump into the "start_hypervisor" function with the new stack pointer.
    unsafe { switch_stack(regs, start_hypervisor as usize, stack_base) };
}

extern "efiapi" {
    // Jumps to the landing code with the new stack pointer.
    fn switch_stack(regs: &GuestRegisters, landing_code: usize, stack_base: u64) -> !;
}
global_asm!(include_str!("switch_stack.nasm"));
