//! The module containing wrapper functions for x86 instructions.
//!
//! Those instructions provided by the `x86` crate as `unsafe` functions, due to
//! the fact that those require certain preconditions. The wrappers provided by
//! this module encapsulate those `unsafe`-ness since this project always
//! satisfies the preconditions and safe to call them at any context.

use core::arch::asm;
use x86::{
    controlregs::{Cr0, Cr4, Xcr0},
    current::rflags::RFlags,
    dtables::DescriptorTablePointer,
    segmentation::SegmentSelector,
};

/// Reads an MSR.
pub(crate) fn rdmsr(msr: u32) -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::msr::rdmsr(msr) }
}

/// Writes a value to an MSR.
pub(crate) fn wrmsr(msr: u32, value: u64) {
    // Safety: this project runs at CPL0.
    unsafe { x86::msr::wrmsr(msr, value) };
}

/// Reads the CR0 register.
pub(crate) fn cr0() -> Cr0 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr0() }
}

/// Writes a value to the CR0 register.
pub(crate) fn cr0_write(val: Cr0) {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr0_write(val) };
}

/// Reads the CR3 register.
pub(crate) fn cr3() -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr3() }
}

/// Reads the CR4 register.
pub(crate) fn cr4() -> Cr4 {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr4() }
}

/// Writes a value to the CR4 register.
pub(crate) fn cr4_write(val: Cr4) {
    // Safety: this project runs at CPL0.
    unsafe { x86::controlregs::cr4_write(val) };
}

/// Reads the IDTR register.
pub(crate) fn sidt() -> DescriptorTablePointer<u64> {
    let mut idtr = DescriptorTablePointer::<u64>::default();
    // Safety: this project runs at CPL0.
    unsafe { x86::dtables::sidt(&mut idtr) };
    idtr
}

/// Reads the GDTR.
pub(crate) fn sgdt() -> DescriptorTablePointer<u64> {
    let mut gdtr = DescriptorTablePointer::<u64>::default();
    // Safety: this project runs at CPL0.
    unsafe { x86::dtables::sgdt(&mut gdtr) };
    gdtr
}

//
pub(crate) fn lsl(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut limit: u64;
    unsafe {
        asm!(
            "lsl {}, {}",
            "pushfq",
            "pop {}",
            out(reg) limit,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
        );
    };
    assert!(RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF));
    limit as u32
}

/// LAR-Load Access Rights Byte
pub(crate) fn lar(selector: SegmentSelector) -> u32 {
    let flags: u64;
    let mut access_rights: u64;
    unsafe {
        asm!(
            "lar {}, {}",
            "pushfq",
            "pop {}",
            out(reg) access_rights,
            in(reg) u64::from(selector.bits()),
            lateout(reg) flags
        );
    };
    assert!(RFlags::from_raw(flags).contains(RFlags::FLAGS_ZF));
    access_rights as u32
}

pub(crate) fn tr() -> SegmentSelector {
    unsafe { x86::task::tr() }
}

pub(crate) fn lgdt<T>(gdt: &DescriptorTablePointer<T>) {
    unsafe { x86::dtables::lgdt(gdt) };
}

pub(crate) fn load_tr(sel: SegmentSelector) {
    unsafe { x86::task::load_tr(sel) };
}

/// Reads 8-bits from an IO port.
pub(crate) fn inb(port: u16) -> u8 {
    // Safety: this project runs at CPL0.
    unsafe { x86::io::inb(port) }
}

/// Writes 8-bits to an IO port.
pub(crate) fn outb(port: u16, val: u8) {
    // Safety: this project runs at CPL0.
    unsafe { x86::io::outb(port, val) };
}

pub(crate) fn xsetbv(xcr: u32, val: Xcr0) {
    assert!(xcr == 0);
    unsafe { x86::controlregs::xcr0_write(val) };
}
