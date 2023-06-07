use bitfield::bitfield;
use core::{arch::asm, ptr::addr_of};
use log::{debug, trace};
use uefi::table::boot::PAGE_SIZE;
use x86::{
    current::{
        paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE},
        rflags::RFlags,
    },
    vmx::vmcs,
};

use crate::{
    paging_structures::{Pd2Mb, Pdpt, Pml4},
    vmx::{mtrr::Mtrr, vmread},
};

use super::vm_succeed;

pub(crate) const LARGE_PAGE_SHIFT: u64 = 21;

// FIXME: name pml4 etc as ept_pml4

#[repr(C, align(4096))]
pub(crate) struct Epts {
    pml4: EptPml4,
    pdpt: EptPdpt,
    pd2mbs: [EptPd2Mb; 512],
    pt: EptPt,
    pt_for_write_protected_gpa: EptPt,
    pt_for_guest_paging_structures_gpa: EptPt,
}

pub(crate) fn write_protect(epts: &mut Epts, gpa: u64) {
    let gpa = gpa as usize;
    let i4 = gpa >> 39 & 0b1_1111_1111;
    let i3 = gpa >> 30 & 0b1_1111_1111;
    let i2 = gpa >> 21 & 0b1_1111_1111;
    let i1 = gpa >> 12 & 0b1_1111_1111;

    assert!(i4 == 0);
    assert!(i2 != 0);
    let mut pa = i4 << 39 | i3 << 30 | i2 << 21;

    let pde2mb = &mut epts.pd2mbs[i3].entries[i2];
    let memory_type = pde2mb.memory_type();
    let pde = unsafe { core::mem::transmute::<&mut EptPde2Mb, &mut EptPde>(pde2mb) };
    pde.0 = 0;
    pde.set_readable(true);
    pde.set_writable(true);
    pde.set_executable(true);
    pde.set_pfn(addr_of!(epts.pt_for_write_protected_gpa) as u64 >> BASE_PAGE_SHIFT);
    for pte in &mut epts.pt_for_write_protected_gpa.entries {
        pte.set_readable(true);
        pte.set_writable(true);
        pte.set_executable(true);
        pte.set_memory_type(memory_type);
        pte.set_pfn(pa as u64 >> BASE_PAGE_SHIFT);
        pa += PAGE_SIZE;
    }
    epts.pt_for_write_protected_gpa.entries[i1].set_writable(false);
    invept(InveptType::SingleContext, vmread(vmcs::control::EPTP_FULL));
}

pub(crate) fn set_writable(epts: &mut Epts, index: u64, writable: bool) {
    epts.pt_for_write_protected_gpa.entries[index as usize].set_writable(writable);
    invept(InveptType::SingleContext, vmread(vmcs::control::EPTP_FULL));
}

pub(crate) fn enable_guest_paging_verification(epts: &mut Epts, la: u64) {
    let i4 = la as usize >> 39 & 0b1_1111_1111;
    let i3 = la as usize >> 30 & 0b1_1111_1111;
    let i2 = la as usize >> 21 & 0b1_1111_1111;
    split_epts_for_la(epts, la);

    // Locate PML4e, PDPTe and PDe to be used to translate the LA from the guest
    // paging structures.
    let pml4 = (vmread(x86::vmx::vmcs::guest::CR3) & !0xfff) as *mut Pml4;
    let pml4 = unsafe { &mut *pml4 };
    let pdpt = (pml4.entries[i4].pfn() << BASE_PAGE_SHIFT) as *mut Pdpt;
    let pdpt = unsafe { &mut *pdpt };
    let pd2mb = (pdpt.entries[i3].pfn() << BASE_PAGE_SHIFT) as *mut Pd2Mb;
    let pd2mb = unsafe { &mut *pd2mb };
    let pde2mb = &pd2mb.entries[i2];
    assert!(pde2mb.large(), "'verify_translation' is unsupported on this system");
    enable_paging_write(epts, pml4 as *const _ as u64);
    enable_paging_write(epts, pdpt as *const _ as u64);
    enable_paging_write(epts, pd2mb as *const _ as u64);
    enable_verify_guest_paging(epts, pde2mb.pfn() << LARGE_PAGE_SHIFT);

    invept(InveptType::SingleContext, vmread(vmcs::control::EPTP_FULL));
}

// Splits a large EPT PDes needed to translate the `la` into 512 EPT PTes.
fn split_epts_for_la(epts: &mut Epts, la: u64) {
    let i4 = la as usize >> 39 & 0b1_1111_1111;
    let i3 = la as usize >> 30 & 0b1_1111_1111;

    // Locate PML4e, PDPTe and PDe to be used to translate the LA from the guest
    // paging structures.
    let pml4 = (vmread(x86::vmx::vmcs::guest::CR3) & !0xfff) as *const Pml4;
    split_pde2mb_for_gpa(epts, pml4 as u64);
    let pml4 = unsafe { &*pml4 };
    let pdpt = (pml4.entries[i4].pfn() << BASE_PAGE_SHIFT) as *const Pdpt;
    split_pde2mb_for_gpa(epts, pdpt as u64);
    let pdpt = unsafe { &*pdpt };
    let pd2mb = (pdpt.entries[i3].pfn() << BASE_PAGE_SHIFT) as *const Pd2Mb;
    split_pde2mb_for_gpa(epts, pd2mb as u64);
}

// Splits a large EPT PDe needed to translate the `gpa` into 512 EPT PTes. If
// already split, it does nothing.
fn split_pde2mb_for_gpa(epts: &mut Epts, gpa: u64) {
    let gpa = gpa as usize;
    let i4 = gpa >> 39 & 0b1_1111_1111;
    let i3 = gpa >> 30 & 0b1_1111_1111;
    let i2 = gpa >> 21 & 0b1_1111_1111;

    assert!(i4 == 0);

    let pde2mb = &mut epts.pd2mbs[i3].entries[i2];
    if !pde2mb.large() {
        trace!("Already split");
        return;
    }

    let memory_type = pde2mb.memory_type();
    let pde = unsafe { core::mem::transmute::<&mut EptPde2Mb, &mut EptPde>(pde2mb) };
    pde.0 = 0;
    pde.set_readable(true);
    pde.set_writable(true);
    pde.set_executable(true);
    pde.set_pfn(addr_of!(epts.pt_for_guest_paging_structures_gpa) as u64 >> BASE_PAGE_SHIFT);

    let mut pa = i4 << 39 | i3 << 30 | i2 << 21;
    assert!(epts.pt_for_guest_paging_structures_gpa.entries[0].0 == 0, "already consumed");
    for pte in &mut epts.pt_for_guest_paging_structures_gpa.entries {
        pte.set_readable(true);
        pte.set_writable(true);
        pte.set_executable(true);
        pte.set_memory_type(memory_type);
        pte.set_pfn(pa as u64 >> BASE_PAGE_SHIFT);
        pa += PAGE_SIZE;
    }
    invept(InveptType::SingleContext, vmread(vmcs::control::EPTP_FULL))
}

fn enable_paging_write(epts: &mut Epts, gpa: u64) {
    let gpa = gpa as usize;
    let i4 = gpa >> 39 & 0b1_1111_1111;
    let i3 = gpa >> 30 & 0b1_1111_1111;
    let i2 = gpa >> 21 & 0b1_1111_1111;
    let i1 = gpa >> 12 & 0b1_1111_1111;

    assert!(gpa >= LARGE_PAGE_SIZE);
    assert!(i4 == 0);
    debug!("Enabling paging write for GPA {gpa:#x?} {i2} {i1}");
    epts.pt_for_guest_paging_structures_gpa.entries[i1].set_paging_write(true);
    assert!(!epts.pd2mbs[i3].entries[i2].large());
}

fn enable_verify_guest_paging(epts: &mut Epts, gpa: u64) {
    let gpa = gpa as usize;
    let i4 = gpa >> 39 & 0b1_1111_1111;
    let i3 = gpa >> 30 & 0b1_1111_1111;
    let i2 = gpa >> 21 & 0b1_1111_1111;
    let i1 = gpa >> 19 & 0b1_1111_1111;

    assert!(gpa >= LARGE_PAGE_SIZE);
    assert!(i4 == 0);
    debug!("Enabling verification for GPA {gpa:#x?}");
    if epts.pd2mbs[i3].entries[i2].large() {
        epts.pd2mbs[i3].entries[i2].set_verify_guest_paging(true);
    } else {
        epts.pt_for_write_protected_gpa.entries[i1].set_verify_guest_paging(true);
    }
}

pub(crate) fn initialize_epts(epts: &mut Epts) {
    let mtrr = Mtrr::new();
    trace!("{mtrr:#x?}");

    let mut pa = 0u64;

    epts.pml4.entries[0].set_readable(true);
    epts.pml4.entries[0].set_writable(true);
    epts.pml4.entries[0].set_executable(true);
    epts.pml4.entries[0].set_pfn(addr_of!(epts.pdpt) as u64 >> BASE_PAGE_SHIFT);
    for (i, pdpte) in epts.pdpt.entries.iter_mut().enumerate() {
        pdpte.set_readable(true);
        pdpte.set_writable(true);
        pdpte.set_executable(true);
        pdpte.set_pfn(addr_of!(epts.pd2mbs[i]) as u64 >> BASE_PAGE_SHIFT);
        for pde2mb in &mut epts.pd2mbs[i].entries {
            if pa == 0 {
                let pde = unsafe { core::mem::transmute::<&mut EptPde2Mb, &mut EptPde>(pde2mb) };
                pde.set_readable(true);
                pde.set_writable(true);
                pde.set_executable(true);
                pde.set_pfn(addr_of!(epts.pt) as u64 >> BASE_PAGE_SHIFT);
                for pte in &mut epts.pt.entries {
                    let memory_type = mtrr.find(pa..pa + PAGE_SIZE as u64).unwrap_or_else(|| {
                        panic!("Memory type could not be resolved for {pa:#x?}")
                    });
                    pte.set_readable(true);
                    pte.set_writable(true);
                    pte.set_executable(true);
                    pte.set_memory_type(memory_type as u64);
                    pte.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += PAGE_SIZE as u64;
                }
            } else {
                let memory_type = mtrr
                    .find(pa..pa + LARGE_PAGE_SIZE as u64)
                    .unwrap_or_else(|| panic!("Memory type could not be resolved for {pa:#x?}"));
                pde2mb.set_readable(true);
                pde2mb.set_writable(true);
                pde2mb.set_executable(true);
                pde2mb.set_memory_type(memory_type as u64);
                pde2mb.set_large(true);
                pde2mb.set_pfn(pa >> LARGE_PAGE_SHIFT);
                pa += LARGE_PAGE_SIZE as u64;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPml4 {
    entries: [EptPml4e; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPdpt {
    entries: [EptPdpte; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPd2Mb {
    entries: [EptPde2Mb; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPd {
    entries: [EptPde; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct EptPt {
    entries: [EptPte; 512],
}

bitfield! {
    /// Table 29-1. Format of an EPT PML4 Entry (PML4E) that References an EPT Page-Directory-Pointer Table
    #[derive(Clone, Copy)]
    struct EptPml4e(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 29-3. Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that References an EPT Page Directory
    #[derive(Clone, Copy)]
    struct EptPdpte(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 29-4. Format of an EPT Page-Directory Entry (PDE) that Maps a 2-MByte Page
    #[derive(Clone, Copy)]
    struct EptPde2Mb(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    large, set_large: 7;
    pfn, set_pfn: 51, 21;
    verify_guest_paging, set_verify_guest_paging: 57;
    paging_write, set_paging_write: 58;
}

bitfield! {
    /// Table 29-5. Format of an EPT Page-Directory Entry (PDE) that References an EPT Page Table
    #[derive(Clone, Copy)]
    struct EptPde(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 29-6. Format of an EPT Page-Table Entry that Maps a 4-KByte Page
    #[derive(Clone, Copy)]
    struct EptPte(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    pfn, set_pfn: 51, 12;
    verify_guest_paging, set_verify_guest_paging: 57;
    paging_write, set_paging_write: 58;
}

/// The wrapper of the INVEPT instruction.
///
/// See: INVEPT - Invalidate Translations Derived from EPT
fn invept(invalidation: InveptType, eptp: u64) {
    let descriptor = InveptDescriptor { eptp, _reserved: 0 };
    let flags = unsafe {
        let flags: u64;
        asm!(
            "invept {}, [{}]",
            "pushfq",
            "pop {}",
            in(reg) invalidation as u64,
            in(reg) &descriptor,
            lateout(reg) flags
        );
        flags
    };
    if let Err(err) = vm_succeed(RFlags::from_raw(flags)) {
        panic!("{err}");
    }
}

/// The type of invalidation the INVEPT instruction performs.
///
/// See: 29.4.3.1 Operations that Invalidate Cached Mappings
#[repr(u64)]
enum InveptType {
    SingleContext = 1,
}

/// The structure to specify the effect of the INVEPT instruction.
///
/// See: Figure 31-1. INVEPT Descriptor
#[repr(C)]
struct InveptDescriptor {
    eptp: u64,
    _reserved: u64,
}
const _: () = assert!(core::mem::size_of::<InveptDescriptor>() == 16);
