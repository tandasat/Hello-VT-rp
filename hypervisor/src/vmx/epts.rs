use bitfield::bitfield;
use core::ptr::addr_of;
use log::trace;
use uefi::table::boot::PAGE_SIZE;
use x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE};

use crate::vmx::mtrr::Mtrr;

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
