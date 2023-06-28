use bitfield::bitfield;
use core::ptr::addr_of;
use log::trace;
use uefi::table::boot::PAGE_SIZE;
use x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE};

use super::mtrr::Mtrr;

#[repr(C, align(4096))]
pub(crate) struct Epts {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: [Pd; 512],
    pt: Pt,
}
impl Epts {
    pub(crate) fn build_identify(&mut self) {
        let mtrr = Mtrr::new();
        trace!("{mtrr:#x?}");
        trace!("Initializing EPTs");

        let mut pa = 0u64;

        self.pml4.0.entries[0].set_readable(true);
        self.pml4.0.entries[0].set_writable(true);
        self.pml4.0.entries[0].set_executable(true);
        self.pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            pdpte.set_readable(true);
            pdpte.set_writable(true);
            pdpte.set_executable(true);
            pdpte.set_pfn(addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT);
            for pde in &mut self.pd[i].0.entries {
                if pa == 0 {
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_pfn(addr_of!(self.pt) as u64 >> BASE_PAGE_SHIFT);
                    for pte in &mut self.pt.0.entries {
                        let memory_type =
                            mtrr.find(pa..pa + PAGE_SIZE as u64).unwrap_or_else(|| {
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
                    let memory_type =
                        mtrr.find(pa..pa + LARGE_PAGE_SIZE as u64)
                            .unwrap_or_else(|| {
                                panic!("Memory type could not be resolved for {pa:#x?}")
                            });
                    pde.set_readable(true);
                    pde.set_writable(true);
                    pde.set_executable(true);
                    pde.set_memory_type(memory_type as u64);
                    pde.set_large(true);
                    pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                    pa += LARGE_PAGE_SIZE as u64;
                }
            }
        }
    }

    pub(crate) fn make_2mb_ro(&mut self, gpa: u64) {
        self.pde_mut(gpa).set_writable(false);
    }

    pub(crate) fn make_2mb_pw(&mut self, gpa: u64) {
        self.pde_mut(gpa).set_paging_write(true);
    }

    pub(crate) fn make_2mb_gpv(&mut self, gpa: u64) {
        self.pde_mut(gpa).set_verify_guest_paging(true);
    }

    fn pde_mut(&mut self, gpa: u64) -> &mut Entry {
        let gpa = gpa as usize;
        let i4 = gpa >> 39 & 0b1_1111_1111;
        let i3 = gpa >> 30 & 0b1_1111_1111;
        let i2 = gpa >> 21 & 0b1_1111_1111;

        assert!((gpa % LARGE_PAGE_SIZE) == 0);
        assert!(i4 == 0);

        let entry = &mut self.pd[i3].0.entries[i2];
        assert!(entry.large());
        entry
    }
}

#[derive(Debug, Clone, Copy)]
struct Pml4(Table);

#[derive(Debug, Clone, Copy)]
struct Pdpt(Table);

#[derive(Debug, Clone, Copy)]
struct Pd(Table);

#[derive(Debug, Clone, Copy)]
struct Pt(Table);

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
struct Table {
    entries: [Entry; 512],
}

bitfield! {
    /// Figure 29-1. Formats of EPTP and EPT Paging-Structure Entries
    #[derive(Clone, Copy)]
    struct Entry(u64);
    impl Debug;
    readable, set_readable: 0;
    writable, set_writable: 1;
    executable, set_executable: 2;
    memory_type, set_memory_type: 5, 3;
    large, set_large: 7;
    pfn, set_pfn: 51, 12;
    verify_guest_paging, set_verify_guest_paging: 57;
    paging_write, set_paging_write: 58;
}
