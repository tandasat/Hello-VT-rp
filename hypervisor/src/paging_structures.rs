use bitfield::bitfield;
use core::ptr::addr_of;
use x86::current::paging::{BASE_PAGE_SHIFT, LARGE_PAGE_SIZE};

#[repr(C, align(4096))]
pub(crate) struct PagingStructures {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: [Pd; 512],
}
impl PagingStructures {
    pub(crate) fn build_identity(&mut self) {
        let pml4 = &mut self.pml4;
        pml4.0.entries[0].set_present(true);
        pml4.0.entries[0].set_writable(true);
        pml4.0.entries[0].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);

        let mut pa = 0;
        for (i, pdpte) in self.pdpt.0.entries.iter_mut().enumerate() {
            pdpte.set_present(true);
            pdpte.set_writable(true);
            pdpte.set_pfn(addr_of!(self.pd[i]) as u64 >> BASE_PAGE_SHIFT);
            for pde in &mut self.pd[i].0.entries {
                pde.set_present(true);
                pde.set_writable(true);
                pde.set_large(true);
                pde.set_pfn(pa >> BASE_PAGE_SHIFT);
                pa += LARGE_PAGE_SIZE as u64;
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pml4(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pdpt(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pd(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
pub(crate) struct Pt(pub(crate) Table);

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Table {
    pub(crate) entries: [Entry; 512],
}

bitfield! {
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub large, set_large: 7;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 12;
}
