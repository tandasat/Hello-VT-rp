use bitfield::bitfield;
use core::ptr::addr_of;
use x86::{bits32::paging::BASE_PAGE_SHIFT, current::paging::LARGE_PAGE_SIZE};

#[repr(C, align(4096))]
pub(crate) struct PagingStructures {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: [Pd; 512],
}

pub(crate) fn initialize_paging_structures(paging_structures: &mut PagingStructures) {
    let pml4 = &mut paging_structures.pml4;
    pml4.0.entries[0].set_present(true);
    pml4.0.entries[0].set_writable(true);
    pml4.0.entries[0].set_pfn(addr_of!(paging_structures.pdpt) as u64 >> BASE_PAGE_SHIFT);

    let mut pa = 0;
    for (i, pdpte) in paging_structures.pdpt.0.entries.iter_mut().enumerate() {
        pdpte.set_present(true);
        pdpte.set_writable(true);
        pdpte.set_pfn(addr_of!(paging_structures.pd[i]) as u64 >> BASE_PAGE_SHIFT);
        for pde in &mut paging_structures.pd[i].0.entries {
            pde.set_present(true);
            pde.set_writable(true);
            pde.set_large(true);
            pde.set_pfn(pa >> BASE_PAGE_SHIFT);
            pa += LARGE_PAGE_SIZE as u64;
        }
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
    #[derive(Clone, Copy)]
    pub struct Entry(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
}
