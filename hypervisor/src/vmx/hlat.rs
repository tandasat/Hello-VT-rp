use core::{ops::Range, ptr::addr_of};
use x86::{
    bits32::paging::LARGE_PAGE_SIZE,
    current::paging::{BASE_PAGE_SHIFT, BASE_PAGE_SIZE},
};

use crate::{
    paging_structures::{Pd2Mb, Pde, Pde2Mb, Pdpt, Pml4, Pt},
    vmx::vmread,
};

#[repr(C, align(4096))]
pub(crate) struct HlatTables {
    pml4: Pml4,
    pdpt: Pdpt,
    pd2mb: Pd2Mb,
    pt: Pd2Mb,
}

pub(crate) fn initialize_hlat_table(tables: &mut HlatTables) {
    for pml4e in &mut tables.pml4.entries {
        pml4e.set_present(true);
        pml4e.set_restart(true);
    }
    for pdpte in &mut tables.pdpt.entries {
        pdpte.set_present(true);
        pdpte.set_restart(true);
    }
    for pde2mb in &mut tables.pd2mb.entries {
        pde2mb.set_present(true);
        pde2mb.set_restart(true);
    }
    for pte in &mut tables.pt.entries {
        pte.set_present(true);
        pte.set_restart(true);
    }
}

pub(crate) fn protect_linear_address(hlat: &mut HlatTables, la: u64) -> Range<u64> {
    let i4 = la as usize >> 39 & 0b1_1111_1111;
    let i3 = la as usize >> 30 & 0b1_1111_1111;
    let i2 = la as usize >> 21 & 0b1_1111_1111;
    let i1 = la as usize >> 12 & 0b1_1111_1111;

    // Locate PML4e, PDPTe and PDe to be used to translate the LA from the guest
    // paging structures.
    let pml4 = (vmread(x86::vmx::vmcs::guest::CR3) & !0xfff) as *mut Pml4;
    let pml4 = unsafe { &mut *pml4 };
    let pdpt = (pml4.entries[i4].pfn() << BASE_PAGE_SHIFT) as *mut Pdpt;
    let pdpt = unsafe { &mut *pdpt };
    let pd2mb = (pdpt.entries[i3].pfn() << BASE_PAGE_SHIFT) as *mut Pd2Mb;
    let pd2mb = unsafe { &mut *pd2mb };
    let pde2mb = &mut pd2mb.entries[i2];

    // Copy flags of them into HLAT paging structures. The PFN values need to point
    // to the HLAT paging structures.
    hlat.pml4.entries[i4].0 = pml4.entries[i4].0;
    hlat.pml4.entries[i4].set_pfn(addr_of!(hlat.pdpt) as u64 >> BASE_PAGE_SHIFT);
    hlat.pdpt.entries[i3].0 = pdpt.entries[i3].0;
    hlat.pdpt.entries[i3].set_pfn(addr_of!(hlat.pd2mb) as u64 >> BASE_PAGE_SHIFT);

    // If the guest PDe is configured for a large page, done. Otherwise, do the
    // same for PTe.
    let hlat_pde2mb = &mut hlat.pd2mb.entries[i2];
    hlat_pde2mb.0 = pde2mb.0;
    if pde2mb.large() {
        let start = la & !0x1ff_fff;
        start..start + LARGE_PAGE_SIZE as u64
    } else {
        // If the
        let pde = unsafe { core::mem::transmute::<&mut Pde2Mb, &mut Pde>(pde2mb) };
        let pt = (pde.pfn() << BASE_PAGE_SHIFT) as *mut Pt;
        let pt = unsafe { &mut *pt };

        hlat_pde2mb.set_pfn(addr_of!(hlat.pt) as u64 >> BASE_PAGE_SHIFT);
        hlat.pt.entries[i1].0 = pt.entries[i1].0;

        let start = la & !0xfff;
        start..start + BASE_PAGE_SIZE as u64
    }

    // TODO: what invalidation is required here?
}
