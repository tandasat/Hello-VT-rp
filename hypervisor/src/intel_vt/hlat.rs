use core::ptr::addr_of;
use x86::current::paging::BASE_PAGE_SHIFT;

use super::vm::vmread;
use crate::paging_structures::{Pd, Pdpt, Pml4, Pt};

// The hypervisor-managed paging structures. The alignment is set to translate
// all those structures only with a single EPT PDe for simpler implementation
// and demonstration.
#[repr(C, align(0x20_0000))]
pub(crate) struct PagingStructures {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: Pd,
    pt: Pt,
}
const _: () = assert!(core::mem::size_of::<PagingStructures>() == 0x20_0000);

impl PagingStructures {
    pub(crate) fn deactivate(&mut self) {
        for pml4e in &mut self.pml4.0.entries {
            pml4e.set_present(true);
            pml4e.set_restart(true);
        }
        for pdpte in &mut self.pdpt.0.entries {
            pdpte.set_present(true);
            pdpte.set_restart(true);
        }
        for pde in &mut self.pd.0.entries {
            pde.set_present(true);
            pde.set_restart(true);
        }
        for pte in &mut self.pt.0.entries {
            pte.set_present(true);
            pte.set_restart(true);
        }
    }

    #[allow(clippy::similar_names)]
    // Prevent aliasing for the given LA by enabling HLAT paging for it. Returns
    // GPA corresponds to the given LA.
    pub(crate) fn enable_hlat_for_4kb(&mut self, la: u64) -> u64 {
        let la = la as usize;
        let i4 = la >> 39 & 0b1_1111_1111;
        let i3 = la >> 30 & 0b1_1111_1111;
        let i2 = la >> 21 & 0b1_1111_1111;
        let i1 = la >> 12 & 0b1_1111_1111;

        // Locate PML4e, PDPTe and PDe to be used to translate the LA from the guest
        // paging structures.
        let pml4 = (vmread(x86::vmx::vmcs::guest::CR3) & !0xfff) as *const Pml4;
        let pml4 = unsafe { &*pml4 };
        let pml4e = pml4.0.entries[i4];
        let pdpt = (pml4e.pfn() << BASE_PAGE_SHIFT) as *const Pdpt;
        let pdpt = unsafe { &*pdpt };
        let pdpte = pdpt.0.entries[i3];
        let pd = (pdpte.pfn() << BASE_PAGE_SHIFT) as *const Pd;
        let pd = unsafe { &*pd };
        let pde = &pd.0.entries[i2];

        // Then, copy the guest entry values into the hypervisor-managed paging
        // structure entries, clear the restart bit as OS may have used this bit,
        // and update PFN to point to the next hypervisor-managed paging structures.
        self.pml4.0.entries[i4].0 = pml4e.0;
        self.pml4.0.entries[i4].set_restart(false);
        self.pml4.0.entries[i4].set_pfn(addr_of!(self.pdpt) as u64 >> BASE_PAGE_SHIFT);
        self.pdpt.0.entries[i3].0 = pdpte.0;
        self.pdpt.0.entries[i3].set_restart(false);
        self.pdpt.0.entries[i3].set_pfn(addr_of!(self.pd) as u64 >> BASE_PAGE_SHIFT);
        if pde.large() {
            self.pd.0.entries[i2].0 = pde.0;
            self.pd.0.entries[i2].set_restart(false);
            self.pd.0.entries[i2].pfn() << BASE_PAGE_SHIFT
        } else {
            // If it is not a large page, also process a PTe.
            let pt = (pde.pfn() << BASE_PAGE_SHIFT) as *const Pt;
            let pt = unsafe { &*pt };
            let pte = &pt.0.entries[i1];

            self.pd.0.entries[i2].0 = pde.0;
            self.pd.0.entries[i2].set_restart(false);
            self.pd.0.entries[i2].set_pfn(addr_of!(self.pt) as u64 >> BASE_PAGE_SHIFT);
            self.pt.0.entries[i1].0 = pte.0;
            self.pt.0.entries[i1].set_restart(false);
            self.pt.0.entries[i1].pfn() << BASE_PAGE_SHIFT
        }
    }
}
