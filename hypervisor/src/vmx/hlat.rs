use core::ptr::addr_of;
use x86::current::paging::BASE_PAGE_SHIFT;

use crate::{
    paging_structures::{Pd, Pdpt, Pml4, Pt},
    vmx::vm::vmread,
};

use super::vm::Vm;

#[repr(C, align(4096))]
pub(crate) struct PagingStructures {
    pml4: Pml4,
    pdpt: Pdpt,
    pd: Pd,
    pt: Pt,
}

pub(crate) fn initialize_hlat_table(tables: &mut PagingStructures) {
    for pml4e in &mut tables.pml4.0.entries {
        pml4e.set_present(true);
        pml4e.set_restart(true);
    }
    for pdpte in &mut tables.pdpt.0.entries {
        pdpte.set_present(true);
        pdpte.set_restart(true);
    }
    for pde2mb in &mut tables.pd.0.entries {
        pde2mb.set_present(true);
        pde2mb.set_restart(true);
    }
    for pte in &mut tables.pt.0.entries {
        pte.set_present(true);
        pte.set_restart(true);
    }
}

#[allow(clippy::similar_names)]
pub(crate) fn protect_la(vm: &mut Vm) {
    let la = vm.regs.rdx as usize;
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
    assert!(!pde.large());
    let pt = (pde.pfn() << BASE_PAGE_SHIFT) as *const Pt;
    let pt = unsafe { &*pt };
    let pte = &pt.0.entries[i1];

    vm.hlat.pml4.0.entries[i4].0 = pml4e.0;
    vm.hlat.pml4.0.entries[i4].set_restart(false);
    vm.hlat.pml4.0.entries[i4].set_pfn(addr_of!(vm.hlat.pdpt) as u64 >> BASE_PAGE_SHIFT);
    vm.hlat.pdpt.0.entries[i3].0 = pdpte.0;
    vm.hlat.pdpt.0.entries[i3].set_restart(false);
    vm.hlat.pdpt.0.entries[i3].set_pfn(addr_of!(vm.hlat.pd) as u64 >> BASE_PAGE_SHIFT);
    vm.hlat.pd.0.entries[i2].0 = pde.0;
    vm.hlat.pd.0.entries[i2].set_restart(false);
    vm.hlat.pd.0.entries[i2].set_pfn(addr_of!(vm.hlat.pt) as u64 >> BASE_PAGE_SHIFT);
    vm.hlat.pt.0.entries[i1].0 = pte.0;
    vm.hlat.pt.0.entries[i1].set_restart(false);

    vm.regs.rax = 0;
}
