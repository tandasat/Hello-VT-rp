use alloc::{alloc::handle_alloc_error, boxed::Box};
use core::alloc::Layout;
use log::{debug, info};
use uefi::{
    prelude::*,
    table::{
        runtime::{Time, TimeCapabilities},
        Header,
    },
};
use uefi_services::system_table;
use x86::{controlregs::Cr0, current::paging::BASE_PAGE_SHIFT};

use crate::{
    hypervisor::{
        SYNTHETIC_IA32_LOCK_TRANSLATION_OF_PAGE, SYNTHETIC_IA32_UNLOCK_TRANSLATION_OF_PAGE,
        SYNTHETIC_IA32_VERIFY_TRANSLATION_OF_PAGE, SYNTHETIC_IA32_WRITE_PROTECT_PAGE,
    },
    paging_structures::{Pd2Mb, Pde, Pde2Mb, Pdpt, Pml4, Pt},
    vmx::epts::LARGE_PAGE_SHIFT,
    x86_instructions::{cr0, cr0_write, cr3, invlpg, wrmsr},
    LargePage, Page,
};

pub(crate) fn test_hlat() {
    let rt = unsafe { system_table().as_ref() }.runtime_services();
    let rt_addr = rt as *const _ as u64;
    let get_time_addr = rt_addr + core::mem::size_of::<Header>() as u64;

    if cfg!(feature = "protect_gpa") {
        let size = core::mem::size_of::<RuntimeServices>() as u64;
        let value = rt_addr | size << 51;
        wrmsr(SYNTHETIC_IA32_WRITE_PROTECT_PAGE, value);
        info!("Protection: gRT->GetTime at GPA {get_time_addr:#x?} is read-only with EPT");
    }
    if cfg!(feature = "protect_translation") {
        wrmsr(SYNTHETIC_IA32_LOCK_TRANSLATION_OF_PAGE, rt_addr);
        info!("=== Enabled HLAT. gRT->GetTime's LA -> GPA translation is protected ===");
    }
    if cfg!(feature = "verify_translation") {
        wrmsr(SYNTHETIC_IA32_VERIFY_TRANSLATION_OF_PAGE, rt_addr);
        info!("Protection: gRT->GetTime's LA -> PA translation will be verified with PW/VPW bits");
    }

    info!("Contents of gRT->GetTime: {:#x?}", unsafe { *(get_time_addr as *mut usize) });

    if cfg!(feature = "alias") {
        let aliased_rt = alias_runtime_services();
        info!("{:#x?}", rt.get_time().unwrap());
        info!("{:#x?}", aliased_rt.get_time().unwrap());
    }

    if cfg!(feature = "remap") {
        let cloned_st = remap_runtime_services();
        let cloned_get_time_addr = cloned_st + core::mem::size_of::<Header>();
        let hooked_get_time = hooked_get_time as usize;

        info!("Attacker: Copied a page with gRT->GetTime to new GPA");
        unsafe { *(cloned_get_time_addr as *mut usize) = hooked_get_time };
        info!("Attacker: Changed contents of the copied gRT->GetTime to {hooked_get_time:#x?}");
        info!("Attacker: Remapped LA of gRT->GetTime onto GPA of the copy");
        info!("Contents of gRT->GetTime: {:#x?}", unsafe { *(get_time_addr as *mut usize) });
        if cfg!(feature = "protect_translation") {
            info!("                          ^^^^^^^^^^ would have been {hooked_get_time:#x?} without HLAT");
        }
        info!("Calling gRT->GetTime");
        info!("    >> {:#x?}", rt.get_time().unwrap());
        if cfg!(feature = "protect_translation") {
            info!("       ^ would have called a hooked GetTime() without HLAT");

            wrmsr(SYNTHETIC_IA32_UNLOCK_TRANSLATION_OF_PAGE, 0);
            info!("=== Disabled HLAT ===");
            info!("Contents of gRT->GetTime: {:#x?}", unsafe { *(get_time_addr as *mut usize) });
            info!("Calling gRT->GetTime");
            info!("    >> {:#x?}", rt.get_time().unwrap());
        }
    }

    if cfg!(feature = "hook") {
        info!("Hooking gRT->GetTime at GPA {get_time_addr:#x?}");
        unsafe { *(get_time_addr as *mut usize) = hooked_get_time as usize };
        info!("{:#x?}", rt.get_time().unwrap());
    }
}

fn remap_runtime_services() -> usize {
    let st = unsafe { system_table().as_ref() };
    let addr_of_st = st.runtime_services() as *const _ as usize;

    // Compute the indexes used to translate the LA of RuntimeServices.
    let i4 = addr_of_st >> 39 & 0b1_1111_1111;
    let i3 = addr_of_st >> 30 & 0b1_1111_1111;
    let i2 = addr_of_st >> 21 & 0b1_1111_1111;
    let i1 = addr_of_st >> 12 & 0b1_1111_1111;

    // Locate PML4e, PDPTe and PDe used to translate the LA of RuntimeServices.
    let pml4 = (cr3() & !0xfff) as *mut Pml4;
    let pml4 = unsafe { &mut *pml4 };
    let pdpt = (pml4.entries[i4].pfn() << BASE_PAGE_SHIFT) as *mut Pdpt;
    let pdpt = unsafe { &mut *pdpt };
    let pd2mb = (pdpt.entries[i3].pfn() << BASE_PAGE_SHIFT) as *mut Pd2Mb;
    let pd2mb = unsafe { &mut *pd2mb };
    let pde2mb = &mut pd2mb.entries[i2];

    let cloned_st = if pde2mb.large() {
        // If the PDe is configured as a large page,

        let copy = unsafe { alloc::alloc::alloc(Layout::new::<LargePage>()) } as *mut LargePage;
        if copy.is_null() {
            handle_alloc_error(Layout::new::<LargePage>());
        }
        let large_page_base = addr_of_st & !0x1ff_fff;
        unsafe { core::ptr::copy_nonoverlapping(large_page_base as *const LargePage, copy, 1) };

        let new_pfn = copy as u64 >> LARGE_PAGE_SHIFT;
        debug!("PFN {:#x?} -> {new_pfn:#x?}", pde2mb.pfn());

        let cr0 = cr0();
        cr0_write(cr0 & !Cr0::CR0_WRITE_PROTECT);
        pde2mb.set_pfn(new_pfn);
        cr0_write(cr0);

        copy as usize + (addr_of_st & 0x1ff_fff)
    } else {
        let pde = unsafe { core::mem::transmute::<&mut Pde2Mb, &mut Pde>(pde2mb) };
        let pt = (pde.pfn() << BASE_PAGE_SHIFT) as *mut Pt;
        let pt = unsafe { &mut *pt };
        let pte = &mut pt.entries[i1];

        let copy = unsafe { alloc::alloc::alloc(Layout::new::<Page>()) } as *mut Page;
        if copy.is_null() {
            handle_alloc_error(Layout::new::<Page>());
        }
        let page_base = addr_of_st & !0xfff;
        unsafe { core::ptr::copy_nonoverlapping(page_base as *const Page, copy, 1) };

        let new_pfn = copy as u64 >> BASE_PAGE_SHIFT;
        info!("PFN {:#x?} -> {new_pfn:#x?}", pte.pfn());

        let cr0 = cr0();
        cr0_write(cr0 & !Cr0::CR0_WRITE_PROTECT);
        pte.set_pfn(new_pfn);
        cr0_write(cr0);

        copy as usize + (addr_of_st & 0xfff)
    };
    invlpg(addr_of_st);
    cloned_st
}

fn alias_runtime_services() -> &'static RuntimeServices {
    let st = unsafe { system_table().as_ref() };
    let addr_of_rt = st.runtime_services() as *const _ as u64;
    let large_page_base = addr_of_rt & !0x1ff_fff;

    let alias = 0;

    // Compute the indexes used to translate the LA of RuntimeServices.
    let i4 = alias >> 39 & 0b1_1111_1111;
    let i3 = alias >> 30 & 0b1_1111_1111;
    let i2 = alias >> 21 & 0b1_1111_1111;

    // Locate PML4e, PDPTe and PDe used to translate the LA of RuntimeServices.
    let pml4 = (cr3() & !0xfff) as *mut Pml4;
    let pml4 = unsafe { &mut *pml4 };
    let pdpt = (pml4.entries[i4].pfn() << BASE_PAGE_SHIFT) as *mut Pdpt;
    let pdpt = unsafe { &mut *pdpt };
    let pd2mb = (pdpt.entries[i3].pfn() << BASE_PAGE_SHIFT) as *mut Pd2Mb;
    let pd2mb = unsafe { &mut *pd2mb };
    let pde2mb = &mut pd2mb.entries[i2];

    assert!(pde2mb.large());

    let cr0 = cr0();
    cr0_write(cr0 & !Cr0::CR0_WRITE_PROTECT);
    pde2mb.set_pfn(large_page_base >> LARGE_PAGE_SHIFT);
    cr0_write(cr0);
    invlpg(alias);

    let offset = addr_of_rt & 0x1ff_fff;
    let aliased_rt = alias as u64 + offset;

    info!("Aliased gRT->GetTime onto a new LA {aliased_rt:#x?}");
    unsafe { Box::leak(Box::from_raw(aliased_rt as *mut RuntimeServices)) }
}

unsafe extern "efiapi" fn hooked_get_time(
    time: *mut Time,
    capabilities: *mut TimeCapabilities,
) -> Status {
    unsafe {
        *time = Time::invalid();
        (*capabilities).resolution = 0;
        (*capabilities).accuracy = 0;
        (*capabilities).sets_to_zero = false;
    }
    info!("Hooked GetTime() called");
    Status::SUCCESS
}
