// TODO: consider using x86's paging structures

use bitfield::bitfield;

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Pml4 {
    pub(crate) entries: [Pml4e; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Pdpt {
    pub(crate) entries: [Pdpte; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Pd2Mb {
    pub(crate) entries: [Pde2Mb; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Pd {
    pub(crate) entries: [Pde; 512],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, align(4096))]
pub(crate) struct Pt {
    pub(crate) entries: [Pte; 512],
}

bitfield! {
    /// Table 4-15. Format of a PML4 Entry (PML4E) that References a Page-Directory-Pointer Table
    #[derive(Clone, Copy)]
    pub struct Pml4e(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, _: 1;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 4-17. Format of a Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory
    #[derive(Clone, Copy)]
    pub struct Pdpte(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, _: 1;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page
    #[derive(Clone, Copy)]
    pub struct Pde2Mb(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub large, _: 7;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 21;
}

bitfield! {
    /// Table 4-19. Format of a Page-Directory Entry that References a Page Table
    #[derive(Clone, Copy)]
    pub struct Pde(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub large, _: 7;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 12;
}

bitfield! {
    /// Table 4-20. Format of a Page-Table Entry that Maps a 4-KByte Page
    #[derive(Clone, Copy)]
    pub struct Pte(u64);
    impl Debug;
    pub present, set_present: 0;
    pub writable, set_writable: 1;
    pub restart, set_restart: 11;
    pub pfn, set_pfn: 51, 12;
}
