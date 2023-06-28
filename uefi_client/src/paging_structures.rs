use bitfield::bitfield;

#[derive(Debug, Clone, Copy)]
#[repr(C, align(0x20_0000))]
pub(crate) struct LargePage([u8; 0x20_0000]);

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
    pub large, set_large: 7;
    pub pfn, set_pfn: 51, 12;
}
