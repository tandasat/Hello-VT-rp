use alloc::{boxed::Box, vec::Vec};
use x86::{
    dtables::DescriptorTablePointer,
    segmentation::{
        BuildDescriptor, Descriptor, DescriptorBuilder, GateDescriptorBuilder, SegmentSelector,
    },
};

use crate::x86_instructions::sgdt;

//
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub(crate) struct Descriptors {
    gdt: Vec<u64>,
    pub(crate) gdtr: DescriptorTablePointer<u64>,
    // `tss` has to be on heap as `gdt` contains an address of it. Otherwise,
    // copying `VmData` would change the address and invalidate contents of `gdt`.
    #[derivative(Debug = "ignore")]
    tss: Box<TaskStateSegment>,
    pub(crate) tr: SegmentSelector,
    pub(crate) tss_base: u64,
    pub(crate) tss_limit: u32,
    pub(crate) tss_ar: u32,
}
impl Default for Descriptors {
    fn default() -> Self {
        Self {
            gdt: Vec::new(),
            gdtr: DescriptorTablePointer::<u64>::default(),
            tss: Box::new(TaskStateSegment([0; 104])),
            tr: SegmentSelector::from_raw(0),
            tss_base: 0,
            tss_limit: 0,
            tss_ar: 0,
        }
    }
}

impl Descriptors {
    pub(crate) fn new_from_current() -> Self {
        let mut vm_data = Self::default();
        let tss_desc = Self::task_segment_descriptor(vm_data.tss.as_ref());

        let current_gdtr = sgdt();
        let current_gdt = unsafe {
            core::slice::from_raw_parts(
                current_gdtr.base.cast::<u64>(),
                usize::from(current_gdtr.limit + 1) / 8,
            )
        };

        vm_data.gdt = current_gdt.to_vec();
        vm_data.gdt.push(tss_desc.as_u64());
        vm_data.gdt.push(0); // FIXME
        vm_data.gdtr.base = vm_data.gdt.as_ptr();
        vm_data.gdtr.limit = u16::try_from(vm_data.gdt.len() * 8 - 1).unwrap();
        vm_data.tr = SegmentSelector::new(vm_data.gdt.len() as u16 - 2, x86::Ring::Ring0);
        vm_data.tss_base = vm_data.tss.as_ref() as *const _ as u64;
        vm_data.tss_limit = core::mem::size_of_val(vm_data.tss.as_ref()) as u32 - 1;
        vm_data.tss_ar = 0x8b00;
        vm_data
    }

    /// Builds a segment descriptor from the task state segment.
    fn task_segment_descriptor(tss: &TaskStateSegment) -> Descriptor {
        let tss_base = tss as *const _ as u64;
        let tss_size = core::mem::size_of_val(tss) as u64;
        <DescriptorBuilder as GateDescriptorBuilder<u32>>::tss_descriptor(
            tss_base,
            tss_size - 1,
            true,
        )
        .present()
        .dpl(x86::Ring::Ring0)
        .finish()
    }
}

/// See: Figure 8-11. 64-Bit TSS Format
struct TaskStateSegment([u8; 104]);
