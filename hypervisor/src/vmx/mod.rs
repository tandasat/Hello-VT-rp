pub(crate) mod descriptors;
pub(crate) mod epts;
pub(crate) mod mtrr;

use alloc::{
    alloc::handle_alloc_error,
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{alloc::Layout, arch::global_asm};
use log::trace;
use x86::{
    controlregs::{Cr0, Cr4},
    current::{paging::BASE_PAGE_SIZE, rflags::RFlags},
    dtables::DescriptorTablePointer,
    segmentation::{cs, ds, es, fs, gs, ss, SegmentSelector},
    vmx::vmcs,
};

use crate::{
    paging_structures::{initialize_paging_structures, PagingStructures},
    x86_instructions::{
        cr0, cr0_write, cr3, cr4, cr4_write, lar, lgdt, load_tr, lsl, rdmsr, sgdt, sidt, tr, wrmsr,
    },
    GuestRegisters,
};

use self::{
    descriptors::Descriptors,
    epts::{initialize_epts, Epts},
};

pub(crate) struct Vmx {
    vmxon_region: Vmxon,
    vmx_enabled: bool,
    original_gdtr: DescriptorTablePointer<u64>,
    host_descriptors: Descriptors,
}
impl Vmx {
    pub(crate) fn new() -> Self {
        let vmxon_region = Vmxon {
            revision_id: rdmsr(x86::msr::IA32_VMX_BASIC) as u32,
            ..Default::default()
        };
        trace!("{:#x?}", vmxon_region);

        Self {
            vmxon_region,
            vmx_enabled: false,
            original_gdtr: sgdt(),
            host_descriptors: Descriptors::new_from_current(),
        }
    }
    pub(crate) fn enable(&mut self) {
        Self::adjust_cr0();
        Self::adjust_cr4();
        Self::adjust_feature_control_msr();
        vmxon(&mut self.vmxon_region);
        self.vmx_enabled = true;
        self.adjust_gdt();
    }

    fn adjust_gdt(&self) {
        // UEFI does not set TSS in the GDT. This is incompatible to be both as VM
        // and hypervisor states.
        // See: 27.2.3 Checks on Host Segment and Descriptor-Table Registers
        // See: 27.3.1.2 Checks on Guest Segment Registers
        assert!(tr().bits() == 0);

        // So, let us update the GDTR with the new GDT that is a copy of the current
        // GDT plus TSS, as well as TR.
        lgdt(&self.host_descriptors.gdtr);
        load_tr(self.host_descriptors.tr);
    }

    /// Updates the CR0 to satisfy the requirement for entering VMX operation.
    fn adjust_cr0() {
        // In order to enter VMX operation, some bits in CR0 (and CR4) have to be
        // set or cleared as indicated by the FIXED0 and FIXED1 MSRs. The rule is
        // summarized as below (taking CR0 as an example):
        //
        //        IA32_VMX_CR0_FIXED0 IA32_VMX_CR0_FIXED1 Meaning
        // Bit X  1                   (Always 1)          The bit X of CR0 is fixed to 1
        // Bit X  0                   1                   The bit X of CR0 is flexible
        // Bit X  (Always 0)          0                   The bit X of CR0 is fixed to 0
        //
        // Some UEFI implementations do not fullfil those requirements for CR0 and
        // need adjustments. The requirements for CR4 are always satisfied as far
        // as the author has experimented (although not guaranteed).
        //
        // See: A.7 VMX-FIXED BITS IN CR0
        // See: A.8 VMX-FIXED BITS IN CR4
        let fixed0cr0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED0);
        let fixed1cr0 = rdmsr(x86::msr::IA32_VMX_CR0_FIXED1);
        let mut new_cr0 = cr0().bits() as u64;
        new_cr0 &= fixed1cr0;
        new_cr0 |= fixed0cr0;
        let new_cr0 = Cr0::from_bits_truncate(new_cr0 as usize);
        cr0_write(new_cr0);
    }

    /// Updates the CR4 to satisfy the requirement for entering VMX operation.
    fn adjust_cr4() {
        let fixed0cr4 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED0);
        let fixed1cr4 = rdmsr(x86::msr::IA32_VMX_CR4_FIXED1);
        let mut new_cr4 = cr4().bits() as u64;
        new_cr4 &= fixed1cr4;
        new_cr4 |= fixed0cr4;
        let new_cr4 = Cr4::from_bits_truncate(new_cr4 as usize);
        cr4_write(new_cr4);
    }

    /// Updates an MSR to satisfy the requirement for entering VMX operation.
    fn adjust_feature_control_msr() {
        const IA32_FEATURE_CONTROL_LOCK_BIT_FLAG: u64 = 1 << 0;
        const IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG: u64 = 1 << 2;

        // If the lock bit is cleared, set it along with the VMXON-outside-SMX
        // operation bit. Without those two bits, the VMXON instruction fails. They
        // are normally set but not always, for example, Bochs with OVFM does not.
        // See: 23.7 ENABLING AND ENTERING VMX OPERATION
        let feature_control = rdmsr(x86::msr::IA32_FEATURE_CONTROL);
        if (feature_control & IA32_FEATURE_CONTROL_LOCK_BIT_FLAG) == 0 {
            wrmsr(
                x86::msr::IA32_FEATURE_CONTROL,
                feature_control
                    | IA32_FEATURE_CONTROL_ENABLE_VMX_OUTSIDE_SMX_FLAG
                    | IA32_FEATURE_CONTROL_LOCK_BIT_FLAG,
            );
        }
    }
}

impl Drop for Vmx {
    fn drop(&mut self) {
        if self.vmx_enabled {
            vmxoff();
            lgdt(&self.original_gdtr);
            load_tr(SegmentSelector::from_raw(0));
        }
    }
}

pub(crate) enum VmExitReason {
    Cpuid,
    Rdmsr,
    Wrmsr,
    XSetBv,
}

pub(crate) struct Vm {
    paging_structures: Box<PagingStructures>,
    _idt: Vec<u64>, // TODO: may be static array
    _idtr: DescriptorTablePointer<u64>,
    pub(crate) regs: GuestRegisters,
    pub(crate) epts: Box<Epts>,
    launched: bool,
    descriptors: Descriptors,
    vmcs: Box<Vmcs>,
}

impl Vm {
    pub(crate) fn new() -> Self {
        let layout = Layout::new::<Epts>();
        let epts = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<Epts>();
        if epts.is_null() {
            handle_alloc_error(layout);
        }

        let layout: Layout = Layout::new::<PagingStructures>();
        let ps = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<PagingStructures>();
        if ps.is_null() {
            handle_alloc_error(layout);
        }
        let mut paging_structures = unsafe { Box::from_raw(ps) };
        initialize_paging_structures(paging_structures.as_mut());

        let mut vmcs = Box::<Vmcs>::default();
        vmcs.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as u32;
        trace!("{vmcs:#x?}");

        Self {
            paging_structures,
            _idt: Vec::new(),
            _idtr: DescriptorTablePointer::<u64>::default(),
            regs: GuestRegisters::default(),
            epts: unsafe { Box::from_raw(epts) },
            launched: false,
            descriptors: Descriptors::new_from_current(),
            vmcs,
        }
    }

    pub(crate) fn activate(&mut self) {
        vmclear(&mut self.vmcs);
        vmptrld(&mut self.vmcs);
    }

    // Set the initial VM state from the current system state.
    pub(crate) fn initialize(&mut self, regs: &GuestRegisters) {
        let idtr = sidt();

        self.regs = *regs;

        vmwrite(vmcs::guest::ES_SELECTOR, es().bits());
        vmwrite(vmcs::guest::CS_SELECTOR, cs().bits());
        vmwrite(vmcs::guest::SS_SELECTOR, ss().bits());
        vmwrite(vmcs::guest::DS_SELECTOR, ds().bits());
        vmwrite(vmcs::guest::FS_SELECTOR, fs().bits());
        vmwrite(vmcs::guest::GS_SELECTOR, gs().bits());
        vmwrite(vmcs::guest::TR_SELECTOR, self.descriptors.tr.bits());
        vmwrite(vmcs::guest::LDTR_SELECTOR, 0u16);

        vmwrite(vmcs::guest::ES_ACCESS_RIGHTS, Self::access_rights_from_native(lar(es())));
        vmwrite(vmcs::guest::CS_ACCESS_RIGHTS, Self::access_rights_from_native(lar(cs())));
        vmwrite(vmcs::guest::SS_ACCESS_RIGHTS, Self::access_rights_from_native(lar(ss())));
        vmwrite(vmcs::guest::DS_ACCESS_RIGHTS, Self::access_rights_from_native(lar(ds())));
        vmwrite(vmcs::guest::FS_ACCESS_RIGHTS, Self::access_rights_from_native(lar(fs())));
        vmwrite(vmcs::guest::GS_ACCESS_RIGHTS, Self::access_rights_from_native(lar(gs())));
        vmwrite(
            vmcs::guest::TR_ACCESS_RIGHTS,
            Self::access_rights_from_native(self.descriptors.tss_ar),
        );
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, Self::access_rights_from_native(0u32));

        vmwrite(vmcs::guest::ES_LIMIT, lsl(es()));
        vmwrite(vmcs::guest::CS_LIMIT, lsl(cs()));
        vmwrite(vmcs::guest::SS_LIMIT, lsl(ss()));
        vmwrite(vmcs::guest::DS_LIMIT, lsl(ds()));
        vmwrite(vmcs::guest::FS_LIMIT, lsl(fs()));
        vmwrite(vmcs::guest::GS_LIMIT, lsl(gs()));
        vmwrite(vmcs::guest::TR_LIMIT, self.descriptors.tss_limit);
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);

        // All segment base registers are assumed to be zero, except that of TR.
        vmwrite(vmcs::guest::TR_BASE, self.descriptors.tss_base);

        vmwrite(vmcs::guest::GDTR_BASE, self.descriptors.gdtr.base as u64);
        vmwrite(vmcs::guest::GDTR_LIMIT, self.descriptors.gdtr.limit);
        vmwrite(vmcs::guest::IDTR_BASE, idtr.base as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, idtr.limit);

        vmwrite(vmcs::guest::IA32_EFER_FULL, rdmsr(x86::msr::IA32_EFER));
        vmwrite(vmcs::guest::CR0, cr0().bits() as u64);
        vmwrite(vmcs::guest::CR3, cr3());
        vmwrite(vmcs::guest::CR4, cr4().bits() as u64);

        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        // Initialize the host part
        let gdtr = sgdt();
        let idtr = sidt();
        vmwrite(vmcs::host::CS_SELECTOR, cs().bits());
        vmwrite(vmcs::host::TR_SELECTOR, tr().bits());
        vmwrite(vmcs::host::CR0, cr0().bits() as u64);
        vmwrite(vmcs::host::CR3, self.paging_structures.as_ref() as *const _ as u64);
        vmwrite(vmcs::host::CR4, cr4().bits() as u64);
        vmwrite(vmcs::host::TR_BASE, Self::segment_base(tr()));
        vmwrite(vmcs::host::GDTR_BASE, gdtr.base as u64);
        vmwrite(vmcs::host::IDTR_BASE, idtr.base as u64);
        vmwrite(
            vmcs::control::VMEXIT_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::VmExit,
                IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_FLAG,
            ),
        );
        vmwrite(
            vmcs::control::VMENTRY_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::VmEntry,
                IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_FLAG,
            ),
        );
        vmwrite(
            vmcs::control::PINBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(VmxControl::PinBased, 0),
        );

        vmwrite(
            vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::ProcessorBased,
                IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG,
            ),
        );
        vmwrite(
            vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::ProcessorBased2,
                IA32_VMX_PROCBASED_CTLS2_ENABLE_EPT_FLAG,
            ),
        );

        // Enable EPT.
        initialize_epts(self.epts.as_mut());
        vmwrite(
            vmcs::control::EPTP_FULL,
            Self::eptp_from_nested_cr3(self.epts.as_ref() as *const _ as u64),
        );
    }

    pub(crate) fn run(&mut self) -> VmExitReason {
        const VMX_EXIT_REASON_CPUID: u16 = 10;
        const VMX_EXIT_REASON_RDMSR: u16 = 31;
        const VMX_EXIT_REASON_WRMSR: u16 = 32;
        const VMX_EXIT_REASON_XSETBV: u16 = 55;

        vmwrite(vmcs::guest::RIP, self.regs.rip);
        vmwrite(vmcs::guest::RSP, self.regs.rsp);
        vmwrite(vmcs::guest::RFLAGS, self.regs.rflags);

        // Execute the VM until VM-exit occurs.
        trace!("Entering the VM");
        let flags = unsafe { run_vmx_vm(&mut self.regs, u64::from(self.launched)) };
        trace!("Exited the VM");
        if let Err(err) = vm_succeed(RFlags::from_raw(flags)) {
            panic!("{err}");
        }
        self.launched = true;
        self.regs.rip = vmread(vmcs::guest::RIP);
        self.regs.rsp = vmread(vmcs::guest::RSP);
        self.regs.rflags = vmread(vmcs::guest::RFLAGS);

        // Return VM-exit reason.
        match vmread(vmcs::ro::EXIT_REASON) as u16 {
            VMX_EXIT_REASON_CPUID => VmExitReason::Cpuid,
            VMX_EXIT_REASON_RDMSR => VmExitReason::Rdmsr,
            VMX_EXIT_REASON_WRMSR => VmExitReason::Wrmsr,
            VMX_EXIT_REASON_XSETBV => VmExitReason::XSetBv,
            _ => panic!("Unhandled VM-exit reason: {:?}", vmread(vmcs::ro::EXIT_REASON)),
        }
    }

    /// Returns an adjust value for the control field according to the
    /// capability MSR.
    pub(crate) fn adjust_vmx_control(control: VmxControl, requested_value: u64) -> u64 {
        const IA32_VMX_BASIC_VMX_CONTROLS_FLAG: u64 = 1 << 55;

        // This determines the right VMX capability MSR based on the value of
        // IA32_VMX_BASIC. This is required to fullfil the following requirements:
        //
        // "It is necessary for software to consult only one of the capability MSRs
        //  to determine the allowed settings of the pin based VM-execution controls:"
        // See: A.3.1 Pin-Based VM-Execution Controls
        let vmx_basic = rdmsr(x86::msr::IA32_VMX_BASIC);
        let true_cap_msr_supported = (vmx_basic & IA32_VMX_BASIC_VMX_CONTROLS_FLAG) != 0;

        let cap_msr = match (control, true_cap_msr_supported) {
            (VmxControl::PinBased, true) => x86::msr::IA32_VMX_TRUE_PINBASED_CTLS,
            (VmxControl::PinBased, false) => x86::msr::IA32_VMX_PINBASED_CTLS,
            (VmxControl::ProcessorBased, true) => x86::msr::IA32_VMX_TRUE_PROCBASED_CTLS,
            (VmxControl::ProcessorBased, false) => x86::msr::IA32_VMX_PROCBASED_CTLS,
            (VmxControl::VmExit, true) => x86::msr::IA32_VMX_TRUE_EXIT_CTLS,
            (VmxControl::VmExit, false) => x86::msr::IA32_VMX_EXIT_CTLS,
            (VmxControl::VmEntry, true) => x86::msr::IA32_VMX_TRUE_ENTRY_CTLS,
            (VmxControl::VmEntry, false) => x86::msr::IA32_VMX_ENTRY_CTLS,
            // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
            // IA32_VMX_PROCBASED_CTLS2 unconditionally.
            (VmxControl::ProcessorBased2, _) => x86::msr::IA32_VMX_PROCBASED_CTLS2,
        };

        // Each bit of the following VMCS values might have to be set or cleared
        // according to the value indicated by the VMX capability MSRs.
        //  - pin-based VM-execution controls,
        //  - primary processor-based VM-execution controls,
        //  - secondary processor-based VM-execution controls.
        //
        // The VMX capability MSR is composed of two 32bit values, the lower 32bits
        // indicate bits can be 0, and the higher 32bits indicates bits can be 1.
        // In other words, if those bits are "cleared", corresponding bits MUST BE 1
        // and MUST BE 0 respectively. The below summarizes the interpretation:
        //
        //        Lower bits (allowed 0) Higher bits (allowed 1) Meaning
        // Bit X  1                      1                       The bit X is flexible
        // Bit X  1                      0                       The bit X is fixed to 0
        // Bit X  0                      1                       The bit X is fixed to 1
        //
        // The following code enforces this logic by setting bits that must be 1,
        // and clearing bits that must be 0.
        //
        // See: A.3.1 Pin-Based VM-Execution Controls
        // See: A.3.2 Primary Processor-Based VM-Execution Controls
        // See: A.3.3 Secondary Processor-Based VM-Execution Controls
        let capabilities = rdmsr(cap_msr);
        let allowed0 = capabilities as u32;
        let allowed1 = (capabilities >> 32) as u32;
        let requested_value = u32::try_from(requested_value).unwrap();
        let mut effective_value = requested_value;
        effective_value |= allowed0;
        effective_value &= allowed1;
        assert!(
            effective_value | requested_value == effective_value,
            "One or more requested features are not supported: {effective_value:#x?} : {requested_value:#x?}"
        );
        u64::from(effective_value)
    }

    fn access_rights_from_native(access_rights: u32) -> u32 {
        const VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG: u32 = 1 << 16;

        if access_rights == 0 {
            return VMX_SEGMENT_ACCESS_RIGHTS_UNUSABLE_FLAG;
        }

        (access_rights >> 8) & 0b1111_0000_1111_1111
    }

    fn eptp_from_nested_cr3(value: u64) -> u64 {
        const EPT_POINTER_MEMORY_TYPE_WRITE_BACK: u64 = 6 /* << 0 */;
        const EPT_POINTER_PAGE_WALK_LENGTH_4: u64 = 3 << 3;

        assert!(value & 0xfff == 0);
        value | EPT_POINTER_PAGE_WALK_LENGTH_4 | EPT_POINTER_MEMORY_TYPE_WRITE_BACK
    }

    fn segment_base(selector: SegmentSelector) -> u64 {
        let current_gdtr = sgdt();
        let current_gdt = unsafe {
            core::slice::from_raw_parts(
                current_gdtr.base.cast::<u64>(),
                usize::from(current_gdtr.limit + 1) / 8,
            )
        };
        let descriptor = current_gdt[selector.index() as usize];
        (descriptor >> 16 & 0xff_ffff) | (descriptor >> 32 & 0xff00_0000)
    }
}

/// The region of memory that the logical processor uses to support VMX
/// operation.
///
/// See: 25.11.5 VMXON Region
#[derive(derivative::Derivative)]
#[derivative(Default, Debug)]
#[repr(C, align(4096))]
struct Vmxon {
    revision_id: u32,
    #[derivative(Default(value = "[0; 4092]"), Debug = "ignore")]
    data: [u8; 4092],
}
const _: () = assert!(core::mem::size_of::<Vmxon>() == BASE_PAGE_SIZE);

/// The region of memory that the logical processor uses to represent a virtual
/// CPU. Called virtual-machine control data structure (VMCS).
///
/// See: 25.2 FORMAT OF THE VMCS REGION
#[derive(derivative::Derivative)]
#[derivative(Default, Debug)]
#[repr(C, align(4096))]
struct Vmcs {
    revision_id: u32,
    abort_indicator: u32,
    #[derivative(Default(value = "[0; 4088]"), Debug = "ignore")]
    data: [u8; 4088],
}
const _: () = assert!(core::mem::size_of::<Vmcs>() == BASE_PAGE_SIZE);

/// The wrapper of the VMXON instruction.
fn vmxon(vmxon_region: &mut Vmxon) {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmxon(vmxon_region as *mut _ as u64).unwrap() };
}

/// The wrapper of the VMXOFF instruction.
fn vmxoff() {
    // Safety: this project runs at CPL0.
    unsafe { x86::current::vmx::vmxoff().unwrap() };
}

/// The wrapper of the VMCLEAR instruction.
fn vmclear(vmcs_region: &mut Vmcs) {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmclear(vmcs_region as *mut _ as u64).unwrap() };
}

/// The wrapper of the VMPTRLD instruction.
fn vmptrld(vmcs_region: &mut Vmcs) {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region as *mut _ as u64).unwrap() }
}

/// The wrapper of the VMREAD instruction. Returns zero on error.
pub(crate) fn vmread(encoding: u32) -> u64 {
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmread(encoding).unwrap() }
}

/// The wrapper of the VMWRITE instruction.
pub(crate) fn vmwrite<T: Into<u64>>(encoding: u32, value: T)
where
    u64: From<T>,
{
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmwrite(encoding, u64::from(value)) }.unwrap();
}

/// Checks that the latest VMX instruction succeeded.
///
/// See: 31.2 CONVENTIONS
pub(crate) fn vm_succeed(flags: RFlags) -> Result<(), String> {
    if flags.contains(RFlags::FLAGS_ZF) {
        // See: 31.4 VM INSTRUCTION ERROR NUMBERS
        Err(format!("VmFailValid with {}", vmread(vmcs::ro::VM_INSTRUCTION_ERROR)))
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err("VmFailInvalid".to_string())
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    VmExit,
    VmEntry,
}

extern "efiapi" {
    /// Runs the VM until VM-exit occurs.
    fn run_vmx_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}
global_asm!(include_str!("run_vmx_vm.nasm"));

// See: Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls
pub(crate) const IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG: u64 = 1 << 31;

// See: Table 25-7. Definitions of Secondary Processor-Based VM-Execution
// Controls
pub(crate) const IA32_VMX_PROCBASED_CTLS2_ENABLE_EPT_FLAG: u64 = 1 << 1;

// See: Table 25-13. Definitions of Primary VM-Exit Controls
pub(crate) const IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_FLAG: u64 = 1 << 9;

// See: Table 25-15. Definitions of VM-Entry Controls
pub(crate) const IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_FLAG: u64 = 1 << 9;
