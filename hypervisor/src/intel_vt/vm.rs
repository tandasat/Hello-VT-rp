use alloc::{
    alloc::handle_alloc_error,
    boxed::Box,
    format,
    string::{String, ToString},
};
use core::{alloc::Layout, arch::global_asm};
use log::trace;
use x86::{
    current::{paging::BASE_PAGE_SIZE, rflags::RFlags},
    segmentation::{cs, ds, es, fs, gs, ss},
    vmx::vmcs,
};

use super::{descriptors::Descriptors, epts::Epts, hlat};
use crate::{
    paging_structures::PagingStructures,
    x86_instructions::{cr0, cr3, cr4, lar, lsl, rdmsr, sidt},
    GuestRegisters, Page,
};

pub(crate) enum VmExitReason {
    Cpuid,
    Rdmsr,
    Wrmsr,
    XSetBv,
    Vmcall,
}

pub(crate) struct Vm {
    pub(crate) regs: GuestRegisters,
    pub(crate) epts: Box<Epts>,
    pub(crate) hlat: Box<hlat::PagingStructures>,
    host_paging_structures: Box<PagingStructures>,
    host_descriptors: Descriptors,
    launched: bool,
    descriptors: Descriptors,
    vmcs: Box<Vmcs>,
    msr_bitmaps: Box<Page>,
}

impl Vm {
    pub(crate) fn new() -> Self {
        let mut vmcs = Box::<Vmcs>::default();
        vmcs.revision_id = rdmsr(x86::msr::IA32_VMX_BASIC) as u32;
        trace!("{vmcs:#x?}");

        let mut host_paging_structures = unsafe { box_zeroed::<PagingStructures>() };
        host_paging_structures.build_identity();

        let mut epts = unsafe { box_zeroed::<Epts>() };
        epts.build_identify();

        Self {
            regs: GuestRegisters::default(),
            epts,
            hlat: unsafe { box_zeroed::<hlat::PagingStructures>() },
            host_paging_structures,
            host_descriptors: Descriptors::new_for_host(),
            launched: false,
            descriptors: Descriptors::new_from_current(),
            vmcs,
            msr_bitmaps: unsafe { box_zeroed::<Page>() },
        }
    }

    pub(crate) fn activate(&mut self) {
        vmclear(&mut self.vmcs);
        vmptrld(&mut self.vmcs);
    }

    // Set the initial VM state from the current system state.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn initialize(&mut self, regs: &GuestRegisters) {
        self.epts
            .make_2mb_read_only(self.hlat.as_ref() as *const _ as u64);

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
            Self::access_rights_from_native(self.descriptors.tss.ar),
        );
        vmwrite(vmcs::guest::LDTR_ACCESS_RIGHTS, Self::access_rights_from_native(0u32));

        vmwrite(vmcs::guest::ES_LIMIT, lsl(es()));
        vmwrite(vmcs::guest::CS_LIMIT, lsl(cs()));
        vmwrite(vmcs::guest::SS_LIMIT, lsl(ss()));
        vmwrite(vmcs::guest::DS_LIMIT, lsl(ds()));
        vmwrite(vmcs::guest::FS_LIMIT, lsl(fs()));
        vmwrite(vmcs::guest::GS_LIMIT, lsl(gs()));
        vmwrite(vmcs::guest::TR_LIMIT, self.descriptors.tss.limit);
        vmwrite(vmcs::guest::LDTR_LIMIT, 0u32);

        // All segment base registers are assumed to be zero, except that of TR.
        vmwrite(vmcs::guest::TR_BASE, self.descriptors.tss.base);

        vmwrite(vmcs::guest::GDTR_BASE, self.descriptors.gdtr.base as u64);
        vmwrite(vmcs::guest::GDTR_LIMIT, self.descriptors.gdtr.limit);
        vmwrite(vmcs::guest::IDTR_BASE, idtr.base as u64);
        vmwrite(vmcs::guest::IDTR_LIMIT, idtr.limit);

        vmwrite(vmcs::guest::IA32_EFER_FULL, rdmsr(x86::msr::IA32_EFER));
        vmwrite(vmcs::guest::CR0, cr0().bits() as u64);
        vmwrite(vmcs::guest::CR3, cr3());
        vmwrite(vmcs::guest::CR4, cr4().bits() as u64);

        vmwrite(vmcs::guest::LINK_PTR_FULL, u64::MAX);

        // Initialize the host part.
        vmwrite(vmcs::host::CS_SELECTOR, self.host_descriptors.cs.bits());
        vmwrite(vmcs::host::TR_SELECTOR, self.host_descriptors.tr.bits());
        vmwrite(vmcs::host::CR0, cr0().bits() as u64);
        vmwrite(vmcs::host::CR3, self.host_paging_structures.as_ref() as *const _ as u64);
        vmwrite(vmcs::host::CR4, cr4().bits() as u64);
        vmwrite(vmcs::host::TR_BASE, self.host_descriptors.tss.base);
        vmwrite(vmcs::host::GDTR_BASE, self.host_descriptors.gdtr.base as u64);
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
                IA32_VMX_PROCBASED_CTLS_USE_MSR_BITMAPS_FLAG
                    | IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG,
            ),
        );
        vmwrite(
            vmcs::control::SECONDARY_PROCBASED_EXEC_CONTROLS,
            Self::adjust_vmx_control(
                VmxControl::ProcessorBased2,
                IA32_VMX_PROCBASED_CTLS2_ENABLE_EPT_FLAG
                    | IA32_VMX_PROCBASED_CTLS2_ENABLE_RDTSCP_FLAG
                    | IA32_VMX_PROCBASED_CTLS2_ENABLE_INVPCID_FLAG
                    | IA32_VMX_PROCBASED_CTLS2_ENABLE_XSAVES_FLAG,
            ),
        );

        fn write_protect(bitmap: &mut Page, msr: usize) {
            assert!(msr < 0x2000);
            let byte_offset = msr / 8 + 2048;
            let byte = &mut bitmap.0[byte_offset];
            let bit_pos_in_byte = msr % 8;
            *byte |= 1 << bit_pos_in_byte;
        }

        write_protect(self.msr_bitmaps.as_mut(), 0x17d0);
        write_protect(self.msr_bitmaps.as_mut(), 0x17d1);
        vmwrite(vmcs::control::MSR_BITMAPS_ADDR_FULL, self.msr_bitmaps.as_ref() as *const _ as u64);
        vmwrite(
            vmcs::control::EPTP_FULL,
            Self::eptp_from_nested_cr3(self.epts.as_ref() as *const _ as u64),
        );

        if cfg!(feature = "enable_vt_rp") {
            vmwrite(
                vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
                Self::adjust_vmx_control(
                    VmxControl::ProcessorBased,
                    IA32_VMX_PROCBASED_CTLS_ACTIVATE_TERTIARY_CONTROLS_FLAG
                        | vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS),
                ),
            );
            vmwrite(
                VMCS_CTRL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                Self::adjust_vmx_control(
                    VmxControl::ProcessorBased3,
                    IA32_VMX_PROCBASED_CTLS3_ENABLE_HLAT_FLAG,
                ),
            );
            vmwrite(VMCS_CTRL_HLAT_POINTER, self.hlat.as_ref() as *const _ as u64);
            self.hlat.deactivate();
        }
    }

    pub(crate) fn run(&mut self) -> VmExitReason {
        const VMX_EXIT_REASON_CPUID: u16 = 10;
        const VMX_EXIT_REASON_VMCALL: u16 = 18;
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
            VMX_EXIT_REASON_VMCALL => VmExitReason::Vmcall,
            VMX_EXIT_REASON_RDMSR => VmExitReason::Rdmsr,
            VMX_EXIT_REASON_WRMSR => VmExitReason::Wrmsr,
            VMX_EXIT_REASON_XSETBV => VmExitReason::XSetBv,
            _ => panic!("Unhandled VM-exit reason: {:?}", vmread(vmcs::ro::EXIT_REASON)),
        }
    }

    /// Returns an adjust value for the control field according to the
    /// capability MSR.
    fn adjust_vmx_control(control: VmxControl, requested_value: u64) -> u64 {
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
            (VmxControl::ProcessorBased3, _) => {
                const IA32_VMX_PROCBASED_CTLS3: u32 = 0x492;

                let allowed1 = rdmsr(IA32_VMX_PROCBASED_CTLS3);
                let effective_value = requested_value & allowed1;
                assert!(
                    effective_value | requested_value == effective_value,
                    "One or more requested features are not supported: {effective_value:#x?} : {requested_value:#x?} "
                );
                return effective_value;
            }
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
            "One or more requested features are not supported for {control:?}: {effective_value:#x?} vs {requested_value:#x?}"
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

        assert!(value.trailing_zeros() >= 12);
        value | EPT_POINTER_PAGE_WALK_LENGTH_4 | EPT_POINTER_MEMORY_TYPE_WRITE_BACK
    }
}

unsafe fn box_zeroed<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>();
    if ptr.is_null() {
        handle_alloc_error(layout);
    }
    unsafe { Box::from_raw(ptr) }
}

#[derive(Clone, Copy, Debug)]
enum VmxControl {
    PinBased,
    ProcessorBased,
    ProcessorBased2,
    ProcessorBased3,
    VmExit,
    VmEntry,
}

extern "efiapi" {
    /// Runs the VM until VM-exit occurs.
    fn run_vmx_vm(registers: &mut GuestRegisters, launched: u64) -> u64;
}
global_asm!(include_str!("run_vmx_vm.S"));

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
    let val = u64::from(value);
    // Safety: this project runs at CPL0.
    unsafe { x86::bits64::vmx::vmwrite(encoding, val) }
        .unwrap_or_else(|_| panic!("Could not write {val:x?} to {encoding:x?}"));
}

/// Checks that the latest VMX instruction succeeded.
///
/// See: 31.2 CONVENTIONS
fn vm_succeed(flags: RFlags) -> Result<(), String> {
    if flags.contains(RFlags::FLAGS_ZF) {
        // See: 31.4 VM INSTRUCTION ERROR NUMBERS
        Err(format!("VmFailValid with {}", vmread(vmcs::ro::VM_INSTRUCTION_ERROR)))
    } else if flags.contains(RFlags::FLAGS_CF) {
        Err("VmFailInvalid".to_string())
    } else {
        Ok(())
    }
}

// See: Table 25-6. Definitions of Primary Processor-Based VM-Execution Controls
const IA32_VMX_PROCBASED_CTLS_ACTIVATE_TERTIARY_CONTROLS_FLAG: u64 = 1 << 17;
const IA32_VMX_PROCBASED_CTLS_USE_MSR_BITMAPS_FLAG: u64 = 1 << 28;
const IA32_VMX_PROCBASED_CTLS_ACTIVATE_SECONDARY_CONTROLS_FLAG: u64 = 1 << 31;

// See: Table 25-7. Definitions of Secondary Processor-Based VM-Execution
// Controls
const IA32_VMX_PROCBASED_CTLS2_ENABLE_EPT_FLAG: u64 = 1 << 1;
const IA32_VMX_PROCBASED_CTLS2_ENABLE_RDTSCP_FLAG: u64 = 1 << 3;
const IA32_VMX_PROCBASED_CTLS2_ENABLE_INVPCID_FLAG: u64 = 1 << 12;
const IA32_VMX_PROCBASED_CTLS2_ENABLE_XSAVES_FLAG: u64 = 1 << 20;

// See: Table 25-8. Definitions of Tertiary Processor-Based VM-Execution
// Controls
const IA32_VMX_PROCBASED_CTLS3_ENABLE_HLAT_FLAG: u64 = 1 << 1;
const _IA32_VMX_PROCBASED_CTLS3_EPT_PAGING_WRITE_CONTROL_FLAG: u64 = 1 << 2;
const _IA32_VMX_PROCBASED_CTLS3_GUEST_PAGING_VERIFICATION_FLAG: u64 = 1 << 3;

// See: Table 25-13. Definitions of Primary VM-Exit Controls
const IA32_VMX_EXIT_CTLS_HOST_ADDRESS_SPACE_SIZE_FLAG: u64 = 1 << 9;

// See: Table 25-15. Definitions of VM-Entry Controls
const IA32_VMX_ENTRY_CTLS_IA32E_MODE_GUEST_FLAG: u64 = 1 << 9;

// See: APPENDIX B FIELD ENCODING IN VMCS
const VMCS_CTRL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS: u32 = 0x2034;
const VMCS_CTRL_HLAT_POINTER: u32 = 0x2040;
