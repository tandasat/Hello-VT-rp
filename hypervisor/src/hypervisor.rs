use log::{debug, trace, warn};
use x86::{cpuid::cpuid, vmx::vmcs};

use crate::{
    vmx::{
        epts::{enable_guest_paging_verification, set_writable, write_protect},
        hlat::protect_linear_address,
        vmread, vmwrite, Vm, VmExitReason, Vmx, VmxControl,
        IA32_VMX_PROCBASED_CTLS_MONITOR_TRAP_FLAG_FLAG,
        VMCS_CTRL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
    },
    x86_instructions::{rdmsr, wrmsr},
    GuestRegisters, CPUID_VENDOR_AND_MAX_FUNCTIONS, HLAT_VENDOR_NAME,
};

// "MSR address range between 40000000H - 4000FFFFH is marked as a specially
// reserved range. All existing and future processors will not implement any
// features using any MSR in this range."
// See: 2.1 ARCHITECTURAL MSRS
pub(crate) const SYNTHETIC_IA32_WRITE_PROTECT_PAGE: u32 = 0x40000000;
pub(crate) const SYNTHETIC_IA32_LOCK_TRANSLATION_OF_PAGE: u32 = 0x40000001;
pub(crate) const SYNTHETIC_IA32_UNLOCK_TRANSLATION_OF_PAGE: u32 = 0x40000002;
pub(crate) const SYNTHETIC_IA32_VERIFY_TRANSLATION_OF_PAGE: u32 = 0x40000003;

pub(crate) fn start_hypervisor(regs: &GuestRegisters) -> ! {
    debug!("Enabling virtualization extension");
    let mut vmx = Vmx::new();
    vmx.enable();

    // Create a new (empty) VM instance and tell the processor to operate on it.
    let vm = &mut Vm::new();
    vm.activate();
    vm.initialize(regs);

    debug!("Starting the VM");
    loop {
        // Then, run the VM until events we (hypervisor) need to handle.
        match vm.run() {
            VmExitReason::Cpuid => handle_cpuid(vm),
            VmExitReason::Rdmsr => handle_rdmsr(vm),
            VmExitReason::Wrmsr => handle_wrmsr(vm),
            VmExitReason::MonitorTrapFlag => handle_mtf(vm),
            VmExitReason::EptViolation => handle_ept_violation(vm),
        }
    }
}

fn handle_cpuid(vm: &mut Vm) {
    let leaf = vm.regs.rax as u32;
    let sub_leaf = vm.regs.rcx as u32;
    trace!("CPUID {leaf:#x?} {sub_leaf:#x?}");
    let mut regs = cpuid!(leaf, sub_leaf);

    // Indicate that the hypervisor is present relevant CPUID is asked.
    if leaf == CPUID_VENDOR_AND_MAX_FUNCTIONS {
        regs.ebx = HLAT_VENDOR_NAME;
        regs.ecx = HLAT_VENDOR_NAME;
        regs.edx = HLAT_VENDOR_NAME;
    }

    vm.regs.rax = regs.eax as u64;
    vm.regs.rbx = regs.ebx as u64;
    vm.regs.rcx = regs.ecx as u64;
    vm.regs.rdx = regs.edx as u64;
    vm.regs.rip += vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
}

fn handle_rdmsr(vm: &mut Vm) {
    let msr = vm.regs.rcx as u32;
    trace!("RDMSR {msr:#x?}");
    let value = rdmsr(msr);

    vm.regs.rax = value & 0xffff_ffff;
    vm.regs.rdx = value >> 32;
    vm.regs.rip += vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
}

fn handle_wrmsr(vm: &mut Vm) {
    let msr = vm.regs.rcx as u32;
    let value = (vm.regs.rax & 0xffff_ffff) | ((vm.regs.rdx & 0xffff_ffff) << 32);
    trace!("WRMSR {msr:#x?} {value:#x?}");

    match msr {
        SYNTHETIC_IA32_WRITE_PROTECT_PAGE => {
            let addr = value & 0x000f_ffff_ffff_ffff;
            let size = value >> 51;
            assert!(size != 0 && size < 0x1000);
            assert!(vm.protected_gpa.end == 0);
            write_protect(vm.epts.as_mut(), addr);
            vm.protected_gpa = addr..addr + size;
            debug!("Protected GPA {:#x?}", vm.protected_gpa);
        }
        SYNTHETIC_IA32_LOCK_TRANSLATION_OF_PAGE => {
            assert!(vm.protected_la.end == 0);
            vm.protected_la = protect_linear_address(vm.hlat.as_mut(), value);
            if cfg!(feature = "enable_vt_rp") {
                debug!("Protected LA {:#x?}", vm.protected_la);
            } else {
                warn!("VT-rp is disabled");
            }
        }
        SYNTHETIC_IA32_UNLOCK_TRANSLATION_OF_PAGE => {
            // Disable all VT-rp features.
            assert!(vm.protected_la.end != 0);
            vmwrite(
                VMCS_CTRL_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
                Vm::adjust_vmx_control(VmxControl::ProcessorBased3, 0),
            );
        }
        SYNTHETIC_IA32_VERIFY_TRANSLATION_OF_PAGE => {
            enable_guest_paging_verification(vm.epts.as_mut(), value);
            if cfg!(feature = "enable_vt_rp") {
                debug!("Verify requested for LA {value:#x?}");
            } else {
                warn!("VT-rp is disabled");
            }
        }
        _ => wrmsr(msr, value),
    }

    vm.regs.rip += vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
}

fn handle_mtf(vm: &mut Vm) {
    // Make the page non-writable again and disable MTF.
    let index = vm.protected_gpa.start >> 12 & 0b1_1111_1111;
    set_writable(&mut vm.epts, index, false);
    vmwrite(
        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
        Vm::adjust_vmx_control(
            VmxControl::ProcessorBased,
            vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS)
                & !IA32_VMX_PROCBASED_CTLS_MONITOR_TRAP_FLAG_FLAG,
        ),
    );
    debug!("MTF {:#x?}", vm.regs.rip);
}

fn handle_ept_violation(vm: &mut Vm) {
    let gpa = vmread(vmcs::ro::GUEST_PHYSICAL_ADDR_FULL);
    if vm.protected_gpa.contains(&gpa) || vm.protected_gpa.contains(&(gpa + 8)) {
        panic!("Protected region {gpa:#x?} being written");
    }

    let qualification = vmread(vmcs::ro::EXIT_QUALIFICATION);
    debug!("EPT {:#x?}: {gpa:#x?} {qualification:#x?}", vm.regs.rip);

    // Table 28-7. Exit Qualification for EPT Violations
    if qualification & (1 << 15) != 0 {
        panic!("Paging write verification failed");
    }

    // Make the page writable and enable MTF.
    let index = vm.protected_gpa.start >> 12 & 0b1_1111_1111;
    set_writable(&mut vm.epts, index, true);
    vmwrite(
        vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS,
        Vm::adjust_vmx_control(
            VmxControl::ProcessorBased,
            vmread(vmcs::control::PRIMARY_PROCBASED_EXEC_CONTROLS)
                | IA32_VMX_PROCBASED_CTLS_MONITOR_TRAP_FLAG_FLAG,
        ),
    );
}
