use log::{debug, info, trace};
use x86::{cpuid::cpuid, vmx::vmcs};

use crate::{
    vmx::{vmread, Vm, VmExitReason, Vmx},
    x86_instructions::{rdmsr, wrmsr},
    GuestRegisters, CPUID_VENDOR_AND_MAX_FUNCTIONS, HLAT_VENDOR_NAME,
};

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
    info!("WRMSR {msr:#x?} {value:#x?}");
    wrmsr(msr, value);

    vm.regs.rip += vmread(vmcs::ro::VMEXIT_INSTRUCTION_LEN);
}
