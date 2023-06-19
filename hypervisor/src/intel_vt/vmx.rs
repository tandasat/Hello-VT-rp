use x86::{
    controlregs::{Cr0, Cr4},
    current::paging::BASE_PAGE_SIZE,
};

use crate::x86_instructions::{cr0, cr0_write, cr4, cr4_write, rdmsr, wrmsr};

pub(crate) struct Vmx {
    vmxon_region: Vmxon,
    vmx_enabled: bool,
}
impl Vmx {
    pub(crate) fn new() -> Self {
        Self {
            vmxon_region: Vmxon::default(),
            vmx_enabled: false,
        }
    }

    pub(crate) fn enable(&mut self) {
        Self::adjust_cr0();
        Self::adjust_cr4();
        Self::adjust_feature_control_msr();
        vmxon(&mut self.vmxon_region);
        self.vmx_enabled = true;
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
        }
    }
}

/// The region of memory that the logical processor uses to support VMX
/// operation.
///
/// See: 25.11.5 VMXON Region
#[derive(derivative::Derivative)]
#[derivative(Debug)]
#[repr(C, align(4096))]
struct Vmxon {
    revision_id: u32,
    #[derivative(Debug = "ignore")]
    data: [u8; 4092],
}
impl Default for Vmxon {
    fn default() -> Self {
        Self {
            revision_id: rdmsr(x86::msr::IA32_VMX_BASIC) as u32,
            data: [0; 4092],
        }
    }
}
const _: () = assert!(core::mem::size_of::<Vmxon>() == BASE_PAGE_SIZE);

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
