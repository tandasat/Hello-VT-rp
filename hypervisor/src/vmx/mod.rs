mod descriptors; // FIXME: delete those.
mod epts;
pub(crate) mod hlat;
mod mtrr;
pub(crate) mod vm;
pub(crate) mod vmx;

pub(crate) enum VmExitReason {
    Cpuid,
    Rdmsr,
    Wrmsr,
    XSetBv,
    Vmcall,
}
