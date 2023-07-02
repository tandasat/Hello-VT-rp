# Enabling VT-rp

This document summarizes how this hypervisor enables each VT-rp features.


## Hypervisor-managed Linear Address Translation (HLAT)

1. In the host, create paging structures on memory as a hypervisor-managed ones with desired translations. All PML4es have the "Reset" bit set so that HLAT paging is always aborted. See [`intel_vt::hlat::PagingStructures::deactivate`].
2. Enable HLAT by:
   1. setting the "Activate tertiary controls" bit in the primary processor-based VM-execution controls.
   2. setting the "Enable HLAT" bit in the tertiary processor-based VM-execution controls.
   3. setting the GPA of (1) in the HLATP VMCS encoding.
   4. leaving the HLAT prefix size VMCS encoding. This is to ensure all LA will be translated with HLAT paging, if the "Reset" bit is ever cleared.

   See [`intel_vt::vm::Vm::initialize`].
3. On VMCALL 0, update (1) for the given LA. Specifically, remove the "Restart" bit so that HLAT paging completes for the LA (but only for that LA). See [`intel_vt::hlat::PagingStructures::enable_hlat_for_4kb`].

NB:
- Normally, the hypervisor-managed paging structures should be mapped in GPA with the read-only permission. It is not done by default for demonstration.
- When the hypervisor-managed paging structures are modified, translation caches (eg, TLB) must be invalidated. It is not done explicitly as this project does not enable VPID, and thus, all translation caches are invalidated on VM-exit and -entry.


## Paging Write (PW)

1. Enable PW by setting the "EPT paging-write control" bit in the tertiary processor-based VM-execution controls. See [`intel_vt::vm::Vm::initialize`].
2. On VMCALL 2, locate the leaf EPT entry that corresponds to the GPA of the hypervisor-managed paging structures and set the "paging-write access" bit in the entry. See [`intel_vt::epts::Epts::make_2mb_pw`].


## Guest-Paging Verification (GPV)

1. Enable GPV by setting the "Guest-paging verification" bit in the tertiary processor-based VM-execution controls. See [`intel_vt::vm::Vm::initialize`].
2. On VMCALL 3, set the "verify guest paging" bit in the leaf EPT entry that corresponds to the GPA protected by HLAT, and then, set the "paging-write access" bit in leaf EPT entry that corresponds to the GPA of the hypervisor-managed paging structures.
