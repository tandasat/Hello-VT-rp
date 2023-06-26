;// Executes VMCALL instruction.
;//
;// extern "C" fn vmcall(number: u64, rdx: u64, r8: u64, r9: u64) -> u64;
.global vmcall
vmcall:
    vmcall
    ret
