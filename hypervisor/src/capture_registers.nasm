;// The module containing the `capture_registers` function.

;// Offsets to each field in the GuestRegisters struct.
.set registers_rax, 0x0
.set registers_rbx, 0x8
.set registers_rcx, 0x10
.set registers_rdx, 0x18
.set registers_rdi, 0x20
.set registers_rsi, 0x28
.set registers_rbp, 0x30
.set registers_r8,  0x38
.set registers_r9,  0x40
.set registers_r10, 0x48
.set registers_r11, 0x50
.set registers_r12, 0x58
.set registers_r13, 0x60
.set registers_r14, 0x68
.set registers_r15, 0x70
.set registers_rflags, 0x78
.set registers_rsp, 0x80
.set registers_rip, 0x88

;// Captures current general purpose registers, RFLAGS, RSP, and RIP.
;//
;// extern "efiapi" fn capture_registers(registers: &mut GuestRegisters);
.global capture_registers
capture_registers:
    ;// Capture general purpose registers.
    mov     [rcx + registers_rax], rax
    mov     [rcx + registers_rbx], rbx
    mov     [rcx + registers_rcx], rcx
    mov     [rcx + registers_rdx], rdx
    mov     [rcx + registers_rsi], rsi
    mov     [rcx + registers_rdi], rdi
    mov     [rcx + registers_rbp], rbp
    mov     [rcx + registers_r8],  r8
    mov     [rcx + registers_r9],  r9
    mov     [rcx + registers_r10], r10
    mov     [rcx + registers_r11], r11
    mov     [rcx + registers_r12], r12
    mov     [rcx + registers_r13], r13
    mov     [rcx + registers_r14], r14
    mov     [rcx + registers_r15], r15

    ;// Capture RFLAGS, RSP, and RIP.
    pushfq
    pop     rax
    mov     [rcx + registers_rflags], rax

    mov     rax, rsp
    add     rax, 8
    mov     [rcx + registers_rsp], rax

    mov     rax, [rsp]
    mov     [rcx + registers_rip], rax

    ret
