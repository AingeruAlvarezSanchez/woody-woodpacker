.intel_syntax noprefix

.text
.globl woody_stub_start
.globl woody_stub_end

woody_stub_start:

    # r12 = runtime address of woody_stub_start
    call .Lget_stub_base

.Lget_stub_base:
    pop r12
    sub r12, 5

    # Linux startup value, preserve it
    push rdx

    # write
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lbanner]
    mov edx, 14
    syscall


.Lbanner:
    .ascii "....WOODY....\n"

    .p2align 3

.Ltext_rel:
    .quad 0x1111111111111111

.Ltext_size:
    .quad 0x2222222222222222

.Lxor_key:
    .quad 0x3333333333333333

.Lentry_rel:
    .quad 0x4444444444444444


woody_stub_end:

.att_syntax prefix
