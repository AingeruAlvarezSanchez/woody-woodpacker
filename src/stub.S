.intel_syntax noprefix

.text
.globl woody_stub_start
.globl woody_stub_end

woody_stub_start:

    call .Lget_stub_base
.Lget_stub_base:
    pop r12
    sub r12, 5

    push rdx

    mov eax, 1
    mov edi, 1
    lea rsi, [rip + .Lbanner]
    mov edx, 14
    syscall

    mov rax, [rip + .Ltext_rel]
    add rax, r12
    mov rdi, rax

    lea rsi, [rip + .Lkeystream]

    mov rcx, [rip + .Ltext_size]
    test rcx, rcx
    jz .Lskip_decrypt

.Lxor_loop:
    mov al, [rsi]
    xor [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jnz .Lxor_loop

.Lskip_decrypt:

    mov rax, [rip + .Lentry_rel]
    add rax, r12
    pop rdx
    jmp rax

    .p2align 3

.Lbanner:
    .ascii "....WOODY....\n"

.Ltext_rel:
    .quad 0x1111111111111111

.Ltext_size:
    .quad 0x2222222222222222

.Lentry_rel:
    .quad 0x3333333333333333

woody_stub_end:

.Lkeystream:

.att_syntax prefix
