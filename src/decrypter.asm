BITS 64

section .text
    global _start

_start:
    push rax                    ; saves the original status of the rax register
    push rdi                    ; saves the original status of the rdi register
    push rsi                    ; saves the original status of the rsi register
    push rdx                    ; saves the original status of the rdx register

    mov rax, 1                  ; write syscall number
    mov rdi, 1                  ; 1st argument of the write syscall, the fd, 1 = STDOUT
    lea rsi, [rel msg]          ; 2nd argument of the write syscall, the msg
    mov rdx, mlen               ; 3rd argument of the write syscall, len of the msg
    syscall                     ; prints "....WOODY...."

    mov r12, [rel count]        ; move the total address count to modify to r12
    lea r13, [rel regions]      ; initial address to override
    lea r14, [rel _start]       ; moves the runtime address of the program to r14
    call decrypt

    pop rdx                     ; restores the original status of the rdx register
    pop rsi                     ; restores the original status of the rsi register
    pop rdi                     ; restores the original status of the rdi register
    pop rax                     ; restores the original status of the rax register

    lea rax, [rel _start]       ; puts the address of the program into rax
    add rax, [rel oe]           ; adds the overwritten oe variable value nto rax
    jmp rax                     ; jumps back to the starting point of the original code

decrypt:
    mov rax, 10                 ; mprotect syscall number

    mov rdi, [r13]              ; moves the current target address (without calculation) to rdi
    add rdi, r14                ; adds the runtime address to point to the right address

    mov r8, rdi                 ; moves the calculated target address into r8
    and r8, 0xfff               ; takes only the lesser bits of the address

    mov rsi, [r13 + 8]          ; address of the size of the address to override

    add rsi, r8                 ; adds the extra-space into the size argument
    and rdi, ~0xfff             ; rounds down the address to comply with page alineation

    mov rdx, 7                  ; mprotect flag for RWX as a bitmap value
    syscall

    add r13, 16                 ; we advance 16 bytes, since regions contains a sequence of addr,size vars
    dec r12                     ; decrement the r12 counter
    cmp r12, 0                  ; check if r12 equals 0
    jne decrypt                 ; if r12 does not equal 0, loop again
    ret

section .data
    msg db "....WOODY....", 10
    mlen equ $ - msg
    oe: dq 0xDEADC0DEDEADC0DE
    count: dq 0xC0FFEE00C0FFEE00
    regions:
