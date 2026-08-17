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

    pop rdx                     ; saves the original status of the rdx register
    pop rsi                     ; saves the original status of the rsi register
    pop rdi                     ; saves the original status of the rdi register
    pop rax                     ; saves the original status of the rax register

    lea rax, [rel _start]       ; puts the address of the program into rax
    add rax, [rel oe]           ; adds the overwritten oe variable value nto rax
    jmp rax                     ; jumps back to the starting point of the original code

section .data
    msg db "....WOODY....", 10
    mlen equ $ - msg
    oe: dq 0xDEADC0DEDEADC0DE
