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

    mov r12, [rel ph_size]      ; move the size of the address to override to r12
    lea r13, [rel ph_addr]      ; initial address to override
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

    mov rsi, r12                ; size of the address to override

    add rsi, r8                 ; adds the extra-space into the size argument
    and rdi, ~0xfff             ; rounds down the address to comply with page alignment

    mov rdx, 7                  ; mprotect flag for RWX as a bitmap value
    syscall
    call chacha20

    ret

chacha20:
    lea r12, [rel _start]       ; moves the address of the program to r12
    add r12, [rel ph_addr]      ; moves the address of the program header to r12
    mov r14, [rel ph_size]      ; moves the size of the program header to r12

.block_loop:
    cld                         ; clears the direction flag
    mov rcx, 8                  ; number of loops for the rep instruction
    lea rsi, [rel seed]         ; moves the keystream seed to rsi
    lea rdi, [rel rkeystream]   ; moves the rkeystream address to rsi
    rep movsq                   ; copies the value of the seed into rkeystream

    lea r10, [rel rkeystream]   ; moves the rkeystream address to r10 (now filled)
    mov r15, 10                 ; number of quarter rounds loops to perform
.round_loop:
    mov r9, 8                   ; number of calls for each round (4 columns, 4 diagonals)
    lea r11, [rel qround_table] ; moves the content of the qround table for the loop to use
.qround_loop:
    movzx eax, word [r11]       ; moves the first word of the current table's position to eax
    lea rsi, [r10 + rax * 4]    ; finds the address of that word inside the block
    mov eax, [rsi]              ; loads its value into eax

    movzx ebx, word [r11 + 2]   ; repeats the same logic with the second word
    lea rdi, [r10 + rbx * 4]
    mov ebx, [rdi]

    movzx ecx, word [r11 + 4]   ; repeats the same logic with the third word
    lea r8, [r10 + rcx * 4]
    mov ecx, [r8]

    movzx edx, word [r11 + 6]   ; repeats the same logic with the fourth word
    lea r13, [r10 + rdx * 4]
    mov edx, [r13]

    call qround

    mov [rsi], eax               ; writes the updated words back to its place
    mov [rdi], ebx
    mov [r8], ecx
    mov [r13], edx

    add r11, 8                  ; moves on to the next row of the table
    dec r9
    jnz .qround_loop

    dec r15
    jnz .round_loop

    lea rsi, [rel seed]         ; goes back to the untouched seed
    mov r9, 16

.addback_loop:
    mov eax, [rsi]              ; loads the original seed word
    add [r10], eax              ; adds it to the matching block word
    add rsi, 4
    add r10, 4
    dec r9
    jnz .addback_loop            ; keeps going until all 16 words are done

    lea r13, [rel rkeystream]   ; goes back to the start of the finished block
    mov r9, 64
    cmp r14, 64                 ; checks if 64 or more bytes of the program are still left
    jae .xor_size_ok            ; if so, the full block will be used
    mov r9, r14                 ; otherwise only use as many bytes as are left

.xor_size_ok:
    sub r14, r9
.xor_loop:
    mov al, [r13]
    xor [r12], al                ; decrypts one byte of the program with it
    inc r13
    inc r12
    dec r9
    jnz .xor_loop

    inc dword [rel seed + 48]   ; increases the keystream counter forward for the next block
    cmp r14, 0
    jne .block_loop
    ret

qround:
    add eax, ebx                 ; performs the qround operations as stated by RFC 8439
    xor edx, eax                 ; mixes the fourth word with the updated first word
    rol edx, 16                  ; rotates the fourth word left by 16 bits

    add ecx, edx                 ; repeats process
    xor ebx, ecx
    rol ebx, 12

    add eax, ebx
    xor edx, eax
    rol edx, 8

    add ecx, edx
    xor ebx, ecx
    rol ebx, 7
    ret

section .bss
    rkeystream: resq 8

section .data
    msg db "....WOODY....", 10
    mlen equ $ - msg
    oe: dq 0xDEADC0DEDEADC0DE
    ph_addr: dq 0xC0FFEE00C0FFEE00
    ph_size: dq 0xDEADBEEFDEADBEEF
    seed: dd 0x61707865,0x3320646e,0x79622d32,0x6b206574
          dd 0xCAFEBABE,0xCAFEBABE,0xCAFEBABE,0xCAFEBABE,0xCAFEBABE,0xCAFEBABE,0xCAFEBABE,0xCAFEBABE
          dd 0x00000001
          dd 0xFEEDFACE,0xFEEDFACE,0xFEEDFACE
    qround_table: dw 0,4,8,12
                  dw 1,5,9,13
                  dw 2,6,10,14
                  dw 3,7,11,15
                  dw 0,5,10,15
                  dw 1,6,11,12
                  dw 2,7,8,13
                  dw 3,4,9,14
