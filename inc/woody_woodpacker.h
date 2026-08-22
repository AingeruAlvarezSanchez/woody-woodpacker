//
// Created by aalvarez on 29/07/2026.
//

#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define ENOELF "Not an ELF file"
#define EWRONGARCH "File architecture not suported. x86_64 only"
#define ENOPTNOTE "ELF does not contain a PT_NOTE symbol. Aborting"
#define ENOPHOLDER "the stub doesn't contain one or more expected placeholder values. Aborting"

#define URANDOM "/dev/urandom"

// macro used to rotate left the bits on a 32 bit number
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROUND_UP(x) ((x + 0xfff) & ~0xfffUL)

// chacha20 constants used as the first four numbers of the state vector as defined by RFC 8439
#define CHACHA20_C0 0x61707865
#define CHACHA20_C1 0x3320646e
#define CHACHA20_C2 0x79622d32
#define CHACHA20_C3 0x6b206574
#define ENTRY_PLACEHOLDER 0xDEADC0DEDEADC0DE
#define PHADDR_PLACEHOLDER 0xC0FFEE00C0FFEE00
#define PHSIZE_PLACEHOLDER 0xDEADBEEFDEADBEEF
#define KEY_PLACEHOLDER 0xCAFEBABECAFEBABE
#define NONCE_PLACEHOLDER 0xFEEDFACEFEEDFACE

#define MAX_HEXA 0xff

#define ENCRYPTED_EXECUTABLE_NAME "woody"

#include <elf.h>
#include <stdio.h>

typedef struct s_elf {
    const unsigned char *elf64_raw;
    off_t offset;
    Elf64_Addr program_addr;
    Elf64_Xword program_size;
    __uint32_t states[16];
} t_elf;

__uint8_t error(char *msg);

// chacha20 related
int prepare_chacha20_stream(__uint32_t states[16]);
void chacha20_encrypt(t_elf *elf, const Elf64_Ehdr *header, const Elf64_Phdr *program_header);

// Stub related
__uint8_t inject_stub(t_elf *elf, Elf64_Ehdr *header);
ssize_t write_stub(int fd);

#endif //WOODY_WOODPACKER_H
