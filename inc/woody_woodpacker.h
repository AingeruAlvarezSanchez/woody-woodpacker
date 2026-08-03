//
// Created by aalvarez on 29/07/2026.
//

#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define ENOELF "Not an ELF file"
#define EWRONGARCH "File architecture not suported. x86_64 only"

#define URANDOM "/dev/urandom"

// macro used to rotate left the bits on a 32 bit number
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

// chacha20 constants used as the first four numbers of the state vector as defined by RFC 8439
#define CHACHA20_C0 0x61707865
#define CHACHA20_C1 0x3320646e
#define CHACHA20_C2 0x79622d32
#define CHACHA20_C3 0x6b206574

#define MAX_HEXA 0xff

#define ENCRYPTED_EXECUTABLE_NAME "woody"

#include <stdio.h>

typedef struct s_elf {
    const unsigned char *elf64_raw;
    off_t offset;
} t_elf;

__uint8_t error(char *msg);
int prepare_chacha20_stream(__uint32_t states[16]);
void chacha20_encrypt(__uint32_t states[16], unsigned char *text, size_t len);

#endif //WOODY_WOODPACKER_H
