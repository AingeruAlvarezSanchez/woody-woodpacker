//
// Created by aalvarez on 8/2/26.
//

#include "woody_woodpacker.h"
#include "libft.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int prepare_chacha20_stream(__uint32_t states[16]) {
    states[0] = CHACHA20_C0;
    states[1] = CHACHA20_C1;
    states[2] = CHACHA20_C2;
    states[3] = CHACHA20_C3;
    states[12] = 1;

    const int fd = open(URANDOM, O_RDONLY);
    if (fd == -1) return error(strerror(errno));
    if (read(fd, &states[4], 32) != 32 || read(fd, &states[13], 12) != 12) {
        close(fd);
        return error(strerror(errno));
    }
    close(fd);

    return EXIT_SUCCESS;
}

static void chacha20_quarter_round(__uint32_t *a, __uint32_t *b, __uint32_t *c, __uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

static void chacha20_block(__uint32_t states[16], unsigned char keystream[64]) {
    __uint32_t working_state[16];
    ft_memcpy(working_state, states, 16 * sizeof(__uint32_t));

    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }
    for (int i = 0; i < 16; i++) {
        working_state[i] += states[i];
    }
    for (int i = 0; i < 16; i++) {
        keystream[i * 4] = working_state[i];
        keystream[i * 4 + 1] = working_state[i] >> 8 & MAX_HEXA;
        keystream[i * 4 + 2] = working_state[i] >> 16 & MAX_HEXA;
        keystream[i * 4 + 3] = working_state[i] >> 24 & MAX_HEXA;
    }
}

static void encrypt_block(__uint32_t states[16], unsigned char *text, const size_t len) {
    unsigned char encrypted_text[64];
    for (size_t i = 0; i < len; i += 64) {
        chacha20_block(states, encrypted_text);
        states[12]++;
        const size_t n = len - i < 64 ? len - i : 64;
        for (size_t k = 0; k < n; k++) {
            text[i + k] ^= encrypted_text[k];
        }
    }
}

void chacha20_encrypt(t_elf *elf, const Elf64_Ehdr *header, const Elf64_Phdr *program_header) {
    for (int i = 0; i < header->e_phnum; i++) {
        if (program_header[i].p_type == PT_LOAD && program_header[i].p_flags & PF_X) {
            unsigned char *text = (unsigned char *)elf->elf64_raw + program_header[i].p_offset;
            encrypt_block(elf->states, text, program_header[i].p_filesz);
            elf->program_addr = program_header[i].p_vaddr;
            elf->program_size = program_header[i].p_filesz;
            break;
        }
    }
}
