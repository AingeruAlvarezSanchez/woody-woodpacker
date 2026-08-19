#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

#include "libft.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include "elf_internal.h"

#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

// chacha20 constants used as the first four numbers of the state vector as defined by RFC 8439
#define CHACHA20_C0 0x61707865
#define CHACHA20_C1 0x3320646e
#define CHACHA20_C2 0x79622d32
#define CHACHA20_C3 0x6b206574
#define MAX_HEXA 0xff

#define ENOELF                      "Not an ELF file"
#define EWRONGARCH                 "File architecture not supported. x86_64 only"
#define EINVALIDPHT                "Invalid program header table"

#define URANDOM_DEVICE_PATH        "/dev/urandom"
#define WOODY_OUTPUT_FILENAME      "woody"

#define PAGE_SIZE_BYTES            0x1000UL
#define PAGE_ALIGN_MASK            (~(PAGE_SIZE_BYTES - 1))
#define XOR_KEY_SIZE_BYTES         8

/* Hexadecimal literals used as placeholders and replaced before injection. */
#define STUB_MARKER_TEXT_REL       UINT64_C(0x1111111111111111)
#define STUB_MARKER_TEXT_SIZE      UINT64_C(0x2222222222222222)
#define STUB_MARKER_XOR_KEY        UINT64_C(0x3333333333333333)
#define STUB_MARKER_ENTRY_REL      UINT64_C(0x4444444444444444)

/* ── Central Woody Packer Context Structure ────────────────────────────── */
typedef struct s_woody {
    t_elf          elf;
    Elf64_Addr     text_vaddr;
    Elf64_Xword    text_size;
    Elf64_Off      text_offset;
    Elf64_Addr     original_entry;

    uint64_t       xor_key;

    unsigned char *stub;
    size_t         stub_size;
    Elf64_Off      stub_file_offset;
    Elf64_Addr     stub_vaddr;

    uint32_t         chacha_state[16];
} t_woody;

uint8_t error(char *);
void      woody_cleanup(t_woody *);
int       woody_find_target_segment(t_woody *);
void      make_text_segment_writable(t_woody *);
int       woody_prepare_cipher(t_woody *);
int       prepare_chacha20_stream(uint32_t states[16]);
void      chacha20_encrypt(uint32_t states[16], unsigned char *text, const size_t len);
int       woody_encrypt_segment(t_woody *);
int       woody_inject_payload(t_woody *);
int       create_woody_executable(t_woody *);

unsigned char *stub_template(void);
size_t    stub_template_size(void);
void      print_key_info(uint64_t);

#endif
