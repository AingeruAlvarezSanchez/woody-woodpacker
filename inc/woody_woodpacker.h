//
// Created by aalvarez on 29/07/2026.
//

#ifndef WOODY_WOODPACKER_H
#define WOODY_WOODPACKER_H

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define ENOELF "Not an ELF file"
#define EWRONGARCH "File architecture not suported. x86_64 only"

#include <stdio.h>

typedef struct s_elf {
    const unsigned char *elf64_raw;
    off_t offset;
} t_elf;

#endif //WOODY_WOODPACKER_H
