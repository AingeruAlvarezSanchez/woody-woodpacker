#ifndef DEBUG_H
#define DEBUG_H

#include <elf.h>
#include <stdio.h>
#include <stdint.h>

void debug_elf_header(const Elf64_Ehdr *);
void debug_program_headers(const Elf64_Phdr *, Elf64_Half);
void debug_entry_point_segment(const Elf64_Ehdr *, const Elf64_Phdr *);

#endif
