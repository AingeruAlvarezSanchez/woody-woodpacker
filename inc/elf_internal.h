#ifndef ELF_INTERNAL_H
#define ELF_INTERNAL_H

#include <elf.h>
#include <sys/types.h>
#include <stddef.h>

typedef struct s_elf {
    unsigned char *map;
    size_t        file_size;

    Elf64_Ehdr    *ehdr;
    Elf64_Phdr    *phdrs;
} t_elf;

int load_elf_file(const char *, t_elf *);
int program_headers_are_valid(const Elf64_Ehdr *, off_t);
Elf64_Addr get_highest_pt_load_vaddr(t_elf *);

#endif

