//
// Created by aalvarez on 8/22/26.
//

#include "stub.h"
#include "woody_woodpacker.h"
#include <unistd.h>

ssize_t write_stub(const int fd) {
    return write(fd, stub, stub_len);
}

static void fill_placeholder(size_t offset, const uint32_t *content, const size_t size) {
    for (size_t i = 0; i < size; i++) {
        *(uint32_t *)(stub + offset) = content[i];
        offset += 4;
    }
}

static __uint8_t replace_asm_placeholder(const Elf64_Addr delta, const t_elf *elf) {
    typedef struct s_placeholder {
        uint64_t placeholder;
        const uint32_t *src;
        size_t words;
    } t_placeholder;
    const t_placeholder ph_table[] = {
        {.placeholder = ENTRY_PLACEHOLDER, .src = (const uint32_t *)&delta, .words = 2},
        {.placeholder = PHADDR_PLACEHOLDER, .src = (const uint32_t *)&elf->program_addr, .words = 2},
        {.placeholder = PHSIZE_PLACEHOLDER, .src = (const uint32_t *)&elf->program_size, .words = 2},
        {.placeholder = KEY_PLACEHOLDER, .src = &elf->states[4], .words = 8},
        {.placeholder = NONCE_PLACEHOLDER, .src = &elf->states[13], .words = 3}
    };
    const size_t table_size = sizeof(ph_table) / sizeof(ph_table[0]);

    __uint8_t found_ph = 0;
    for (size_t i = 0; i + 8 <= stub_len; i++) {
        for (size_t j = 0; j < table_size; j++) {
            if (*(uint64_t *)(stub + i) == ph_table[j].placeholder) {
                fill_placeholder(i, ph_table[j].src, ph_table[j].words);
                i += ph_table[j].words * 4 - 1;
                found_ph++;
                break;
            }
        }
    }
    return found_ph != 5;
}

__uint8_t inject_stub(t_elf *elf, Elf64_Ehdr *header) {
    Elf64_Phdr *program_header = (Elf64_Phdr *)(elf->elf64_raw + header->e_phoff), *pt_note = NULL;
    const Elf64_Addr entry_cpy = header->e_entry;
    Elf64_Addr new_vaddr = 0;
    for (int i = 0; i < header->e_phnum; i++) {
        if (program_header[i].p_type == PT_NOTE) {
            pt_note = &program_header[i];
        } else if (program_header[i].p_type == PT_LOAD) {
            new_vaddr = new_vaddr < program_header[i].p_vaddr + program_header[i].p_memsz
                                    ? program_header[i].p_vaddr + program_header[i].p_memsz
                                    : new_vaddr;
        }
    }
    if (pt_note == NULL) return error(ENOPTNOTE);

    new_vaddr = ROUND_UP(new_vaddr);
    pt_note->p_type = PT_LOAD;
    pt_note->p_flags = PF_R | PF_W | PF_X;
    pt_note->p_offset = elf->offset;
    pt_note->p_filesz = stub_len;
    pt_note->p_memsz = stub_len;
    pt_note->p_vaddr = new_vaddr + (pt_note->p_offset & 0xfffUL);
    pt_note->p_align = 0x1000;
    header->e_entry = pt_note->p_vaddr;

    elf->program_addr -= pt_note->p_vaddr;
    if (replace_asm_placeholder(entry_cpy - pt_note->p_vaddr, elf)) return error(ENOPHOLDER);

    return EXIT_SUCCESS;
}
