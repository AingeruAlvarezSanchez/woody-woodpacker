//
// Created by aalvarez on 29/07/2026.
//

#include "woody_woodpacker.h"
#include "libft.h"
#include "stub.h"
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

__uint8_t error(char *msg) {
    ft_putendl_fd(msg, STDOUT_FILENO);
    return EXIT_FAILURE;
}

static int validate_elf_file(const char *file, t_elf *elf) {
    const int fd = open(file, 0);
    if (fd == -1) return error(strerror(errno));

    const off_t offset = lseek(fd, 0, SEEK_END);
    if (offset == -1) {
        close(fd);
        return error(strerror(errno));
    }
    if (offset < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return error(ENOELF);
    }

    Elf64_Ehdr *elf_header = mmap(NULL, offset, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (elf_header == MAP_FAILED) return error(strerror(errno));
    if (ft_memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(elf_header, offset);
        return error(ENOELF);
    }
    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64 || elf_header->e_machine != EM_X86_64) {
        munmap(elf_header, offset);
        return error(EWRONGARCH);
    }

    elf->elf64_raw = (const unsigned char *)elf_header;
    elf->offset = offset;
    return EXIT_SUCCESS;
}

static __uint8_t create_woody_executable(const t_elf *elf) {
    const int fd = open(ENCRYPTED_EXECUTABLE_NAME, O_CREAT | O_RDWR | O_TRUNC, 0755);
    if (fd == -1) return error(strerror(errno));

    ssize_t result = write(fd, elf->elf64_raw, elf->offset);
    if (result == -1) return error(strerror(errno));
    result = write(fd, stub, stub_len);
    if (result == -1) return error(strerror(errno));
    for (size_t i = 0; i < elf->executable_sections; i++) {
        result = write(fd, &elf->section_addr[i], sizeof(Elf64_Addr));
        if (result == -1) return error(strerror(errno));
        result = write(fd, &elf->section_size[i], sizeof(Elf64_Xword));
        if (result == -1) return error(strerror(errno));
    }

    close(fd);
    return EXIT_SUCCESS;
}

static void fill_placeholder(size_t offset, const uint32_t *content, const size_t size) {
    for (size_t i = 0; i < size; i++) {
        *(uint32_t *)(stub + offset) = content[i];
        offset += 4;
    }
}

static __uint8_t replace_asm_placeholder(const Elf64_Addr delta, const t_elf *elf) {
    __uint8_t found_ph = 0;
    for (size_t i = 0; i + 8 <= stub_len; i++) {
        switch (*(uint64_t *)(stub + i)) {
            case ENTRY_PLACEHOLDER:
                *(uint64_t *)(stub + i) = delta;
                found_ph++;
                break;
            case COUNT_PLACEHOLDER:
                *(uint64_t *)(stub + i) = elf->executable_sections;
                found_ph++;
                break;
            case KEY_PLACEHOLDER:
                fill_placeholder(i, &elf->states[4], 8);
                i += 32;
                found_ph++;
                break;
            case NONCE_PLACEHOLDER:
                fill_placeholder(i, &elf->states[13], 3);
                i += 12;
                found_ph++;
                break;
            default: ;
        }
    }
    return found_ph != 4;
}

static __uint8_t inject_stub(const t_elf *elf, Elf64_Ehdr *header) {
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
    pt_note->p_flags = PF_R | PF_X;
    pt_note->p_offset = elf->offset;
    pt_note->p_filesz = stub_len + elf->executable_sections * 16;
    pt_note->p_memsz = stub_len + elf->executable_sections * 16;
    pt_note->p_vaddr = new_vaddr + (pt_note->p_offset & 0xfffUL);
    pt_note->p_align = 0x1000;
    header->e_entry = pt_note->p_vaddr;

    for (size_t i = 0; i < elf->executable_sections; i++) {
        elf->section_addr[i] -= pt_note->p_vaddr;
    }
    if (replace_asm_placeholder(entry_cpy - pt_note->p_vaddr, elf)) return error(ENOPHOLDER);

    return EXIT_SUCCESS;
}

int main(const int argc, char **argv) {
    if (argc != 2) return error(strerror(EINVAL));

    t_elf elf = {};
    if (validate_elf_file(argv[1], &elf) != EXIT_SUCCESS) return EXIT_FAILURE;
    Elf64_Ehdr *header = (Elf64_Ehdr *)elf.elf64_raw;
    const Elf64_Shdr *section_header = (Elf64_Shdr *)(elf.elf64_raw + header->e_shoff);

    if (prepare_chacha20_stream(elf.states) != EXIT_SUCCESS) return EXIT_FAILURE;

    Elf64_Addr section_addr[header->e_shnum];
    Elf64_Xword section_size[header->e_shnum];
    for (int i = 0; i < header->e_shnum; i++) {
        if (section_header[i].sh_flags & SHF_EXECINSTR) {
            unsigned char *text = (unsigned char *)elf.elf64_raw + section_header[i].sh_offset;
            chacha20_encrypt(elf.states, text, section_header[i].sh_size);
            section_addr[elf.executable_sections] = section_header[i].sh_addr;
            section_size[elf.executable_sections] = section_header[i].sh_size;
            elf.executable_sections++;
        }
    }
    elf.section_addr = section_addr;
    elf.section_size = section_size;

    inject_stub(&elf, header);
    printf("key_value: ");
    for (int i = 0; i < 16; i++) {
        if (i != 12) {
            printf("%08x", elf.states[i]);
        } else {
            printf("%08x", 1);
        }
    }
    printf("\n");

    if (create_woody_executable(&elf) != EXIT_SUCCESS) return EXIT_FAILURE;

    munmap((void *)elf.elf64_raw, elf.offset);
    return EXIT_SUCCESS;
}
