//
// Created by aalvarez on 29/07/2026.
//

#include "woody_woodpacker.h"
#include "libft.h"
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

__uint8_t create_woody_executable(t_elf *elf) {
    const int fd = open(ENCRYPTED_EXECUTABLE_NAME, O_CREAT | O_RDWR | O_TRUNC, 0755);
    if (fd == -1) return error(strerror(errno));

    const ssize_t result = write(fd, elf->elf64_raw, elf->offset);
    if (result == -1) return error(strerror(errno));

    close(fd);
    return EXIT_SUCCESS;
}

int main(const int argc, char **argv) {
    if (argc != 2) return error(strerror(EINVAL));

    t_elf elf = {};
    if (validate_elf_file(argv[1], &elf) != EXIT_SUCCESS) return EXIT_FAILURE;
    const Elf64_Ehdr *header = (Elf64_Ehdr *)elf.elf64_raw;
    const Elf64_Shdr *section_header = (Elf64_Shdr *)(elf.elf64_raw + header->e_shoff);

    __uint32_t states[16];
    if (prepare_chacha20_stream(states) != EXIT_SUCCESS) return EXIT_FAILURE;

    Elf64_Addr section_addr[header->e_shnum];
    Elf64_Xword section_size[header->e_shnum];
    for (int i = 0; i < header->e_shnum; i++) {
        if (section_header[i].sh_flags & SHF_EXECINSTR) {
            unsigned char *text = (unsigned char *)elf.elf64_raw + section_header[i].sh_offset;
            chacha20_encrypt(states, text, section_header[i].sh_size);
            section_addr[elf.executable_sections] = section_header[i].sh_addr;
            section_size[elf.executable_sections] = section_header[i].sh_size;
            elf.executable_sections++;
        }
    }
    elf.section_addr = section_addr;
    elf.section_size = section_size;

    printf("key_value: ");
    for (int i = 4; i != 12; i++) {
        printf("%08x", states[i]);
    }
    printf("\n");

    if (create_woody_executable(&elf) != EXIT_SUCCESS) return EXIT_FAILURE;

    munmap((void *)elf.elf64_raw, elf.offset);
    return EXIT_SUCCESS;
}
