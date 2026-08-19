#include "elf_internal.h"
#include "woody_woodpacker.h"
#include "debug.h"

void woody_cleanup(t_woody *woody) {
    if (woody == NULL)
        return;
    if (woody->stub != NULL) {
        free(woody->stub);
        woody->stub = NULL;
    }

    if (woody->elf.map != NULL && woody->elf.file_size > 0) {
        munmap((void *)woody->elf.map, woody->elf.file_size);
        woody->elf.map = NULL;
        woody->elf.file_size = 0;
    }
}

int load_elf_file(const char *file, t_elf *elf) {
    if (file == NULL || elf == NULL)
        return (error(strerror(EINVAL)));

    const int fd = open(file, O_RDONLY);
    if (fd == -1)
        return (error(strerror(errno)));

    const off_t offset = lseek(fd, 0, SEEK_END);
    if (offset == -1) {
        close(fd);
        return (error(strerror(errno)));
    }

    if (offset < 1 || offset < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return (error(ENOELF));
    }

    void *addr = mmap(NULL, offset, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

    if (addr == MAP_FAILED)
        return (error(strerror(errno)));

    Elf64_Ehdr *elf_header = addr;
    if (ft_memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
        munmap(elf_header, offset);
        return (error(ENOELF));
    }

    if (elf_header->e_ident[EI_CLASS] != ELFCLASS64 || elf_header->e_machine != EM_X86_64) {
        munmap(elf_header, offset);
        return (error(EWRONGARCH));
    }

    if (program_headers_are_valid(elf_header, offset) != EXIT_SUCCESS) {
        munmap(elf_header, offset);
        return (error(EINVALIDPHT));
    }

    Elf64_Phdr *program_headers = (Elf64_Phdr *)((unsigned char *)elf_header + elf_header->e_phoff);

    debug_elf_header(elf_header);
    debug_program_headers(program_headers, elf_header->e_phnum);
    debug_entry_point_segment(elf_header, program_headers);

    elf->map = (unsigned char *)elf_header;
    elf->file_size = (size_t)offset;
    elf->ehdr = elf_header;
    elf->phdrs = program_headers;

    return (EXIT_SUCCESS);
}
