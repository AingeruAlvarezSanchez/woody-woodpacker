#include "elf_internal.h"
#include "woody_woodpacker.h"

static int program_header_table_fits(const Elf64_Ehdr *header, off_t file_size) {
    if (header->e_phentsize != sizeof(Elf64_Phdr))
        return (EXIT_FAILURE);
    if (header->e_phoff > (Elf64_Off)file_size)
        return (EXIT_FAILURE);
    return (header->e_phnum <= ((Elf64_Off)file_size - header->e_phoff)
        / header->e_phentsize ? EXIT_SUCCESS : EXIT_FAILURE);
}

static int program_header_offsets_fit(const Elf64_Ehdr *header, off_t file_size) {
    const Elf64_Phdr *program_headers;

    program_headers = (const Elf64_Phdr *)((const unsigned char *)header + header->e_phoff);
        for (Elf64_Half index = 0; index < header->e_phnum; index++) {
            if (program_headers[index].p_offset > (Elf64_Off)file_size)
                return (EXIT_FAILURE);
            if (program_headers[index].p_filesz > (Elf64_Off)(file_size - program_headers[index].p_offset))
                return (EXIT_FAILURE);
            if (program_headers[index].p_type == PT_LOAD && program_headers[index].p_filesz > program_headers[index].p_memsz)
                return (EXIT_FAILURE);
            if (program_headers[index].p_type == PT_LOAD && (program_headers[index].p_align > 1) && (program_headers[index].p_align
                    & (program_headers[index].p_align - 1)) != 0)
                return (EXIT_FAILURE);
    }
    return (EXIT_SUCCESS);
}

int program_headers_are_valid(const Elf64_Ehdr *header, off_t file_size) {
    if (program_header_table_fits(header, file_size) != EXIT_SUCCESS) return (EXIT_FAILURE);

    return (program_header_offsets_fit(header, file_size));
}

Elf64_Addr get_highest_pt_load_vaddr(t_elf *elf) {
    Elf64_Addr max_vaddr = 0;

    if (elf == NULL || elf->ehdr == NULL || elf->phdrs == NULL)
        return (PAGE_SIZE_BYTES);

    for (Elf64_Half i = 0; i < elf->ehdr->e_phnum; i++)
        if (elf->phdrs[i].p_type == PT_LOAD && elf->phdrs[i].p_vaddr + elf->phdrs[i].p_memsz > max_vaddr)
            max_vaddr = elf->phdrs[i].p_vaddr + elf->phdrs[i].p_memsz; // actualizar la dirección virtual más alta de los segmentos PT_LOAD
    return (max_vaddr + (PAGE_SIZE_BYTES - 1)) & PAGE_ALIGN_MASK;
}

// Encontrar el segmento ejecutable que contiene la dirección de entrada
int woody_find_target_segment(t_woody *woody) {
    if (woody == NULL || woody->elf.ehdr == NULL || woody->elf.phdrs == NULL)
        return (EXIT_FAILURE);

    for (Elf64_Half index = 0; index < woody->elf.ehdr->e_phnum; index++) {
        if (woody->elf.phdrs[index].p_type == PT_LOAD && woody->elf.ehdr->e_entry >= woody->elf.phdrs[index].p_vaddr
            && woody->elf.ehdr->e_entry < woody->elf.phdrs[index].p_vaddr + woody->elf.phdrs[index].p_memsz) {
            woody->text_vaddr = woody->elf.phdrs[index].p_vaddr;
            woody->text_size = woody->elf.phdrs[index].p_filesz;
            woody->text_offset = woody->elf.phdrs[index].p_offset;
            woody->original_entry = woody->elf.ehdr->e_entry;
            return (EXIT_SUCCESS);
        }
    }
    return (EXIT_FAILURE);
}

void make_text_segment_writable(t_woody *woody) {
    if (woody == NULL || woody->elf.ehdr == NULL || woody->elf.phdrs == NULL) return;

   for (Elf64_Half index = 0; index < woody->elf.ehdr->e_phnum; index++) {
        if (woody->elf.phdrs[index].p_type == PT_LOAD && woody->elf.phdrs[index].p_vaddr == woody->text_vaddr) {
            woody->elf.phdrs[index].p_flags = PF_R | PF_W | PF_X;
            woody->elf.phdrs[index].p_align = PAGE_SIZE_BYTES;
            break;
        }
    }
}
