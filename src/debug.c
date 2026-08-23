#include "debug.h"

static const char *elf_class_name(unsigned char elf_class){
    if (elf_class == ELFCLASS32)
        return ("ELFCLASS32");
    else if(elf_class == ELFCLASS64)
     return ("ELFCLASS64");
    else return ("ELFCLASSNONE");
}

static const char *elf_data_name(unsigned char data) {
    if (data == ELFDATA2LSB)
        return ("little-endian");
    else if (data == ELFDATA2MSB)
        return ("big-endian");
    else return ("unknown");
}

static const char *elf_type_name(Elf64_Half type) {
    if (type == ET_REL)
        return ("ET_REL");
    else if (type == ET_EXEC)
        return ("ET_EXEC");
    else if (type == ET_DYN)
        return ("ET_DYN");
    else if (type == ET_CORE)
        return ("ET_CORE");
    else return ("ET_NONE/unknown");
}

static const char *elf_machine_name(Elf64_Half machine) {
    if (machine == EM_X86_64)
        return ("EM_X86_64");
    else return ("unsupported/unknown");
}

void debug_elf_header(const Elf64_Ehdr *header) {
    printf("\nELF Header\n");
    printf("  magic       = %02x %02x %02x %02x\n",
        header->e_ident[EI_MAG0], header->e_ident[EI_MAG1],
        header->e_ident[EI_MAG2], header->e_ident[EI_MAG3]);
    printf("  class       = %u (%s)\n", header->e_ident[EI_CLASS],
        elf_class_name(header->e_ident[EI_CLASS]));
    printf("  data        = %u (%s)\n", header->e_ident[EI_DATA],
        elf_data_name(header->e_ident[EI_DATA]));
    printf("  type        = %u (%s)\n", header->e_type,
        elf_type_name(header->e_type));
    printf("  machine     = %u (%s)\n", header->e_machine,
        elf_machine_name(header->e_machine));
    printf("  entry       = 0x%llx\n",
        (unsigned long long)header->e_entry);
    printf("  phoff       = 0x%llx\n",
        (unsigned long long)header->e_phoff);
    printf("  phentsize   = %u\n", header->e_phentsize);
    printf("  phnum       = %u\n", header->e_phnum);
    printf("  shoff       = 0x%llx\n",
        (unsigned long long)header->e_shoff);
    printf("  shentsize   = %u\n", header->e_shentsize);
    printf("  shnum       = %u\n", header->e_shnum);
    printf("  shstrndx    = %u\n", header->e_shstrndx);
}

static void debug_program_header_flags(Elf64_Word flags) {
    printf("  p_flags  = 0x%x (%c%c%c)\n", (unsigned int)flags,
        flags & PF_R ? 'R' : '-',
        flags & PF_W ? 'W' : '-',
        flags & PF_X ? 'X' : '-');
}

static void debug_range(const char *name, uint64_t start, uint64_t size) {
    if (size <= (UINT64_MAX - start)) {
        printf("  %s = [0x%llx, 0x%llx)\n", name,
            (unsigned long long)start,
            (unsigned long long)(start + size));
    }
    else
        printf("  %s = overflow\n", name);
}

static void debug_program_header(const Elf64_Phdr *program_header, Elf64_Half index){
    printf("\nProgram Header [%u]\n", (unsigned int)index);
    printf("  p_type   = %u\n", (unsigned int)program_header->p_type);
    debug_program_header_flags(program_header->p_flags);
    printf("  p_offset = 0x%llx\n",
        (unsigned long long)program_header->p_offset);
    printf("  p_vaddr  = 0x%llx\n",
        (unsigned long long)program_header->p_vaddr);
    printf("  p_paddr  = 0x%llx\n",
        (unsigned long long)program_header->p_paddr);
    printf("  p_filesz = 0x%llx\n",
        (unsigned long long)program_header->p_filesz);
    printf("  p_memsz  = 0x%llx\n",
        (unsigned long long)program_header->p_memsz);
    printf("  p_align  = 0x%llx\n",
        (unsigned long long)program_header->p_align);
    debug_range("file range", program_header->p_offset,
        program_header->p_filesz);
    debug_range("memory range", program_header->p_vaddr,
        program_header->p_memsz);
}

void debug_program_headers(const Elf64_Phdr *program_headers, Elf64_Half program_header_count) {
    for (Elf64_Half index = 0; index < program_header_count; index++)
        debug_program_header(&program_headers[index], index);
}

void debug_entry_point_segment(const Elf64_Ehdr *header, const Elf64_Phdr *program_headers) {
    for (Elf64_Half index = 0; index < header->e_phnum; index++) {
        if (program_headers[index].p_type == PT_LOAD
            && header->e_entry >= program_headers[index].p_vaddr
            && header->e_entry - program_headers[index].p_vaddr
                < program_headers[index].p_memsz) {
            printf("\nEntry point 0x%llx is in PT_LOAD [%u]\n",
                (unsigned long long)header->e_entry, (unsigned int)index);
            printf("  entry virtual offset = 0x%llx\n",
                (unsigned long long)(header->e_entry
                    - program_headers[index].p_vaddr));
            debug_range("entry segment virtual range",
                program_headers[index].p_vaddr, program_headers[index].p_memsz);
            debug_range("entry segment file range",
                program_headers[index].p_offset, program_headers[index].p_filesz);
            return ;
        }
    }
    printf("\nEntry point 0x%llx is not in a PT_LOAD segment\n",
        (unsigned long long)header->e_entry);
}

void debug_stub_conversion(const Elf64_Phdr *old_note, const Elf64_Phdr *new_load,
        Elf64_Addr entry) {
    printf("\n[stub] Replacing PT_NOTE\n");
    printf("  old offset : 0x%llx\n", (unsigned long long)old_note->p_offset);
    printf("  old vaddr  : 0x%llx\n", (unsigned long long)old_note->p_vaddr);

    printf("\n[stub] New PT_LOAD\n");
    printf("  file offset : 0x%llx\n", (unsigned long long)new_load->p_offset);
    printf("  vaddr       : 0x%llx\n", (unsigned long long)new_load->p_vaddr);
    printf("  filesz      : 0x%llx\n", (unsigned long long)new_load->p_filesz);
    printf("  memsz       : 0x%llx\n", (unsigned long long)new_load->p_memsz);
    printf("  align       : 0x%llx\n", (unsigned long long)new_load->p_align);
    printf("  entry       : 0x%llx\n", (unsigned long long)entry);
}
