#include "woody_woodpacker.h"

extern unsigned char woody_stub_start[];
extern unsigned char woody_stub_end[];

unsigned char *stub_template(void) {
    return woody_stub_start;
}

size_t stub_template_size(void) {
    return (size_t)(woody_stub_end - woody_stub_start);
}

static int copy_stub_template(t_woody *woody) {
    woody->stub_size = stub_template_size();
    if (woody->stub_size == 0)
        return EXIT_FAILURE;

    woody->stub = malloc(woody->stub_size);
    if (woody->stub == NULL)
        return error(strerror(ENOMEM));

    memcpy(woody->stub, stub_template(), woody->stub_size);
    return EXIT_SUCCESS;
}

static int find_marker(const unsigned char *payload, size_t payload_size, uint64_t marker, size_t *marker_offset) {
    uint64_t candidate_value;

    if (payload == NULL || marker_offset == NULL)
        return EXIT_FAILURE;

    if (payload_size < sizeof(uint64_t))
        return EXIT_FAILURE;

    for (size_t i = 0;i + sizeof(candidate_value) <= payload_size; ++i) {
        memcpy(&candidate_value, payload + i, sizeof(candidate_value));

        if (candidate_value == marker) {
            *marker_offset = i;
            return EXIT_SUCCESS;
        }
    }

    return EXIT_FAILURE;
}

static int patch_marker_u64(unsigned char *payload, size_t payload_size, uint64_t marker, uint64_t value) {
    size_t marker_offset;

    if (find_marker(payload, payload_size, marker, &marker_offset) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    memcpy(payload + marker_offset, &value, sizeof(value));
    return EXIT_SUCCESS;
}

static Elf64_Phdr *find_program_header_by_type(t_elf *elf, Elf64_Word type) {
    if (elf == NULL || elf->ehdr == NULL || elf->phdrs == NULL)
        return NULL;

    for (Elf64_Half i = 0; i < elf->ehdr->e_phnum; ++i)
        if (elf->phdrs[i].p_type == type)
            return &elf->phdrs[i];

    return NULL;
}

static int patch_stub_parameters(t_woody *woody) {
    size_t entry_marker_offset;
    int64_t entry_offset;

    if (patch_marker_u64(woody->stub, woody->stub_size, STUB_MARKER_TEXT_REL,
        (uint64_t)((int64_t)woody->text_vaddr - (int64_t)woody->stub_vaddr)) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (patch_marker_u64(woody->stub, woody->stub_size, STUB_MARKER_TEXT_SIZE, (uint64_t)woody->text_size) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (patch_marker_u64(woody->stub, woody->stub_size, STUB_MARKER_XOR_KEY, woody->xor_key) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (find_marker(woody->stub, woody->stub_size, STUB_MARKER_ENTRY_REL, &entry_marker_offset) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    entry_offset = (int64_t)(woody->original_entry - (int64_t)(woody->stub_vaddr + entry_marker_offset));

    memcpy(woody->stub + entry_marker_offset, &entry_offset, sizeof(entry_offset));

    return EXIT_SUCCESS;
}

static int install_stub(t_woody *woody) {
    Elf64_Phdr *stub_header;

    stub_header = find_program_header_by_type(&woody->elf, PT_NOTE);
    if (stub_header == NULL)
        return EXIT_FAILURE;

    printf("\n[stub] Replacing PT_NOTE\n");
    printf("  old offset : 0x%lx\n",
        (unsigned long)stub_header->p_offset);
    printf("  old vaddr  : 0x%lx\n",
        (unsigned long)stub_header->p_vaddr);

    stub_header->p_type = PT_LOAD;
    stub_header->p_offset = woody->stub_file_offset;
    stub_header->p_vaddr = woody->stub_vaddr;
    stub_header->p_paddr = woody->stub_vaddr;
    stub_header->p_filesz = woody->stub_size;
    stub_header->p_memsz = woody->stub_size;
    stub_header->p_flags = PF_R | PF_X | PF_W;
    stub_header->p_align = PAGE_SIZE_BYTES;

    woody->elf.ehdr->e_entry = woody->stub_vaddr;

    printf("\n[stub] New PT_LOAD\n");
    printf("  file offset : 0x%lx\n",
        (unsigned long)stub_header->p_offset);
    printf("  vaddr       : 0x%lx\n",
        (unsigned long)stub_header->p_vaddr);
    printf("  filesz      : 0x%lx\n",
        (unsigned long)stub_header->p_filesz);
    printf("  memsz       : 0x%lx\n",
        (unsigned long)stub_header->p_memsz);
    printf("  align       : 0x%lx\n",
        (unsigned long)stub_header->p_align);
    printf("  entry       : 0x%lx\n",
        (unsigned long)woody->elf.ehdr->e_entry);

    return EXIT_SUCCESS;
}

int woody_inject_payload(t_woody *woody) {
    size_t aligned_file_offset;

    if (woody == NULL || woody->elf.ehdr == NULL || woody->elf.phdrs == NULL)
        return EXIT_FAILURE;

    if (copy_stub_template(woody) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    aligned_file_offset = (woody->elf.file_size + (PAGE_SIZE_BYTES - 1)) & PAGE_ALIGN_MASK;
    woody->stub_file_offset = aligned_file_offset;

    woody->stub_vaddr = get_highest_pt_load_vaddr(&woody->elf);

    if (patch_stub_parameters(woody) != EXIT_SUCCESS || install_stub(woody) != EXIT_SUCCESS) {
        free(woody->stub);
        woody->stub = NULL;
        woody->stub_size = 0;
        return EXIT_FAILURE;
    }

    make_text_segment_writable(woody);

    return EXIT_SUCCESS;
}
