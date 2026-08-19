#include "woody_woodpacker.h"

static int process_file(t_woody *woody) {
    if (woody_find_target_segment(woody) != EXIT_SUCCESS)
        return error("No executable segment found");

    if (woody_prepare_cipher(woody) != EXIT_SUCCESS || woody_encrypt_segment(woody) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    if (woody_inject_payload(woody) != EXIT_SUCCESS)
        return error("Cannot inject the entry stub");

    return create_woody_executable(woody);
}

static int pack_file(const char *path) {
    t_woody woody = {0};
    int result;

    if (load_elf_file(path, &woody.elf) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    result = process_file(&woody);
    woody_cleanup(&woody);
    return result;
}

int main(const int argc, char **argv) {
    if (argc != 2)
        return error(strerror(EINVAL));

    return pack_file(argv[1]);
}
