#include "woody_woodpacker.h"

int create_woody_executable(t_woody *woody) {
    if (woody == NULL || woody->elf.map == NULL || woody->stub == NULL)
        return (EXIT_FAILURE);

    int fd = open(WOODY_OUTPUT_FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1)
        return (EXIT_FAILURE);

    if (write(fd, woody->elf.map, woody->elf.file_size) != (ssize_t)woody->elf.file_size) {
        close(fd);
        return (EXIT_FAILURE);
    }

    size_t current_size = woody->elf.file_size;
    size_t aligned_size = (current_size + PAGE_SIZE_BYTES - 1) & PAGE_ALIGN_MASK;
    char zero = 0;
    while (current_size < aligned_size) {
        if (write(fd, &zero, 1) != 1) {
            close(fd);
            return (EXIT_FAILURE);
        }
        current_size++;
    }

    if (write(fd, woody->stub, woody->stub_size) != (ssize_t)woody->stub_size) {
        close(fd);
        return (EXIT_FAILURE);
    }

    close(fd);
    return (EXIT_SUCCESS);
}
