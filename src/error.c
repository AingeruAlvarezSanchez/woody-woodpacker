#include "woody_woodpacker.h"

uint8_t error(char *msg) {
    ft_putendl_fd(msg, STDOUT_FILENO);
    return (EXIT_FAILURE);
}
