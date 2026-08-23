#include "woody_woodpacker.h"

int woody_prepare_cipher(t_woody *woody) {
    if (woody == NULL)
        return EXIT_FAILURE;

    if (prepare_chacha20_stream(woody->chacha_state) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    ft_memcpy(woody->chacha_initial_state, woody->chacha_state, sizeof(woody->chacha_state));

    return EXIT_SUCCESS;
}

int woody_encrypt_segment(t_woody *woody) {

    if (woody == NULL || woody->elf.map == NULL || woody->elf.ehdr == NULL)
        return EXIT_FAILURE;

    unsigned char *text = woody->elf.map + woody->text_offset;

    chacha20_encrypt(woody->chacha_state, text, woody->text_size);

    printf("key_value: ");

    for (int i = 4; i != 12; i++)
        printf("%08x", woody->chacha_state[i]);

    printf("\n");

    return EXIT_SUCCESS;
}

int prepare_chacha20_stream(uint32_t states[16]) {
    states[0] = CHACHA20_C0;
    states[1] = CHACHA20_C1;
    states[2] = CHACHA20_C2;
    states[3] = CHACHA20_C3;
    states[12] = 1;

    const int fd = open(URANDOM_DEVICE_PATH, O_RDONLY);
    if (fd == -1)
        return error(strerror(errno));

    if (read(fd, &states[4], 32) != 32 || read(fd, &states[13], 12) != 12) {
        close(fd);
        return error(strerror(errno));
    }

    close(fd);

    return EXIT_SUCCESS;
}

static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b;
    *d ^= *a;
    *d = ROTL32(*d, 16);

    *c += *d;
    *b ^= *c;
    *b = ROTL32(*b, 12);

    *a += *b;
    *d ^= *a;
    *d = ROTL32(*d, 8);

    *c += *d;
    *b ^= *c;
    *b = ROTL32(*b, 7);
}

static void chacha20_block(uint32_t states[16], unsigned char keystream[64]) {
    uint32_t working_state[16];

    ft_memcpy(working_state, states, 16 * sizeof(uint32_t));

    for (int i = 0; i < 10; i++) {
        chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8], &working_state[12]);
        chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9], &working_state[13]);
        chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
        chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);
        chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
        chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
        chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8], &working_state[13]);
        chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9], &working_state[14]);
    }

    for (int i = 0; i < 16; i++)
        working_state[i] += states[i];

    for (int i = 0; i < 16; i++) {
        keystream[i * 4] = working_state[i];
        keystream[i * 4 + 1] = working_state[i] >> 8 & MAX_HEXA;
        keystream[i * 4 + 2] = working_state[i] >> 16 & MAX_HEXA;
        keystream[i * 4 + 3] = working_state[i] >> 24 & MAX_HEXA;
    }
}

/* Genera el keystream bloque a bloque y lo aplica sobre dst.
 * Este es el unico bucle de chaCha20; encrypt y generate_keystream
 * comparten el mismo skeleton y solo difieren en la operacion final
 * (XOR para cifrar, memcpy para extraer el keystream). Extraerlo evita
 * duplicar el recorrido de bloques y el incremento del counter. */
static void chacha20_process(uint32_t states[16], unsigned char *dst,
        const size_t len, const int apply_xor) {
    unsigned char block[64];

    for (size_t i = 0; i < len; i += 64) {
        chacha20_block(states, block);

        states[12]++;

        const size_t n = ((len - i) < 64)
            ? (len - i) : 64;

        if (apply_xor) {
            for (size_t k = 0; k < n; k++)
                dst[i + k] ^= block[k];
        } else {
            ft_memcpy(dst + i, block, n);
        }
    }
}

void chacha20_encrypt(uint32_t states[16], unsigned char *text, const size_t len) {
    chacha20_process(states, text, len, 1);
}

void chacha20_generate_keystream(uint32_t states[16], unsigned char *keystream_out, const size_t len) {
    chacha20_process(states, keystream_out, len, 0);
}
