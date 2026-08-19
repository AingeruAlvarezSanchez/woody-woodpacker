NAME = woody_woodpacker

CC = gcc
CFLAGS = -Wall -Werror -Wextra -MMD -MP
SANITIZE = -g3 -fsanitize=address -fsanitize=leak

SRC = src/woody_woodpacker.c src/elf.c src/program_headers.c src/debug.c src/error.c src/chacha20.c src/output.c src/stub.c
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC)) obj/stub_asm.o
DEP = $(OBJ:.o=.d)

INCLUDE = -I./inc
LIBFT = libft

all: libft_submodule $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDE) -I$(LIBFT) $(OBJ) -L$(LIBFT) -lft -o $(NAME)

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) $(INCLUDE) -I$(LIBFT) -c $< -o $@

obj/stub_asm.o: src/stub.S
	@mkdir -p obj
	$(CC) -c $< -o $@

-include $(DEP)

.PHONY: clean
clean:
	$(RM) -r obj
	[ -d $(LIBFT) ] && $(MAKE) clean -C $(LIBFT) || true

.PHONY: fclean
fclean: clean
	$(RM) $(NAME)
	$(RM) woody

.PHONY: re
re: fclean all

.PHONY: libft_submodule
libft_submodule:
	@if [ ! -e $(LIBFT)/.git ]; then \
		if [ -z "$$(git config --file .gitmodules submodule.$(LIBFT).url 2>/dev/null)" ]; then \
			git submodule add --force https://github.com/AingeruAlvarezSanchez/Libft $(LIBFT); \
		fi; \
		git submodule update --init --recursive; \
	fi
	$(MAKE) -C $(LIBFT)

.PHONY: sanitize
sanitize: CFLAGS += $(SANITIZE)
sanitize: clean all
