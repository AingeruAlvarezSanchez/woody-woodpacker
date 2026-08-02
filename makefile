NAME = woody_woodpacker

CC = gcc
CFLAGS = -Wall -Werror -Wextra
SANITIZE = -g3 -fsanitize=address -fsanitize=leak

SRC = src/woody_woodpacker.c src/chacha20.c
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

INCLUDE = -I./inc
LIBFT = libft

.PHONY: all
all: $(NAME)
$(NAME): libft_submodule $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -L$(LIBFT) -lft -o $(NAME)

obj/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(INCLUDE) -I$(LIBFT) $< -o $@

.PHONY: clean
clean:
	$(RM) -r obj
	[ -d $(LIBFT) ] && $(MAKE) clean -C $(LIBFT) || true

.PHONY: fclean
fclean: clean
	$(RM) $(NAME)
	[ -d $(LIBFT) ] && $(MAKE) fclean -C $(LIBFT) || true

.PHONY: re
re: fclean
	git submodule deinit -f $(LIBFT) 2>/dev/null || true
	$(RM) -r .git/modules/$(LIBFT) $(LIBFT)
	$(MAKE) all

.PHONY: libft_submodule
libft_submodule:
	@if [ ! -e $(LIBFT)/.git ]; then \
		if [ -z "$$(git config --file .gitmodules submodule.$(LIBFT).url 2>/dev/null)" ]; then \
			git submodule add --force https://github.com/AingeruAlvarezSanchez/Libft $(LIBFT); \
		fi; \
		git submodule update --init --recursive; \
	fi
	$(MAKE) ext -C $(LIBFT)

.PHONY: sanitize
sanitize: CFLAGS += $(SANITIZE)
sanitize: clean all