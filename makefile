NAME = woody_woodpacker

CC = gcc
CFLAGS = -Wall -Werror -Wextra
SANITIZE = -g3 -fsanitize=address -fsanitize=leak

SRC = src/woody_woodpacker.c
OBJ = $(patsubst src/%.c, obj/%.o, $(SRC))

INCLUDE = -I./inc

.PHONY: all
all: $(NAME)
$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME)

obj/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@

.PHONY: clean
clean:
	$(RM) -r obj

.PHONY: fclean
fclean: clean
	$(RM) $(NAME)

.PHONY: re
re: fclean all

.PHONY: sanitize
sanitize: CFLAGS += $(SANITIZE)
sanitize: clean all