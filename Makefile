NAME = ft_strace

CC = gcc
CFLAGS = -I includes
RM = rm -rf

SRCS_DIR = srcs
SRCS = $(wildcard $(SRCS_DIR)/*.c)

OBJS_DIR = objs
OBJS = $(SRCS:$(SRCS_DIR)/%.c=$(OBJS_DIR)/%.o)

GREEN = \033[0;32m
RED = \033[0;31m
RESET = \033[0m

all: $(NAME)

$(OBJS_DIR):
	@mkdir -p $(OBJS_DIR)

$(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c | $(OBJS_DIR)
	@printf "$(GREEN)Compiling:$(RESET) $<\n"
	@$(CC) $(CFLAGS) -c $< -o $@

$(NAME): $(OBJS)
	@printf "$(GREEN)Linking:$(RESET) $(NAME)\n"
	@$(CC) $(CFLAGS) $(OBJS) -o $(NAME) -lm
	@printf "$(GREEN)Build complete!$(RESET)\n"

clean:
	@printf "$(RED)Cleaning objects...$(RESET)\n"
	@$(RM) $(OBJS_DIR)

fclean: clean
	@printf "$(RED)Cleaning executable...$(RESET)\n"
	@$(RM) $(NAME)

re: fclean all

.PHONY: all clean fclean re