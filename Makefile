TARGET = ft_ssl
CC = gcc
CFLAG = -g #-Wall -Wextra -Werror
RM = rm -rf

INC = ./include/
SRC = $(wildcard ./src/*.c)
SRC += $(wildcard ./src/block_mode/*.c)
OBJ = $(SRC:.c=.o)

%.o: %.c
	$(CC) $(CFLAG) -c $^ -o $@ -I $(INC)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAG) $(OBJ) -o $@

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(TARGET)

re: fclean all

.PHONY: all clean fclean re
