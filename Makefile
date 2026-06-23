CC = gcc

CFLAGS = -Wall -Wextra -Wpedantic -g

TARGET = sniffer

SRCS = main.c tcp_state.c talkers.c

OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

