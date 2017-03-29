# Maciej Buszka
# 279129

CC=gcc
CFLAGS=-Wall -Wextra -std=gnu99

all : traceroute
clean :
	rm *.o
distclean :
	rm traceroute *.o



traceroute.o : traceroute.c sockets.h
	$(CC) $(CFLAGS) -c traceroute.c

sockets.o : sockets.h sockets.c
	$(CC) $(CFLAGS) -c sockets.c

traceroute : traceroute.o sockets.o
	$(CC) -o traceroute traceroute.o sockets.o
