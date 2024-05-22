# Variables
CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

all: csa_attack

csa_attack: csa_attack.o
	$(CC) $(CFLAGS) -o csa_attack csa_attack.o $(LDFLAGS)

csa_attack.o: csa_attack.c
	$(CC) $(CFLAGS) -c csa_attack.c

clean:
	rm -f *.o csa_attack
