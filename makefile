

#GCC compiler
BIN=Oauth20

CC=gcc

CFLAGS=-g -c -Wall -I/usr/local/openssl-1.1.0e/include -D__TLS__ -D__UNIX_SOCKET_IPC__
#CFLAGS=-c -Wall -I/usr/local/openssl-1.0.2k/include -D__TLS__

LDFLAGS=-L/usr/local/openssl-1.1.0e/lib
#LDFLAGS=-L/usr/local/openssl-1.0.2k/lib

LIBS=-lssl -lcrypto

SRC=$(shell find . -type f -name '*.c')

OBJ=$(SRC:.c=.o)


all: $(SRC) $(BIN)

$(BIN): $(OBJ)
	$(CC) $(LDFLAGS) $(LIBS) $(OBJ) -o $@


.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -fr *.o
	rm -fr $(BIN)

