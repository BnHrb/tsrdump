CFLAGS=-Wall -lpcap
CFLAGS_COMPLETE=-lpcap -g -std=gnu99 -W -Wall -Wextra -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wbad-function-cast -Wcast-qual -Wno-discarded-qualifiers
CC=gcc
C_SOURCES=application.c transport.c network.c data_link.c main.c
OUTPUT=tsrdump
FILESTOREMOVE=$(OUTPUT)

all:
	$(CC) $(C_SOURCES) $(CFLAGS) -o $(OUTPUT)

complete:
	$(CC) $(C_SOURCES) $(CFLAGS_COMPLETE) -o $(OUTPUT)

clean:
	rm $(FILESTOREMOVE)