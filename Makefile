CFLAGS=-Wall -lpcap
CC=gcc
C_SOURCES=application.c transport.c network.c data_link.c packet.c main.c
OUTPUT=tsrdump
FILESTOREMOVE=$(OUTPUT)

all:
	$(CC) $(C_SOURCES) $(CFLAGS) -o $(OUTPUT)

clean:
	rm $(FILESTOREMOVE)