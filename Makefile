CFLAGS=-Wall -lpcap
YACC_FILE=compiler.y
LEX_FILE=compiler.l
CC=gcc
C_SOURCES=main.c
OUTPUT=tsrdump
FILESTOREMOVE=$(OUTPUT)

all:
	$(CC) $(C_SOURCES) $(CFLAGS) -o $(OUTPUT)

clean:
	rm $(FILESTOREMOVE)