LDLIBS=-lcrypto
CFLAGS=-O3 -std=c99 -Wall -Wno-pointer-sign
all: cryp
clean:
	rm -f cryp
