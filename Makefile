CFLAGS=-DCOMPACT_DISABLE_ED25519 -std=c99 -O3

CSRD=compact25519/src

LOBJS=chacha20.o $(CSRD)/compact_x25519.o $(CSRD)/compact_wipe.o $(CSRD)/c25519/c25519.o $(CSRD)/c25519/f25519.o $(CSRD)/c25519/sha512.o

all: cryp.o libminicrypto.a
	$(CC)  -o cryp $^

libminicrypto.a: $(LOBJS)
	ar q $@ $^

clean:
	rm -f libminicrypto.a $(LOBJS) cryp

