CFLAGS=-DCOMPACT_DISABLE_ED25519 -std=c99 -O3 -march=native -Wall -Wno-pointer-sign

CSRD=compact25519vdr

LOBJS=chacha20.o hkdf.o $(CSRD)/compact_x25519.o $(CSRD)/compact_wipe.o $(CSRD)/c25519/c25519.o $(CSRD)/c25519/f25519.o $(CSRD)/c25519/sha512.o

all: cryp.o libminicrypto.a
	$(CC) $(LDFLAGS) -o cryp $^

libminicrypto.a: $(LOBJS)
	ar q $@ $^

clean:
	rm -f libminicrypto.a $(LOBJS) cryp

