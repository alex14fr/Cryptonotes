#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include "chacha20.h"
#include "compact25519vdr/compact_x25519.h"

#if defined(HAVE_ARC4RANDOM)
#else
#include <sys/random.h>
#endif

void getrand(char *buf, int size) {
#if defined(HAVE_ARC4RANDOM)
	arc4random_buf(buf, size);
#else
	getrandom(buf, size, 0);
#endif
}


void genkey(char *outprefix, char *pkey, char *pubkey) {
	char randseed[X25519_KEY_SIZE];
	getrand(randseed, X25519_KEY_SIZE);
	compact_x25519_keygen(pkey, pubkey, randseed);
	if(outprefix) {
		char fname[256];
		snprintf(fname, 256, "%s-priv", outprefix);
		int f=open(fname, O_WRONLY|O_TRUNC|O_CREAT);
		if(f<0) {
			perror("open");
			exit(1);
		}
		write(f, pkey, X25519_KEY_SIZE);
		close(f);
		snprintf(fname, 256, "%s-pub", outprefix);
		f=open(fname, O_WRONLY|O_TRUNC|O_CREAT);
		if(f<0) {
			perror("open");
			exit(1);
		}
		write(f, pubkey, X25519_KEY_SIZE);
		close(f);
	}
}

void eencrypt(char *fnam) {
	char recipkey[X25519_KEY_SIZE];
	char pkey[X25519_KEY_SIZE];
	char pubkey[X25519_KEY_SIZE];
	char ikm[32];
	char salt[16];
	char iv[16];
	char ch20key[32];
	char *buf=malloc(4096);
	char *bufenc=malloc(4096);
	size_t sz=32;
	int nread=0, nr;

	genkey(NULL, pkey, pubkey);
	write(STDOUT_FILENO, pubkey, X25519_KEY_SIZE);
	getrand(salt, 16);
	write(STDOUT_FILENO, salt, 16);
	getrand(iv, 16);
	write(STDOUT_FILENO, iv, 16);
	int f=open(fnam, O_RDONLY);
	if(f<0) {
		perror("open");
		exit(1);
	}
	while(nread<X25519_KEY_SIZE) {
		nr=read(f, recipkey+nread, X25519_KEY_SIZE-nread);
		if(nr<=0) {
			perror("nread");
			exit(1);
		}
		nread+=nr;
	}
	close(f);
	compact_x25519_shared(ikm, pkey, recipkey);
	hkdf_sha512(salt, 16, ikm, 32, ch20key, 32);

/*
	printf("ch20key=");
	for(int i=0;i<32;i++) { printf("%hhx",ch20key[i]); }
	printf("\n");
*/

	chacha_ctx cctx;
	chacha_keysetup(&cctx, ch20key);
	chacha_ivsetup(&cctx, iv, 0);

	while((nr=read(STDIN_FILENO, buf, 4096))) {
		chacha_encrypt_bytes(&cctx, buf, bufenc, nr);
		write(STDOUT_FILENO, bufenc, nr);
	}

	free(buf);
	free(bufenc);
}

void edecrypt(char *fnam) {
	char pkey[X25519_KEY_SIZE];
	char pubkey[X25519_KEY_SIZE];
	char ikm[32];
	char salt[16];
	char iv[16];
	char ch20key[32];
	char *buf=malloc(4096);
	char *bufenc=malloc(4096);
	int nread=0, nr;

	int f=open(fnam, O_RDONLY);
	if(f<0) {
		perror("open");
		exit(1);
	}
	while(nread<X25519_KEY_SIZE) {
		nr=read(f, pkey+nread, X25519_KEY_SIZE-nread);
		if(nr<=0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	nread=0;
	while(nread<X25519_KEY_SIZE) {
		nr=read(STDIN_FILENO, pubkey+nread, X25519_KEY_SIZE-nread);
		if(nr<0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	nread=0;
	while(nread<16) {
		nr=read(STDIN_FILENO, salt+nread, 16-nread);
		if(nr<0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	nread=0;
	while(nread<16) {
		nr=read(STDIN_FILENO, iv+nread, 16-nread);
		if(nr<0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	compact_x25519_shared(ikm, pkey, pubkey);
	hkdf_sha512(salt, 16, ikm, 32, ch20key, 32);

	/*
	printf("ch20key=");
	for(int i=0;i<32;i++) { printf("%hhx",ch20key[i]); }
	printf("\n");
	*/

	chacha_ctx cctx;
	chacha_keysetup(&cctx, ch20key);
	chacha_ivsetup(&cctx, iv, 0);

	while((nr=read(STDIN_FILENO, buf, 4096))) {
		chacha_encrypt_bytes(&cctx, buf, bufenc, nr);
		write(STDOUT_FILENO, bufenc, nr);
	}

	free(buf);
	free(bufenc);
}

int main(int argc, char **argv) {
	if(argc<2) {
		printf("Usage:\n   %s genkey <prefix>\n   %s encrypt <recip-key-pub>\n   %s decrypt <key-priv>\n", argv[0], argv[0], argv[0]);
		exit(1);
	}
	if(!strcmp(argv[1], "genkey")) {
		char pkey[X25519_KEY_SIZE];
		char pubkey[X25519_KEY_SIZE];
		genkey(argv[2], pkey, pubkey);
	} else if(!strcmp(argv[1], "encrypt")) {
		eencrypt(argv[2]);
	} else if(!strcmp(argv[1], "decrypt")) {
		edecrypt(argv[2]);
	} /* else if(!strcmp(argv[1], "test-sha")) {
		char input[22]="sha512/256 test vector";
		char hash[32];
		sha512_256(input, 22, hash);
		for(int i=0;i<32;i++) printf("%0hhx", hash[i]);
		printf("\n");
	} */
}

