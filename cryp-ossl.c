#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define X25519_KEY_SIZE 32

#define getrand RAND_priv_bytes

void genkey(char *outprefix, char *pkey, char *pubkey) {
	getrand(pkey, X25519_KEY_SIZE);
	EVP_PKEY *evpkey=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pkey, X25519_KEY_SIZE);
	if(!evpkey) {
		printf("openssl error\n");
		exit(1);
	}
	size_t sz=32;
	EVP_PKEY_get_raw_public_key(evpkey, pubkey, &sz);
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
		write(f, pubkey, sz);
		close(f);
	}
	EVP_PKEY_free(evpkey);
}

void eencrypt(char *fnam) {
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *evpkey;
	char *recipkey=malloc(X25519_KEY_SIZE);
	char *pkey=malloc(X25519_KEY_SIZE);
	char *pubkey=malloc(X25519_KEY_SIZE);
	char *symkey=malloc(48);
	char *symkeyh=malloc(32);
	char *iv=malloc(16);
	char *buf=malloc(4096);
	char *bufenc=malloc(4096);
	size_t sz=32;
	genkey(NULL, pkey, pubkey);
	evpkey=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pkey, X25519_KEY_SIZE);
	pctx=EVP_PKEY_CTX_new(evpkey, NULL);
	write(STDOUT_FILENO, pubkey, X25519_KEY_SIZE);
	getrand(symkey+32, 16);
	write(STDOUT_FILENO, symkey+32, 16);
	int f=open(fnam, O_RDONLY);
	if(f<0) {
		perror("open");
		exit(1);
	}
	int nread=0, nr;
	while(nread<X25519_KEY_SIZE) {
		nr=read(f, recipkey+nread, X25519_KEY_SIZE-nread);
		if(nr<=0) {
			perror("nread");
			exit(1);
		}
		nread+=nr;
	}
	close(f);
	EVP_PKEY *evprecip=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, recipkey, X25519_KEY_SIZE);
	if(!evprecip) {
		printf("openssl error x\n");
		exit(1);
	}
	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_derive_set_peer(pctx, evprecip);
	memset(iv, 0, 16);
	
	EVP_PKEY_derive(pctx, symkey, &sz);
	if(sz!=32) {
		printf("derive key error");
		exit(1);
	}
	unsigned int szz=32;
	EVP_Digest(symkey, 48, symkeyh, &szz, EVP_sha256(), NULL);
	if(szz!=32) {
		printf("error EVP_Digest\n");
		exit(1);
	}
	EVP_CIPHER_CTX *ciphctx=EVP_CIPHER_CTX_new();
	/*
	printf("symkeyh=");
	for(int i=0;i<32;i++) { printf("%hhx",symkeyh[i]); }
	printf("\n");
	*/
	EVP_EncryptInit(ciphctx, EVP_chacha20(), symkeyh, iv);
	int bufenclen=4096;
	while((nr=read(STDIN_FILENO, buf, 4096))) {
		EVP_EncryptUpdate(ciphctx, bufenc, &bufenclen, buf, nr);
		write(STDOUT_FILENO, bufenc, bufenclen);
	}

	EVP_PKEY_free(evpkey);
	EVP_PKEY_free(evprecip);
	EVP_PKEY_CTX_free(pctx);
	EVP_CIPHER_CTX_free(ciphctx);
	free(recipkey);
	free(pkey);
	free(pubkey);
	free(symkey);
	free(symkeyh);
	free(iv);
	free(buf);
	free(bufenc);

}

void edecrypt(char *fnam) {
	EVP_PKEY_CTX *pctx;
	EVP_PKEY *evpkey, *evpsender;
	char *pkey=malloc(X25519_KEY_SIZE);
	char *pubkey=malloc(X25519_KEY_SIZE);
	char *symkey=malloc(48);
	char *symkeyh=malloc(32);
	char *iv=malloc(16);
	memset(iv, 0, 16);
	char *buf=malloc(4096);
	char *bufenc=malloc(4096);
	size_t sz=32;

	int f=open(fnam, O_RDONLY);
	if(f<0) {
		perror("open");
		exit(1);
	}
	int nread=0, nr;
	while(nread<X25519_KEY_SIZE) {
		nr=read(f, pkey+nread, X25519_KEY_SIZE-nread);
		if(nr<=0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	evpkey=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, pkey, X25519_KEY_SIZE);
	pctx=EVP_PKEY_CTX_new(evpkey, NULL);
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
		nr=read(STDIN_FILENO, symkey+32+nread, 16-nread);
		if(nr<0) {
			perror("read");
			exit(1);
		}
		nread+=nr;
	}
	evpsender=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pubkey, X25519_KEY_SIZE);
	EVP_PKEY_derive_init(pctx);
	EVP_PKEY_derive_set_peer(pctx, evpsender);
	EVP_PKEY_derive(pctx, symkey, &sz);
	if(sz!=32) {
		printf("derive key error");
		exit(1);
	}
	unsigned int szz=32;
	EVP_Digest(symkey, 48, symkeyh, &szz, EVP_sha256(), NULL);
	if(szz!=32) {
		printf("error EVP_Digest\n");
		exit(1);
	}
	/*
	printf("symkeyh=");
	for(int i=0;i<32;i++) { printf("%hhx",symkeyh[i]); }
	printf("\n");
	*/
	EVP_CIPHER_CTX *ciphctx=EVP_CIPHER_CTX_new();
	EVP_EncryptInit(ciphctx, EVP_chacha20(), symkeyh, iv);
	int bufenclen=4096;
	while((nr=read(STDIN_FILENO, buf, 4096))) {
		EVP_EncryptUpdate(ciphctx, bufenc, &bufenclen, buf, nr);
		write(STDOUT_FILENO, bufenc, bufenclen);
	}

	EVP_PKEY_free(evpkey);
	EVP_PKEY_free(evpsender);
	EVP_PKEY_CTX_free(pctx);
	EVP_CIPHER_CTX_free(ciphctx);
	free(pkey);
	free(pubkey);
	free(symkey);
	free(symkeyh);
	free(iv);
	free(buf);
	free(bufenc);
}

int main(int argc, char **argv) {
	if(argc<2) {
		printf("Usage:\n   %s genkey <prefix>\n   %s encrypt <recip-key-pub>\n   %s decrypt <key-priv>\n", argv[0], argv[0], argv[0]);
		exit(1);
	}
	EVP_add_digest(EVP_blake2s256());
	EVP_add_cipher(EVP_chacha20());
	if(!strcmp(argv[1], "genkey")) {
		char *pkey=malloc(X25519_KEY_SIZE);
		char *pubkey=malloc(X25519_KEY_SIZE);
		genkey(argv[2], pkey, pubkey);
		free(pkey);
		free(pubkey);
	} else if(!strcmp(argv[1], "encrypt")) {
		eencrypt(argv[2]);
	} else if(!strcmp(argv[1], "decrypt")) {
		edecrypt(argv[2]);
	}
}

