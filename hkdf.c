#include "hkdf.h"
#include <assert.h>

void sha512(char *in, int inlen, char *out) {
	struct sha512_state s;
	sha512_init(&s);
	sha512_final(&s, in, inlen);
	sha512_get(&s, out, 0, 64);
}

void sha512_256(char *in, int inlen, char *out) {
	struct sha512_state s;
	s.h[0] = 0x22312194FC2BF72CLL;
	s.h[1] = 0x9F555FA3C84C64C2LL;
	s.h[2] = 0x2393B86B6F53B151LL;
	s.h[3] = 0x963877195940EABDLL;
	s.h[4] = 0x96283EE2A88EFFE3LL;
	s.h[5] = 0xBE5E1E2553863992LL;
	s.h[6] = 0x2B0199FC2C85B8AALL;
	s.h[7] = 0x0EB72DDC81C52CA2LL;
	sha512_final(&s, in, inlen);
	sha512_get(&s, out, 0, 32);
}

void hmac_sha512(char *text, int textlen, char *key, int keylen, char *out) {
	assert(textlen<129 && keylen<129);
	char ipad_h[128], opad[128];
	struct sha512_state s;
	memset(ipad_h, 0x36, 128);
	memset(opad, 0x5c, 128);
	for(int i=0; i<keylen; i++) {
		ipad_h[i] ^= key[i];
		opad[i] ^= key[i];
	}
	sha512_init(&s);
	sha512_block(&s, ipad_h);
	sha512_final(&s, text, textlen+128);	
	sha512_get(&s, ipad_h, 0, 64);
	sha512_init(&s);
	sha512_block(&s, opad);
	sha512_final(&s, ipad_h, 128+64);
	sha512_get(&s, out, 0, 64);
}

static void hkdf_sha512_extract(char *salt, int saltlen, char *ikm, int ikmlen, char *outprk) {
	hmac_sha512(ikm, ikmlen, salt, saltlen, outprk);
}

void hkdf_sha512(char *salt, int saltlen, char *ikm, int ikmlen, char *okm, int okmlen) {
	assert(okmlen<65);
	char prk[64], fullokm[64];
	hkdf_sha512_extract(salt, saltlen, ikm, ikmlen, prk);
	const char u[]={0x01};
	hmac_sha512(u, 1, prk, 64, fullokm);
	memcpy(okm, fullokm, okmlen);
}

/*
void main(void) {
	char ikm[]="hkdf test vector";
	char salt[]="$alt";
	char out[64];
	hkdf_sha512(salt, 4, ikm, strlen(ikm), out, 64);
	for(int i=0;i<64;i++)
		printf("%02hhx", out[i]);
	printf("\n");
}
*/
