#include "compact25519vdr/c25519/sha512.h"

extern void sha512(char*, int, char*);
extern void sha512_256(char*, int, char*);
extern void hmac_sha512(char*, int, char*, int, char*);
extern void hkdf_sha512(char*, int, char*, int, char*, int);

