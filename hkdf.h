#include "compact25519vdr/c25519/sha512.h"

extern void sha512(const char*, const int, char* const);
extern void sha512_256(const char*, const int, char* const);
extern void hmac_sha512(const char*, const int, const char*, const int, char* const);
extern void hkdf_sha512(const char*, const int, const char*, const int, char* const, const int);

