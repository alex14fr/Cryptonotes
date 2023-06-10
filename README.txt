Compile with make. 

Uses X25519 key exchange to wrap a ChaCha20 symmetric key.

Usage:

   ./cryp genkey <prefix>
   ./cryp encrypt <recip-key-pub>
   ./cryp decrypt <key-priv>

Example:

# generate X25519 keypair in mykey-priv and mykey-pub
$ ./cryp genkey mykey

# encrypt using public key
$ echo "hello world" | ./cryp encrypt mykey-pub > encrypted

# decrypt using private key
$ ./cryp decrypt mykey-priv < encrypted
hello world


File format: 

   64 bytes of "header" (see below)
   rest of the file: ChaCha20 encrypted stream with IV=I and KEY=C (see below)
   header:
     K = ephemeral sender-generated X25519 public key (32 bytes)
     S = HKDF salt (16 bytes)
     I = Chacha20 iv (16 bytes)
   the "input key material" (IKM) is computed by the sender as:
     IKM = X25519(ephemeral private key, recipient public key)
   or, equivalently, by the recipient as:
     IKM = X25519(recipient private key, ephemeral public key)
   ChaCha20 key C is given by: 
     C = TRUNC(HKDF-SHA512(IKM, salt = S, info = ""))
     where TRUNC returns the first 32 bytes of its 64-byte input



