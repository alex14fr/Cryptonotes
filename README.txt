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

# file format: 
#   ephemeral "sender"-generated X25519 key (32 bytes)
#   salt (16 bytes)
#   rest of the file: ChaCha20 encrypted stream with iv=0, and
#      key=SHA512/256(X25519(ephemeral private key, recipient public key)||salt)
#      key=SHA512/256(X25519(recipient private key, ephemeral public key)||salt)

# decrypt using private key
$ ./cryp decrypt mykey-priv < encrypted
hello world

