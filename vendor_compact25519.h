#!/bin/sh
set -x
git clone --depth=1 https://github.com/DavyLandman/compact25519
mkdir compact25519vdr
cp compact25519/LICENSE compact25519vdr/
for f in compact_x25519.c compact_x25519.h compact_wipe.c compact_wipe.h; do
	cp compact25519/src/$f  compact25519vdr/
done
mkdir compact25519vdr/c25519
for f in c25519/c25519.c c25519/c25519.h c25519/f25519.c c25519/f25519.h c25519/sha512.c c25519/sha512.h; do
	cp compact25519/src/$f compact25519vdr/c25519
done

