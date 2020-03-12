CC=clang

all:
	$(CC) -w -I./contrib/trezor/crypto/ main.c contrib/trezor/crypto/*.c contrib/trezor/crypto/ed25519-donna/*.c
