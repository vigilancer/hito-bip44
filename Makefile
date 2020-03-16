.POSIX:

TREZOR_PATH=./contrib/trezor/crypto

CC = cc
# CFLAGS = -std=c99 -pedantic -Wall -Wextra -Wno-missing-field-initializers \
# 	-I./contrib/trezor/crypto/
CFLAGS= -w

all: sample

get_trezor_lib:
	cd $(TREZOR_PATH) && make tests/libtrezor-crypto.so
	mkdir tests; cp $(TREZOR_PATH)/tests/libtrezor-crypto.so ./tests

sample: libbip44.so
	$(CC) \
		-I$(TREZOR_PATH)\
		-L./tests \
		-L./ \
		-ltrezor-crypto \
		-lbip44 \
		sample.c \
		-o sample

libbip44.so: bip44.o get_trezor_lib
	$(CC) \
		-shared \
		-fPIC \
		-o libbip44.so \
		-L./tests \
		-ltrezor-crypto \
		bip44.o

bip44.o:
	$(CC) -c \
		-I./contrib/trezor/crypto \
		$(CFLAGS) \
		bip44.c \
		bip44.h

clean:
	rm -f \
		*.so \
		*.o \
		./sample
	rm -rf ./tests

clean-all: clean
	cd $(TREZOR_PATH) && make clean


.PHONY: no_targets__ list get_trezor_lib
no_targets__:
# list all available targets. isn't it nice
list:
	sh -c "$(MAKE) -p no_targets__ | awk -F':' '/^[a-zA-Z0-9][^\$$#\/\\t=]*:([^=]|$$)/ {split(\$$1,A,/ /);for(i in A)print A[i]}' | grep -v '__\$$' | sort"
