//usr/bin/clang "$0" && exec ./a.out "$@"; exit

#include <assert.h>
#include <ctype.h>
#include <iso646.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bip44.h"
#include "bip32.h"

int
main(int argc, char** argv)
{
  HDNode node_test2;
  char *seed_test2_text =
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239"
      "319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
  printf("%s\n", seed_test2_text);
  uint8_t *seed_test2 = fromhex(seed_test2_text);

  Bip44HDPath path = {44, 0, 0, 0, 2};

  const size_t buflen = 128;
  char buf[buflen + 1];

  bip44_path_to_address(seed_test2, path, buf, buflen);


  printf("{} %s\n", buf);

  printf("you can generate bunch of addresses for this seed: https://iancoleman.io/bip39/\n");

  printf("-===============\n");

  char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon "
                   "abandon abandon abandon abandon about";
  uint8_t seed[64];
  bip44_mnemonic_to_seed(mnemonic, seed);

  printf("mnemonic: %s\n", mnemonic);
  printf("seed: ");
  int n;
  for(n=0; n< SHA512_DIGEST_LENGTH; n++) {
    printf("%02x", seed[n]);
  }
  putchar('\n');


  printf("-===============\n");

  char xpriv[112];
  bip44_seed_to_master(seed, xpriv);
  printf("private key of master node from previous mnemonic: \n%s\n", xpriv);
}
