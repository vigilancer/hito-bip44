//usr/bin/clang "$0" && exec ./a.out "$@"; exit

#include "curves.h"
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
  int n;
  HDNode node_test2;
  char *seed_test2_text =
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239"
      "319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
  printf("%s\n", seed_test2_text);
  uint8_t *seed_test2 = fromhex(seed_test2_text);

  Bip44HDPath path = {44, 0, 0, 0, 2};

  const size_t buflen = 128;
  char buf[buflen + 1];

  uint32_t address_code = 0; // 0 = pubkey hash. 0x6f = testnet pubkey hash

  bip44_path_to_address(seed_test2, &path, buf, buflen, address_code);

  printf("44'/0'/0'/0/2 address: %s\n", buf);

  uint8_t node_public_key_raw[PUBLIC_KEY_LENGTH];
  uint8_t node_private_key_raw[PRIVATE_KEY_LENGTH];
  char node_private_key_wif[MAX_WIF_SIZE];

  bip44_hdkey_public_raw(seed_test2, &path, node_public_key_raw);
  bip44_hdkey_private_raw(seed_test2, &path, node_private_key_raw);
  bip44_hdkey_private_wif(seed_test2, &path, node_private_key_wif);

  printf("public key (raw): ");
  for (n = 0; n < PUBLIC_KEY_LENGTH; n++) {
    printf("%02x", node_public_key_raw[n]);
  }
  putchar('\n');

  printf("private key (raw): ");
  for (n = 0; n < PRIVATE_KEY_LENGTH; n++) {
    printf("%02x", node_private_key_raw[n]);
  }
  putchar('\n');
  printf("private key (WIF): %s\n", node_private_key_wif);

  printf("\nyou can generate bunch of addresses with keys from this seed here: https://iancoleman.io/bip39/\n");

}
