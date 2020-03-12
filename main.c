//usr/bin/clang "$0" && exec ./a.out "$@"; exit

#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "pbkdf2.h"
#include "secp256k1.h"
#include <assert.h>
#include <ctype.h>
#include <iso646.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define VERSION_PUBLIC_MAIN 0x0488b21e
#define VERSION_PRIVATE_MAIN 0x0488ade4
#define VERSION_PUBLIC_TEST 0x043587cf
#define VERSION_PRIVATE_TEST 0x04358394

#define FROMHEX_MAXLEN 512

const uint8_t*
fromhex(const char* str)
{
  static uint8_t buf[FROMHEX_MAXLEN];
  size_t len = strlen(str) / 2;
  if (len > FROMHEX_MAXLEN)
    len = FROMHEX_MAXLEN;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9')
      c += (str[i * 2] - '0') << 4;
    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');
    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

int
main(int argc, char** argv)
{
  // test vectors: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
  char* mnemonic = "abandon abandon abandon abandon abandon abandon abandon "
                   "abandon abandon abandon abandon about";
  char* passphrase = "TREZOR";

  uint8_t seed[512 / 8];
  int n;

  mnemonic_to_seed(mnemonic, passphrase, seed, NULL);

  printf("seed: ");
  for (n = 0; n < SHA512_DIGEST_LENGTH; n++) {
    printf("%02x", seed[n]);
  }
  putchar('\n');

  HDNode node;
  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  /* hdnode_fill_public_key(&node); */
  /* hdnode_private_ckd(&node, 44); */

  char str[112];
  int fingerprint = 0;

  hdnode_serialize_private(
    &node, fingerprint, VERSION_PRIVATE_MAIN, str, sizeof(str));

  /* hdnode_fill_public_key(&node); */
  hdnode_serialize_private(
    &node, fingerprint, VERSION_PRIVATE_MAIN, str, sizeof(str));

  printf("mainnet private: %s\n", str);

  hdnode_serialize_private(
    &node, fingerprint, VERSION_PRIVATE_TEST, str, sizeof(str));

  printf("testnet private: %s\n", str);
}
