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
#include "bip44.h"


const uint8_t *fromhex(const char *str) {
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

void print_seed(uint8_t seed[]) {
  int n;
  for (n = 0; n < SHA512_DIGEST_LENGTH; n++) {
    printf("%02x", seed[n]);
  }
}

void hdnode_print_private(HDNode *node) {
  char str[112];
  int fingerprint = 0;
  hdnode_serialize_private(&node, fingerprint, VERSION_PRIVATE_MAIN, str,
                           sizeof(str));
  printf("priv: %s\n", str);
  printf("depth: %d\n", node->depth);
}

void hdnode_print_public(HDNode *node) {
  char str[112];
  int fingerprint = 0;
  hdnode_serialize_private(&node, fingerprint, VERSION_PUBLIC_MAIN, str,
                           sizeof(str));
  printf("%s\n", str);
  putchar('\n');
}

void bip44_path_to_address(uint8_t *seed, Bip44HDPath * path,
                           char *buf, uint8_t buflen,
                           uint32_t version

) {
  HDNode node;

  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  hdnode_private_ckd(&node, path->purpose | 0x80000000);
  hdnode_private_ckd(&node, path->coin_type | 0x80000000);
  hdnode_private_ckd(&node, path->account | 0x80000000);
  hdnode_private_ckd(&node, path->chain);
  hdnode_private_ckd(&node, path->address_index);
  hdnode_fill_public_key(&node);

  ecdsa_get_address(node.public_key, version, HASHER_SHA2_RIPEMD,
                    HASHER_SHA2D, buf, buflen);
}

void bip44_mnemonic_to_seed(char * mnemonic, uint8_t seed_out[64]) {
  mnemonic_to_seed(mnemonic, "", seed_out, NULL);
}

void bip44_seed_to_master(uint8_t seed[64], char xpriv_out[112]) {
  HDNode node;
  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);
  hdnode_serialize_private(
      &node,
      0,
      VERSION_PRIVATE_MAIN,
      xpriv_out,
      112
  );
}

void bip44_hdkey_public_raw(
    uint8_t seed[64],
    Bip44HDPath * path,
    uint8_t key_out[PUBLIC_KEY_LENGTH]
) {
  HDNode node;

  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  hdnode_private_ckd(&node, path->purpose | 0x80000000);
  hdnode_private_ckd(&node, path->coin_type | 0x80000000);
  hdnode_private_ckd(&node, path->account | 0x80000000);
  hdnode_private_ckd(&node, path->chain);
  hdnode_private_ckd(&node, path->address_index);
  hdnode_fill_public_key(&node);

  memcpy(key_out, node.public_key, PUBLIC_KEY_LENGTH);
}

void bip44_hdkey_private_raw(
    uint8_t seed[64],
    Bip44HDPath * path,
    uint8_t key_out[PRIVATE_KEY_LENGTH]
) {
  HDNode node;

  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  hdnode_private_ckd(&node, path->purpose | 0x80000000);
  hdnode_private_ckd(&node, path->coin_type | 0x80000000);
  hdnode_private_ckd(&node, path->account | 0x80000000);
  hdnode_private_ckd(&node, path->chain);
  hdnode_private_ckd(&node, path->address_index);

  memcpy(key_out, node.private_key, PRIVATE_KEY_LENGTH);
}

void bip44_hdkey_private_wif(
    uint8_t seed[64],
    Bip44HDPath * path,
    char key_out[MAX_WIF_SIZE]
) {
  HDNode node;

  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  hdnode_private_ckd(&node, path->purpose | 0x80000000);
  hdnode_private_ckd(&node, path->coin_type | 0x80000000);
  hdnode_private_ckd(&node, path->account | 0x80000000);
  hdnode_private_ckd(&node, path->chain);
  hdnode_private_ckd(&node, path->address_index);

  ecdsa_get_wif(node.private_key, 0x80, HASHER_SHA2D, key_out, MAX_WIF_SIZE);
}
