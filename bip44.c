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

void bip44_path_to_address(uint8_t *seed, Bip44HDPath path,
                           char *buf, uint8_t buflen

) {
  HDNode node;

  const char addr_version = 0x00;

  char str[112];

  /* uint8_t *seed = fromhex(seed_text); */

  /* printf("seed: %s\n", seed); */
  print_seed(seed);
  putchar('\n');

  hdnode_from_seed(seed, 512 / 8, SECP256K1_NAME, &node);

  /* hdnode_serialize_private(const HDNode *node, uint32_t fingerprint, uint32_t
   * version, char *str, int strsize) */

  int fingerprint = 0;

  hdnode_serialize_private(&node, 0, VERSION_PRIVATE_MAIN, str, sizeof(str));
  printf("root: %s\n", str);

  hdnode_private_ckd(&node, path.purpose | 0x80000000);
  hdnode_private_ckd(&node, path.coin_type | 0x80000000);
  hdnode_private_ckd(&node, path.account | 0x80000000);
  hdnode_private_ckd(&node, path.chain);
  hdnode_private_ckd(&node, path.address_index);
  hdnode_fill_public_key(&node);

  ecdsa_get_address(node.public_key, addr_version, HASHER_SHA2_RIPEMD,
                    HASHER_SHA2D, buf, buflen);
}
