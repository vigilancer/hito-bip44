
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

typedef struct {
  uint32_t purpose;   // hardened. 44 for BIP44
  uint32_t coin_type; // hardened. 0 - bitcoin
  uint32_t account;   // hardened
  uint32_t chain;     // 0 - external, 1 - internal
  uint32_t address_index;
} Bip44HDPath;


/**
 * generate public address for account
 *
 * @param seed - seed to create master node
 * @param path - ex.: m/0'/0'/0'/0/0
 *               purpose, coin_type and account are hardened
 * @param buf - where to store address
 */
void bip44_path_to_address(uint8_t *seed, Bip44HDPath path,
                       char *buf, uint8_t buflen
);

/**
 * generate seed from mnemonic.
 * no check for mnemonic validity is done
 */
void bip44_mnemonic_to_seed(char * mnemonic, uint8_t seed_out[64]);

void bip44_seed_to_master(uint8_t seed[64], char xpriv_out[112]);

// todo (ae): move to separate header for testing. ex.: bip44_test.h
const uint8_t *fromhex(const char *str);
