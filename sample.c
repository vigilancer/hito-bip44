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

  hdnode_from_seed2(seed_test2_text, seed_test2, path, buf, buflen);

  printf("{} %s\n", buf);
}
