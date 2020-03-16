
### what's what

There are only two files that are worth attention
actually: `bip44.h` and `bip44.c`.

BIP32 and BIP39 implementations are completely covered by
[trezor](https://github.com/trezor/trezor-firmware/tree/master/crypto) lib.

That lib is currently vendored inside `contrib` dir without modifications (except one added import).

### how to run

For quick tests there is `sample.c`.

`make sample && ./sample`

### test vectors

I've used [this service](https://iancoleman.io/bip39/) to do a quick check of
things that are not covered by publicly available static test vectors
(for addresses, for example).

### links

[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
[BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
