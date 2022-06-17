
/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sha3.h>
#include <string.h>

// Single-Shot SHA3-224
uint8_t *SHA3_224(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_224_DIGEST_LENGTH]) {
  KECCAK1600_CTX ctx;
  size_t size = 224;
  unsigned char ack = 6;
  SHA3_Init(&ctx, ack, size) && SHA3_Update(&ctx, data, len) &&
                 SHA3_Final(out, &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

// Single-Shot SHA3-256
uint8_t *SHA3_256(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_256_DIGEST_LENGTH]) {
  // We have to verify that all the SHA services actually succeed before
  // updating the indicator state, so we lock the state here.

  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  size_t size = 256;
  unsigned char ack = 6;
  const int ok = SHA3_Init(&ctx, ack, size) && SHA3_Update(&ctx, data, len) &&
                 SHA3_Final(out, &ctx);
  FIPS_service_indicator_unlock_state();
  if (ok) {
    FIPS_service_indicator_update_state();
  }
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

// Single-Shot SHA3-256
uint8_t *SHA3_384(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_384_DIGEST_LENGTH]) {
  // We have to verify that all the SHA services actually succeed before
  // updating the indicator state, so we lock the state here.

  FIPS_service_indicator_lock_state();
  KECCAK1600_CTX ctx;
  unsigned char ack = 6;
  const int ok = SHA3_Init(&ctx, ack, 384) && SHA3_Update(&ctx, data, len) &&
                 SHA3_Final(out, &ctx);
  FIPS_service_indicator_unlock_state();
  if (ok) {
    FIPS_service_indicator_update_state();
  }
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

uint8_t *SHA3_512(const uint8_t *data, size_t len,
                  uint8_t out[SHA3_512_DIGEST_LENGTH]) {
  // We have to verify that all the SHA services actually succeed before
  // updating the indicator state, so we lock the state here.

  KECCAK1600_CTX ctx;
  size_t size = 512;
  unsigned char ack = 6;
  SHA3_Init(&ctx, ack, size) && SHA3_Update(&ctx, data, len) &&
                 SHA3_Final(out, &ctx);
  OPENSSL_cleanse(&ctx, sizeof(ctx));
  return out;
}

void SHA3_Reset(KECCAK1600_CTX *ctx) {
  memset(ctx->A, 0, sizeof(ctx->A));
  ctx->bufsz = 0;
}

int SHA3_Init(KECCAK1600_CTX *ctx, unsigned char pad, size_t bitlen) {
  size_t bsz = SHA3_BLOCKSIZE(bitlen);
  if (bsz <= sizeof(ctx->buf)) {
    SHA3_Reset(ctx);
    ctx->block_size = bsz;
    ctx->md_size = bitlen / 8;
    ctx->pad = pad;
    return 1;
  }
  return 0;
}

int SHA3_keccak_kmac_Init(KECCAK1600_CTX *ctx, unsigned char pad,
                          size_t bitlen) {
  int ret = SHA3_Init(ctx, pad, bitlen);

  if (ret)
    ctx->md_size *= 2;
  return ret;
}

int SHA3_Update(KECCAK1600_CTX *ctx, const void *_inp, size_t len) {
  unsigned char *inp = (unsigned char *)_inp;
  size_t bsz = ctx->block_size;
  size_t num, rem;

  if (len == 0)
    return 1;

  if ((num = ctx->bufsz) != 0) { /* process intermediate buffer? */

    rem = bsz - num;
    if (len < rem) {
      memcpy(ctx->buf + num, inp, len);
      ctx->bufsz += len;
      return 1;
    }
    /*
     * We have enough data to fill or overflow the intermediate
     * buffer. So we append |rem| bytes and process the block,
     * leaving the rest for later processing...
     */
    memcpy(ctx->buf + num, inp, rem);
    inp += rem, len -= rem;
    (void)SHA3_Absorb(ctx->A, ctx->buf, bsz, bsz);
    ctx->bufsz = 0;
    /* ctx->buf is processed, ctx->num is guaranteed to be zero */
  }
  if (len >= bsz)
    rem = SHA3_Absorb(ctx->A, inp, len, bsz);
  else
    rem = len;

  if (rem) {
    memcpy(ctx->buf, inp + len - rem, rem);
    ctx->bufsz = rem;
  }

  return 1;
}

int SHA3_Final(unsigned char *md, KECCAK1600_CTX *ctx) {
  size_t bsz = ctx->block_size;
  size_t num = ctx->bufsz;

  if (ctx->md_size == 0)
    return 1;

  /*
   * Pad the data with 10*1. Note that |num| can be |bsz - 1|
   * in which case both byte operations below are performed on
   * same byte...
   */
  memset(ctx->buf + num, 0, bsz - num);
  ctx->buf[num] = ctx->pad;
  ctx->buf[bsz - 1] |= 0x80;

  (void)SHA3_Absorb(ctx->A, ctx->buf, bsz, bsz);

  SHA3_Squeeze(ctx->A, md, ctx->md_size, bsz);

  return 1;
}
