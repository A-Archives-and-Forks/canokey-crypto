/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_AES_H
#define CANOKEY_CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

typedef enum { AES_KEY_128 = 128, AES_KEY_192 = 192, AES_KEY_256 = 256 } aes_key_size_t;
typedef enum { AES_MODE_ECB, AES_MODE_CBC } aes_mode_t;
typedef enum { AES_OP_ENCRYPT, AES_OP_DECRYPT } aes_operation_t;

/**
 * Process complete AES blocks in ECB or CBC mode.
 *
 * The IV is required for CBC and is not modified. Input and output may be the same buffer;
 * otherwise, they must not overlap.
 */
int aes_crypt(aes_mode_t mode, aes_operation_t operation, aes_key_size_t key_size, const uint8_t *key,
              const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in, uint8_t *out, size_t len);

/* Compatibility entry points for one ECB block. */
int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes192_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes192_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
