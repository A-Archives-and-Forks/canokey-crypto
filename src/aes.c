// SPDX-License-Identifier: Apache-2.0
#include <aes.h>
#include <block-cipher.h>
#ifdef USE_MBEDCRYPTO
#include <psa/crypto.h>

#define PSA_CHECK(call)                                                                                                \
  do {                                                                                                                 \
    if ((call) != PSA_SUCCESS) return -1;                                                                              \
  } while (0)

static int aes_ecb(const void *in, void *out, const void *key, size_t keybits, psa_key_usage_t usage) {
  PSA_CHECK(psa_crypto_init());

  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attr, keybits);
  psa_set_key_usage_flags(&attr, usage);
  psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);

  psa_key_id_t key_id;
  PSA_CHECK(psa_import_key(&attr, key, keybits / 8, &key_id));

  size_t out_len;
  psa_status_t status;
  if (usage == PSA_KEY_USAGE_ENCRYPT)
    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &out_len);
  else
    status = psa_cipher_decrypt(key_id, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &out_len);

  psa_destroy_key(key_id);
  return status == PSA_SUCCESS ? 0 : -1;
}
#endif

__attribute__((weak)) int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 128, PSA_KEY_USAGE_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 128, PSA_KEY_USAGE_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 256, PSA_KEY_USAGE_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes_ecb(in, out, key, 256, PSA_KEY_USAGE_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes_crypt(aes_mode_t mode, aes_operation_t operation, aes_key_size_t key_size,
                                    const uint8_t *key, const uint8_t iv[AES_BLOCK_SIZE], const uint8_t *in,
                                    uint8_t *out, size_t len) {
  enum BLOCK_CIPHER_MODE block_mode;
  switch (mode) {
  case AES_MODE_ECB:
    block_mode = ECB;
    break;
  case AES_MODE_CBC:
    block_mode = CBC;
    break;
  default:
    return -1;
  }

  if (operation != AES_OP_ENCRYPT && operation != AES_OP_DECRYPT) return -1;
  if (key_size != AES_KEY_128 && key_size != AES_KEY_256) return -1;
  if (len % AES_BLOCK_SIZE != 0) return -1;
  if (len == 0) return 0;
  if (in == NULL || out == NULL || key == NULL || (mode == AES_MODE_CBC && iv == NULL)) return -1;

  block_cipher_config cfg = {
      .mode = block_mode,
      .in = in,
      .in_size = len,
      .out = out,
      .iv = iv,
      .key = key,
      .block_size = AES_BLOCK_SIZE,
      .encrypt = key_size == AES_KEY_128 ? aes128_enc : aes256_enc,
      .decrypt = key_size == AES_KEY_128 ? aes128_dec : aes256_dec,
  };
  return operation == AES_OP_ENCRYPT ? block_cipher_enc(&cfg) : block_cipher_dec(&cfg);
}
