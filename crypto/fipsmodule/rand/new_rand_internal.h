
#ifndef OPENSSL_HEADER_CRYPTO_RAND_NEW_RAND_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_RAND_NEW_RAND_INTERNAL_H

#if defined(__cplusplus)
extern "C" {
#endif

// kCtrDrbgReseedInterval is the number of generate calls made to CTR-DRBG
// before reseeding.
static const uint64_t kCtrDrbgReseedInterval = 4096;

#define RAND_NO_USER_PRED_RESISTANCE 0
#define RAND_USE_USER_PRED_RESISTANCE 1

#define RAND_PRED_RESISTANCE_LEN 32

int new_rand_RAND_bytes_with_additional_data(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]);
int new_rand_RAND_bytes(uint8_t *out, size_t out_len);
int new_rand_RAND_priv_bytes(uint8_t *out, size_t out_len);
int new_rand_RAND_pseudo_bytes(uint8_t *out, size_t out_len);
int RAND_bytes_with_user_prediction_resistance(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_RAND_NEW_RAND_INTERNAL_H
