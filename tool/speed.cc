/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"

#if !defined(OPENSSL_BENCHMARK)
#include "bssl_bm.h"
#else
#include "ossl_bm.h"
#endif

#if defined(OPENSSL_WINDOWS)
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <windows.h>
OPENSSL_MSVC_PRAGMA(warning(pop))
#elif defined(OPENSSL_APPLE)
#include <sys/time.h>
#else
#include <time.h>
#endif

#if !defined(INTERNAL_TOOL)
// align_pointer returns |ptr|, advanced to |alignment|. |alignment| must be a
// power of two, and |ptr| must have at least |alignment - 1| bytes of scratch
// space.
static inline void *align_pointer(void *ptr, size_t alignment) {
  // |alignment| must be a power of two.
  assert(alignment != 0 && (alignment & (alignment - 1)) == 0);
  // Instead of aligning |ptr| as a |uintptr_t| and casting back, compute the
  // offset and advance in pointer space. C guarantees that casting from pointer
  // to |uintptr_t| and back gives the same pointer, but general
  // integer-to-pointer conversions are implementation-defined. GCC does define
  // it in the useful way, but this makes fewer assumptions.
  uintptr_t offset = (0u - (uintptr_t)ptr) & (alignment - 1);
  ptr = (char *)ptr + offset;
  assert(((uintptr_t)ptr & (alignment - 1)) == 0);
  return ptr;
}
#endif

static inline void *BM_memset(void *dst, int c, size_t n) {
  if (n == 0) {
    return dst;
  }

  return memset(dst, c, n);
}

// g_print_json is true if printed output is JSON formatted.
static bool g_print_json = false;

static std::string ChunkLenSuffix(size_t chunk_len) {
  char buf[32];
  snprintf(buf, sizeof(buf), " (%zu byte%s)", chunk_len,
           chunk_len != 1 ? "s" : "");
  return buf;
}

// TimeResults represents the results of benchmarking a function.
struct TimeResults {
  // num_calls is the number of function calls done in the time period.
  uint64_t num_calls;
  // us is the number of microseconds that elapsed in the time period.
  uint64_t us;

  void Print(const std::string &description) const {
    if (g_print_json) {
      PrintJSON(description);
    } else {
      printf(
          "Did %" PRIu64 " %s operations in %" PRIu64 "us (%.1f ops/sec)\n",
          num_calls, description.c_str(), us,
          (static_cast<double>(num_calls) / static_cast<double>(us)) * 1000000);
    }
  }

  void PrintWithBytes(const std::string &description,
                      size_t bytes_per_call) const {
    if (g_print_json) {
      PrintJSON(description, bytes_per_call);
    } else {
      printf(
          "Did %" PRIu64 " %s operations in %" PRIu64
          "us (%.1f ops/sec): %.1f MB/s\n",
          num_calls, (description + ChunkLenSuffix(bytes_per_call)).c_str(), us,
          (static_cast<double>(num_calls) / static_cast<double>(us)) * 1000000,
          static_cast<double>(bytes_per_call * num_calls) /
              static_cast<double>(us));
    }
  }

 private:
  void PrintJSON(const std::string &description,
                 size_t bytes_per_call = 0) const {
    if (first_json_printed) {
      puts(",");
    }

    printf("{\"description\": \"%s\", \"numCalls\": %" PRIu64
           ", \"microseconds\": %" PRIu64,
           description.c_str(), num_calls, us);

    if (bytes_per_call > 0) {
      printf(", \"bytesPerCall\": %zu", bytes_per_call);
    }

    printf("}");
    first_json_printed = true;
  }

  // first_json_printed is true if |g_print_json| is true and the first item in
  // the JSON results has been printed already. This is used to handle the
  // commas between each item in the result list.
  static bool first_json_printed;
};

bool TimeResults::first_json_printed = false;

#if defined(OPENSSL_WINDOWS)
static uint64_t time_now() { return GetTickCount64() * 1000; }
#elif defined(OPENSSL_APPLE)
static uint64_t time_now() {
  struct timeval tv;
  uint64_t ret;

  gettimeofday(&tv, NULL);
  ret = tv.tv_sec;
  ret *= 1000000;
  ret += tv.tv_usec;
  return ret;
}
#else
static uint64_t time_now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  uint64_t ret = ts.tv_sec;
  ret *= 1000000;
  ret += ts.tv_nsec / 1000;
  return ret;
}
#endif

static uint64_t g_timeout_seconds = 1;
static std::vector<size_t> g_chunk_lengths = {16, 256, 1350, 8192, 16384};

static bool TimeFunction(TimeResults *results, std::function<bool()> func) {
  // The first time |func| is called an expensive self check might run that
  // will skew the iterations between checks calculation
  if (!func()) {
    return false;
  }
  // total_us is the total amount of time that we'll aim to measure a function
  // for.
  const uint64_t total_us = g_timeout_seconds * 1000000;
  uint64_t start = time_now(), now, delta;

  if (!func()) {
    return false;
  }
  now = time_now();
  delta = now - start;
  unsigned iterations_between_time_checks;
  if (delta == 0) {
    iterations_between_time_checks = 250;
  } else {
    // Aim for about 100ms between time checks.
    iterations_between_time_checks =
        static_cast<double>(100000) / static_cast<double>(delta);
    if (iterations_between_time_checks > 1000) {
      iterations_between_time_checks = 1000;
    } else if (iterations_between_time_checks < 1) {
      iterations_between_time_checks = 1;
    }
  }

  // Don't include the time taken to run |func| to calculate
  // |iterations_between_time_checks|
  start = time_now();
  uint64_t done = 0;
  for (;;) {
    for (unsigned i = 0; i < iterations_between_time_checks; i++) {
      if (!func()) {
        return false;
      }
      done++;
    }

    now = time_now();
    if (now - start > total_us) {
      break;
    }
  }

  results->us = now - start;
  results->num_calls = done;
  return true;
}

static bool SpeedRSA(const std::string &selected) {
  if (!selected.empty() && selected.find("RSA") == std::string::npos) {
    return true;
  }

  static const struct {
    const char *name;
    const uint8_t *key;
    const size_t key_len;
  } kRSAKeys[] = {
    {"RSA 2048", kDERRSAPrivate2048, kDERRSAPrivate2048Len},
    {"RSA 4096", kDERRSAPrivate4096, kDERRSAPrivate4096Len},
    {"RSA 8192", kDERRSAPrivate8192, kDERRSAPrivate8192Len},
  };

  for (size_t i = 0; i < BM_ARRAY_SIZE(kRSAKeys); i++) {
    const std::string name = kRSAKeys[i].name;

    // d2i_RSAPrivateKey expects to be able to modify the input pointer as it parses the input data and we don't want it
    // to modify the original |*key| data. Therefore create a new temp variable that points to the same data and pass
    // in the reference to it. As a sanity check make sure |input_key| points to the end of the |*key|.
    const uint8_t *input_key = kRSAKeys[i].key;
    BM_NAMESPACE::UniquePtr<RSA> key(d2i_RSAPrivateKey(NULL, &input_key, (long) kRSAKeys[i].key_len));
    if (key == nullptr) {
      fprintf(stderr, "Failed to parse %s key.\n", name.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }

    std::unique_ptr<uint8_t[]> sig(new uint8_t[RSA_size(key.get())]);
    const uint8_t fake_sha256_hash[32] = {0};
    unsigned sig_len;

    TimeResults results;
    if (!TimeFunction(&results,
                      [&key, &sig, &fake_sha256_hash, &sig_len]() -> bool {
          // Usually during RSA signing we're using a long-lived |RSA| that has
          // already had all of its |BN_MONT_CTX|s constructed, so it makes
          // sense to use |key| directly here.
          return RSA_sign(NID_sha256, fake_sha256_hash, sizeof(fake_sha256_hash),
                          sig.get(), &sig_len, key.get());
        })) {
      fprintf(stderr, "RSA_sign failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
    results.Print(name + " signing");

    if (!TimeFunction(&results,
                      [&key, &fake_sha256_hash, &sig, sig_len]() -> bool {
          return RSA_verify(
              NID_sha256, fake_sha256_hash, sizeof(fake_sha256_hash),
              sig.get(), sig_len, key.get());
        })) {
      fprintf(stderr, "RSA_verify failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
    results.Print(name + " verify (same key)");

    if (!TimeFunction(&results,
                      [&key, &fake_sha256_hash, &sig, sig_len]() -> bool {
          // Usually during RSA verification we have to parse an RSA key from a
          // certificate or similar, in which case we'd need to construct a new
          // RSA key, with a new |BN_MONT_CTX| for the public modulus. If we
          // were to use |key| directly instead, then these costs wouldn't be
          // accounted for.
          BM_NAMESPACE::UniquePtr<RSA> verify_key(RSA_new());
          if (!verify_key) {
            return false;
          }
#if defined(OPENSSL_1_0_BENCHMARK)
          const BIGNUM *temp_n = key.get()->n;
          const BIGNUM *temp_e = key.get()->e;
          verify_key.get()->n = BN_dup(temp_n);
          verify_key.get()->e = BN_dup(temp_e);
#else
          const BIGNUM *temp_n = NULL;
          const BIGNUM *temp_e = NULL;

          RSA_get0_key(key.get(), &temp_n, &temp_e, NULL);
          RSA_set0_key(verify_key.get(), BN_dup(temp_n), BN_dup(temp_e), NULL);
#endif

          return RSA_verify(NID_sha256, fake_sha256_hash,
                            sizeof(fake_sha256_hash), sig.get(), sig_len,
                            verify_key.get());
        })) {
      fprintf(stderr, "RSA_verify failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
    results.Print(name + " verify (fresh key)");

// |RSA_private_key_from_bytes| is not available in OpenSSL.
// TODO: Add support for OpenSSL RSA private key parsing benchmarks. Tracked in
//       CryptoAlg-1092.
#if !defined(OPENSSL_BENCHMARK)
    if (!TimeFunction(&results, [&]() -> bool {
          return BM_NAMESPACE::UniquePtr<RSA>(RSA_private_key_from_bytes(
                     kRSAKeys[i].key, kRSAKeys[i].key_len)) != nullptr;
        })) {
      fprintf(stderr, "Failed to parse %s key.\n", name.c_str());
      ERR_print_errors_fp(stderr);
      return false;
    }
    results.Print(name + " private key parse");
#endif
  }

  return true;
}

static bool SpeedRSAKeyGen(const std::string &selected) {
  // Don't run this by default because it's so slow.
  if (selected != "RSAKeyGen") {
    return true;
  }

  BM_NAMESPACE::UniquePtr<BIGNUM> e(BN_new());
  if (!BN_set_word(e.get(), 65537)) {
    return false;
  }

  const std::vector<int> kSizes = {2048, 3072, 4096};
  for (int size : kSizes) {
    const uint64_t start = time_now();
    uint64_t num_calls = 0;
    uint64_t us;
    std::vector<uint64_t> durations;

    for (;;) {
      BM_NAMESPACE::UniquePtr<RSA> rsa(RSA_new());

      const uint64_t iteration_start = time_now();
      if (!RSA_generate_key_ex(rsa.get(), size, e.get(), nullptr)) {
        fprintf(stderr, "RSA_generate_key_ex failed.\n");
        ERR_print_errors_fp(stderr);
        return false;
      }
      const uint64_t iteration_end = time_now();

      num_calls++;
      durations.push_back(iteration_end - iteration_start);

      us = iteration_end - start;
      if (us > 30 * 1000000 /* 30 secs */) {
        break;
      }
    }

    std::sort(durations.begin(), durations.end());
    const std::string description =
        std::string("RSA ") + std::to_string(size) + std::string(" key-gen");
    const TimeResults results = {num_calls, us};
    results.Print(description);
    const size_t n = durations.size();
    assert(n > 0);

    // Distribution information is useful, but doesn't fit into the standard
    // format used by |g_print_json|.
    if (!g_print_json) {
      uint64_t min = durations[0];
      uint64_t median = n & 1 ? durations[n / 2]
                              : (durations[n / 2 - 1] + durations[n / 2]) / 2;
      uint64_t max = durations[n - 1];
      printf("  min: %" PRIu64 "us, median: %" PRIu64 "us, max: %" PRIu64
             "us\n",
             min, median, max);
    }
  }

  return true;
}

static bool SpeedAESGCMChunk(const EVP_CIPHER *cipher, std::string name,
                             size_t chunk_byte_len, size_t ad_len) {
  int len;
  int* len_ptr = &len;
  const size_t key_len = EVP_CIPHER_key_length(cipher);
  static const unsigned kAlignment = 16;
  const size_t iv_len = EVP_CIPHER_iv_length(cipher);
  // GCM uses 16 byte tags
  const size_t overhead_len = 16;
  std::unique_ptr<uint8_t[]> key(new uint8_t[key_len]);
  BM_memset(key.get(), 0, key_len);
  std::unique_ptr<uint8_t[]> nonce(new uint8_t[iv_len]);
  BM_memset(nonce.get(), 0, iv_len);
  std::unique_ptr<uint8_t[]> plaintext_storage(new uint8_t[chunk_byte_len + kAlignment]);
  std::unique_ptr<uint8_t[]> ciphertext_storage(new uint8_t[chunk_byte_len + overhead_len + kAlignment]);
  std::unique_ptr<uint8_t[]> in2_storage(new uint8_t[chunk_byte_len + overhead_len + kAlignment]);
  std::unique_ptr<uint8_t[]> ad(new uint8_t[ad_len]);
  BM_memset(ad.get(), 0, ad_len);
  std::unique_ptr<uint8_t[]> tag_storage(new uint8_t[overhead_len + kAlignment]);

  uint8_t *const plaintext = static_cast<uint8_t *>(align_pointer(plaintext_storage.get(), kAlignment));
  BM_memset(plaintext, 0, chunk_byte_len);
  uint8_t *const ciphertext = static_cast<uint8_t *>(align_pointer(ciphertext_storage.get(), kAlignment));
  BM_memset(ciphertext, 0, chunk_byte_len + overhead_len);
  uint8_t *const tag = static_cast<uint8_t *>(align_pointer(tag_storage.get(), kAlignment));
  BM_memset(tag, 0, overhead_len);

  BM_NAMESPACE::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());

  std::string encryptName = name + " Encrypt";
  TimeResults encryptResults;

  // Call EVP_EncryptInit_ex once with the cipher, in the benchmark loop reuse the cipher
  if (!EVP_EncryptInit_ex(ctx.get(), cipher, NULL, key.get(), nonce.get())){
    fprintf(stderr, "Failed to configure encryption context.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (!TimeFunction(&encryptResults, [&ctx, chunk_byte_len, plaintext, ciphertext, len_ptr, tag, &key, &nonce, &ad, ad_len]() -> bool {
        return EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key.get(), nonce.get()) &&
               EVP_EncryptUpdate(ctx.get(), NULL, len_ptr, ad.get(), ad_len) &&
               EVP_EncryptUpdate(ctx.get(), ciphertext, len_ptr, plaintext, chunk_byte_len) &&
               EVP_EncryptFinal_ex(ctx.get(), ciphertext + *len_ptr, len_ptr) &&
               EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag);
      })) {
    fprintf(stderr, "%s failed.\n", encryptName.c_str());
    ERR_print_errors_fp(stderr);
    return false;
  }

  encryptResults.PrintWithBytes(encryptName, chunk_byte_len);
  std::string decryptName = name + " Decrypt";
  TimeResults decryptResults;
  // Call EVP_DecryptInit_ex once with the cipher, in the benchmark loop reuse the cipher
  if (!EVP_DecryptInit_ex(ctx.get(), cipher, NULL, key.get(), nonce.get())){
    fprintf(stderr, "Failed to configure decryption context.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (!TimeFunction(&decryptResults, [&ctx, chunk_byte_len, plaintext, ciphertext, len_ptr, tag, &key, &nonce, &ad, ad_len]() -> bool {
        return EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key.get(), nonce.get()) &&
               EVP_DecryptUpdate(ctx.get(), NULL, len_ptr, ad.get(), ad_len) &&
               EVP_DecryptUpdate(ctx.get(), plaintext, len_ptr, ciphertext, chunk_byte_len) &&
               EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, tag) &&
               EVP_DecryptFinal_ex(ctx.get(), ciphertext + *len_ptr, len_ptr);
      })) {
    fprintf(stderr, "%s failed.\n", decryptName.c_str());
    ERR_print_errors_fp(stderr);
    return false;
  }
  decryptResults.PrintWithBytes(decryptName, chunk_byte_len);


  return true;
}
static bool SpeedAESGCM(const EVP_CIPHER *cipher, const std::string &name,
                        size_t ad_len, const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_byte_len : g_chunk_lengths) {
    if (!SpeedAESGCMChunk(cipher, name, chunk_byte_len, ad_len)) {
      return false;
    }
  }

  return true;
}

#if !defined(OPENSSL_BENCHMARK)
static bool SpeedAEADChunk(const EVP_AEAD *aead, std::string name,
                           size_t chunk_len, size_t ad_len,
                           evp_aead_direction_t direction) {
  static const unsigned kAlignment = 16;

  BM_NAMESPACE::ScopedEVP_AEAD_CTX ctx;
  const size_t key_len = EVP_AEAD_key_length(aead);
  const size_t nonce_len = EVP_AEAD_nonce_length(aead);
  const size_t overhead_len = EVP_AEAD_max_overhead(aead);

  std::unique_ptr<uint8_t[]> key(new uint8_t[key_len]);
  BM_memset(key.get(), 0, key_len);
  std::unique_ptr<uint8_t[]> nonce(new uint8_t[nonce_len]);
  BM_memset(nonce.get(), 0, nonce_len);
  std::unique_ptr<uint8_t[]> in_storage(new uint8_t[chunk_len + kAlignment]);
  // N.B. for EVP_AEAD_CTX_seal_scatter the input and output buffers may be the
  // same size. However, in the direction == evp_aead_open case we still use
  // non-scattering seal, hence we add overhead_len to the size of this buffer.
  std::unique_ptr<uint8_t[]> out_storage(
      new uint8_t[chunk_len + overhead_len + kAlignment]);
  std::unique_ptr<uint8_t[]> in2_storage(
      new uint8_t[chunk_len + overhead_len + kAlignment]);
  std::unique_ptr<uint8_t[]> ad(new uint8_t[ad_len]);
  BM_memset(ad.get(), 0, ad_len);
  std::unique_ptr<uint8_t[]> tag_storage(
      new uint8_t[overhead_len + kAlignment]);

  uint8_t *const in =
      static_cast<uint8_t *>(align_pointer(in_storage.get(), kAlignment));
  BM_memset(in, 0, chunk_len);
  uint8_t *const out =
      static_cast<uint8_t *>(align_pointer(out_storage.get(), kAlignment));
  BM_memset(out, 0, chunk_len + overhead_len);
  uint8_t *const tag =
      static_cast<uint8_t *>(align_pointer(tag_storage.get(), kAlignment));
  BM_memset(tag, 0, overhead_len);
  uint8_t *const in2 =
      static_cast<uint8_t *>(align_pointer(in2_storage.get(), kAlignment));

  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.get(), key_len,
                                        EVP_AEAD_DEFAULT_TAG_LENGTH,
                                        evp_aead_seal)) {
    fprintf(stderr, "Failed to create EVP_AEAD_CTX.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  TimeResults results;
  if (direction == evp_aead_seal) {
    if (!TimeFunction(&results,
                      [chunk_len, nonce_len, ad_len, overhead_len, in, out, tag,
                       &ctx, &nonce, &ad]() -> bool {
                        size_t tag_len;
                        return EVP_AEAD_CTX_seal_scatter(
                            ctx.get(), out, tag, &tag_len, overhead_len,
                            nonce.get(), nonce_len, in, chunk_len, nullptr, 0,
                            ad.get(), ad_len);
                      })) {
      fprintf(stderr, "EVP_AEAD_CTX_seal failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
  } else {
    size_t out_len;
    EVP_AEAD_CTX_seal(ctx.get(), out, &out_len, chunk_len + overhead_len,
                      nonce.get(), nonce_len, in, chunk_len, ad.get(), ad_len);

    ctx.Reset();
    if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.get(), key_len,
                                          EVP_AEAD_DEFAULT_TAG_LENGTH,
                                          evp_aead_open)) {
      fprintf(stderr, "Failed to create EVP_AEAD_CTX.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }

    if (!TimeFunction(&results,
                      [chunk_len, overhead_len, nonce_len, ad_len, in2, out,
                       out_len, &ctx, &nonce, &ad]() -> bool {
                        size_t in2_len;
                        // N.B. EVP_AEAD_CTX_open_gather is not implemented for
                        // all AEADs.
                        return EVP_AEAD_CTX_open(ctx.get(), in2, &in2_len,
                                                 chunk_len + overhead_len,
                                                 nonce.get(), nonce_len, out,
                                                 out_len, ad.get(), ad_len);
                      })) {
      fprintf(stderr, "EVP_AEAD_CTX_open failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
  }

  results.PrintWithBytes(
      name + (direction == evp_aead_seal ? " seal" : " open"), chunk_len);
  return true;
}

static bool SpeedAEAD(const EVP_AEAD *aead, const std::string &name,
                      size_t ad_len, const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedAEADChunk(aead, name, chunk_len, ad_len, evp_aead_seal)) {
      return false;
    }
  }
  return true;
}

static bool SpeedAEADOpen(const EVP_AEAD *aead, const std::string &name,
                          size_t ad_len, const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedAEADChunk(aead, name, chunk_len, ad_len, evp_aead_open)) {
      return false;
    }
  }

  return true;
}

static bool SpeedSingleKEM(const std::string &name, int nid, const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }
  // Key generation (Alice).
  BM_NAMESPACE::UniquePtr<EVP_PKEY_CTX> a_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
  if (!a_ctx ||
      !EVP_PKEY_CTX_kem_set_params(a_ctx.get(), nid) ||
      !EVP_PKEY_keygen_init(a_ctx.get())) {
    return false;
  }

  EVP_PKEY *key = NULL;
  TimeResults results;
  if (!TimeFunction(&results, [&a_ctx, &key]() -> bool {
        return EVP_PKEY_keygen(a_ctx.get(), &key);
      })) {
    return false;
  }
  results.Print(name + " keygen");

  // Encapsulation setup (Bob).
  BM_NAMESPACE::UniquePtr<EVP_PKEY_CTX> b_ctx(EVP_PKEY_CTX_new(key, nullptr));

  size_t b_ss_len, b_ct_len;
  if (!EVP_PKEY_encapsulate(b_ctx.get(), NULL, &b_ct_len, NULL, &b_ss_len)) {
    return false;
  }
  std::unique_ptr<uint8_t[]> b_ct(new uint8_t[b_ct_len]);
  std::unique_ptr<uint8_t[]> b_ss(new uint8_t[b_ss_len]);

  // Decapsulation setup (Alice).
  a_ctx.reset(EVP_PKEY_CTX_new(key, nullptr));

  size_t a_ss_len;
  if (!EVP_PKEY_decapsulate(a_ctx.get(), NULL, &a_ss_len, NULL, 0)) {
    return false;
  }
  std::unique_ptr<uint8_t[]> a_ss(new uint8_t[a_ss_len]);

  // Sanity check (encaps/decaps gives the same shared secret).
  if (!EVP_PKEY_encapsulate(b_ctx.get(), b_ct.get(), &b_ct_len, b_ss.get(), &b_ss_len) ||
      !EVP_PKEY_decapsulate(a_ctx.get(), a_ss.get(), &a_ss_len, b_ct.get(), b_ct_len) ||
      (a_ss_len != b_ss_len)) {
    return false;
  }
  for (size_t i = 0; i < a_ss_len; i++) {
    if (a_ss.get()[i] != b_ss.get()[i]) {
        return false;
    }
  }

  // Measure encapsulation and decapsulation performance.
  if (!TimeFunction(&results, [&b_ct, &b_ct_len, &b_ss, &b_ss_len, &b_ctx]() -> bool {
        return EVP_PKEY_encapsulate(b_ctx.get(), b_ct.get(), &b_ct_len, b_ss.get(), &b_ss_len);
      })) {
    return false;
  }
  results.Print(name + " encaps");

  if (!TimeFunction(&results, [&b_ct, &b_ct_len, &a_ss, &a_ss_len, &a_ctx]() -> bool {
        return EVP_PKEY_decapsulate(a_ctx.get(), a_ss.get(), &a_ss_len, b_ct.get(), b_ct_len);
      })) {
    return false;
  }
  results.Print(name + " decaps");

  return true;
}


static bool SpeedKEM(std::string selected) {
  return SpeedSingleKEM("Kyber512_R3", NID_KYBER512_R3, selected) &&
         SpeedSingleKEM("Kyber768_R3", NID_KYBER768_R3, selected) &&
         SpeedSingleKEM("Kyber1024_R3", NID_KYBER1024_R3, selected);
}
#endif

static bool SpeedAESBlock(const std::string &name, unsigned bits,
                          const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  static const uint8_t kZero[32] = {0};

  {
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          AES_KEY key;
          return AES_set_encrypt_key(kZero, bits, &key) == 0;
        })) {
      fprintf(stderr, "AES_set_encrypt_key failed.\n");
      return false;
    }
    results.Print(name + " encrypt setup");
  }

  {
    AES_KEY key;
    if (AES_set_encrypt_key(kZero, bits, &key) != 0) {
      return false;
    }
    uint8_t block[16] = {0};
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          AES_encrypt(block, block, &key);
          return true;
        })) {
      fprintf(stderr, "AES_encrypt failed.\n");
      return false;
    }
    results.Print(name + " encrypt");
  }

  {
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          AES_KEY key;
          return AES_set_decrypt_key(kZero, bits, &key) == 0;
        })) {
      fprintf(stderr, "AES_set_decrypt_key failed.\n");
      return false;
    }
    results.Print(name + " decrypt setup");
  }

  {
    AES_KEY key;
    if (AES_set_decrypt_key(kZero, bits, &key) != 0) {
      return false;
    }
    uint8_t block[16] = {0};
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          AES_decrypt(block, block, &key);
          return true;
        })) {
      fprintf(stderr, "AES_decrypt failed.\n");
      return false;
    }
    results.Print(name + " decrypt");
  }

  return true;
}

static bool SpeedAES256XTS(const std::string &name, //const size_t in_len,
                           const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  const EVP_CIPHER *cipher = EVP_aes_256_xts();
  const size_t key_len = EVP_CIPHER_key_length(cipher);
  const size_t iv_len = EVP_CIPHER_iv_length(cipher);

  std::vector<uint8_t> key(key_len);
  std::vector<uint8_t> iv(iv_len, 9);
  std::vector<uint8_t> in, out;

  // key = key1||key2 and key1 should not equal key2
  std::generate(key.begin(), key.end(), [] {
    static uint8_t i = 0;
    return i++;
  });

  BM_NAMESPACE::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  // Benchmark initialisation and encryption
  for (size_t in_len : g_chunk_lengths) {
    in.resize(in_len);
    out.resize(in_len);
    std::fill(in.begin(), in.end(), 0x5a);
    int len;
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          if (!EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data(),
                                  iv.data()) ||
              !EVP_EncryptUpdate(ctx.get(), out.data(), &len, in.data(),
                                 in.size())) {
            return false;
          }
          return true;
        })) {
      fprintf(stderr, "AES-256-XTS initialisation or encryption failed.\n");
      return false;
    }
    results.PrintWithBytes(name + " init and encrypt",
                           in_len);
  }

  // Benchmark initialisation and decryption
  for (size_t in_len : g_chunk_lengths) {
    in.resize(in_len);
    out.resize(in_len);
    std::fill(in.begin(), in.end(), 0x5a);
    int len;
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          if (!EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data(),
                                  iv.data()) ||
              !EVP_DecryptUpdate(ctx.get(), out.data(), &len, in.data(),
                                 in.size())) {
            return false;
          }
          return true;
        })) {
      fprintf(stderr, "AES-256-XTS initialisation or decryption failed.\n");
      return false;
    }
    results.PrintWithBytes(name + " init and decrypt",
                           in_len);
  }

  return true;
}

static bool SpeedHashChunk(const EVP_MD *md, std::string name,
                           size_t chunk_len) {
  // OpenSSL 1.0.x has a different API to create an EVP_MD_CTX
#if defined(OPENSSL_1_0_BENCHMARK)
  BM_NAMESPACE::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_create());
#else
  BM_NAMESPACE::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
#endif
  std::unique_ptr<uint8_t[]> input(new uint8_t[chunk_len]);

  TimeResults results;
  if (!TimeFunction(&results, [&ctx, md, chunk_len, &input]() -> bool {
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        return EVP_DigestInit_ex(ctx.get(), md, NULL /* ENGINE */) &&
               EVP_DigestUpdate(ctx.get(), input.get(), chunk_len) &&
               EVP_DigestFinal_ex(ctx.get(), digest, &md_len);
      })) {
    fprintf(stderr, "EVP_DigestInit_ex failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  results.PrintWithBytes(name, chunk_len);
  return true;
}

static bool SpeedHash(const EVP_MD *md, const std::string &name,
                      const std::string &selected) {
  // This SHA3 API is AWS-LC specific.
#if defined(OPENSSL_IS_AWSLC)
  if (name.find("SHA3") != std::string::npos) {
    EVP_MD_unstable_sha3_enable(true);
  }
#endif

  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedHashChunk(md, name, chunk_len)) {
      return false;
    }
  }

  // This SHA3 API is AWS-LC specific.
#if defined(OPENSSL_IS_AWSLC)
  EVP_MD_unstable_sha3_enable(false);
#endif
  return true;
}

static bool SpeedHmacChunk(const EVP_MD *md, std::string name,
                           size_t chunk_len) {
  // OpenSSL 1.0.x doesn't have a function that creates a new,
  // properly initialized HMAC pointer so we need to create 
  // the pointer and then do the initialization logic ourselves
#if defined(OPENSSL_1_0_BENCHMARK)
  BM_NAMESPACE::UniquePtr<HMAC_CTX> ctx(new HMAC_CTX);
  HMAC_CTX_init(ctx.get());
#else
  BM_NAMESPACE::UniquePtr<HMAC_CTX> ctx(HMAC_CTX_new());
#endif
  uint8_t scratch[16384];
  const size_t key_len = EVP_MD_size(md);
  std::unique_ptr<uint8_t[]> key(new uint8_t[key_len]);
  BM_memset(key.get(), 0, key_len);

  if (chunk_len > sizeof(scratch)) {
    return false;
  }

  if (!HMAC_Init_ex(ctx.get(), key.get(), key_len, md, NULL /* ENGINE */)) {
    fprintf(stderr, "Failed to create HMAC_CTX.\n");
  }
  TimeResults results;
  if (!TimeFunction(&results, [&ctx, chunk_len, &scratch]() -> bool {
        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int md_len;

        return HMAC_Init_ex(ctx.get(), NULL, 0, NULL, NULL) &&
               HMAC_Update(ctx.get(), scratch, chunk_len) &&
               HMAC_Final(ctx.get(), digest, &md_len);
      })) {
    fprintf(stderr, "HMAC_Final failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  results.PrintWithBytes(name, chunk_len);
  return true;
}

static bool SpeedHmac(const EVP_MD *md, const std::string &name,
                      const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedHmacChunk(md, name, chunk_len)) {
      return false;
    }
  }

  return true;
}

static bool SpeedHmacChunkOneShot(const EVP_MD *md, std::string name,
                           size_t chunk_len) {
  uint8_t scratch[16384];
  const size_t key_len = EVP_MD_size(md);
  std::unique_ptr<uint8_t[]> key(new uint8_t[key_len]);
  BM_memset(key.get(), 0, key_len);

  if (chunk_len > sizeof(scratch)) {
    return false;
  }

  TimeResults results;
  if (!TimeFunction(&results, [&key, key_len, md, chunk_len, &scratch]() -> bool {

        uint8_t digest[EVP_MAX_MD_SIZE] = {0};
        unsigned int md_len = EVP_MAX_MD_SIZE;

        return HMAC(md, key.get(), key_len, scratch, chunk_len, digest, &md_len) != nullptr;
      })) {
    fprintf(stderr, "HMAC_Final failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  results.PrintWithBytes(name, chunk_len);
  return true;
}

static bool SpeedHmacOneShot(const EVP_MD *md, const std::string &name,
                      const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedHmacChunkOneShot(md, name, chunk_len)) {
      return false;
    }
  }

  return true;
}

static bool SpeedRandomChunk(std::string name, size_t chunk_len) {
  uint8_t scratch[16384];

  if (chunk_len > sizeof(scratch)) {
    return false;
  }

  TimeResults results;
  if (!TimeFunction(&results, [chunk_len, &scratch]() -> bool {
        RAND_bytes(scratch, chunk_len);
        return true;
      })) {
    return false;
  }

  results.PrintWithBytes(name, chunk_len);
  return true;
}

static bool SpeedRandom(const std::string &selected) {
  if (!selected.empty() && selected != "RNG") {
    return true;
  }

  for (size_t chunk_len : g_chunk_lengths) {
    if (!SpeedRandomChunk("RNG", chunk_len)) {
      return false;
    }
  }

  return true;
}

static bool SpeedECDHCurve(const std::string &name, int nid,
                           const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  BM_NAMESPACE::UniquePtr<EC_KEY> peer_key(EC_KEY_new_by_curve_name(nid));
  if (!peer_key ||
      !EC_KEY_generate_key(peer_key.get())) {
    return false;
  }

  size_t peer_value_len = EC_POINT_point2oct(
      EC_KEY_get0_group(peer_key.get()), EC_KEY_get0_public_key(peer_key.get()),
      POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (peer_value_len == 0) {
    return false;
  }
  std::unique_ptr<uint8_t[]> peer_value(new uint8_t[peer_value_len]);
  peer_value_len = EC_POINT_point2oct(
      EC_KEY_get0_group(peer_key.get()), EC_KEY_get0_public_key(peer_key.get()),
      POINT_CONVERSION_UNCOMPRESSED, peer_value.get(), peer_value_len, nullptr);
  if (peer_value_len == 0) {
    return false;
  }

  TimeResults results;
  if (!TimeFunction(&results, [nid, peer_value_len, &peer_value]() -> bool {
        BM_NAMESPACE::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
        if (!key ||
            !EC_KEY_generate_key(key.get())) {
          return false;
        }
        const EC_GROUP *const group = EC_KEY_get0_group(key.get());
        BM_NAMESPACE::UniquePtr<EC_POINT> point(EC_POINT_new(group));
        BM_NAMESPACE::UniquePtr<EC_POINT> peer_point(EC_POINT_new(group));
        BM_NAMESPACE::UniquePtr<BN_CTX> ctx(BN_CTX_new());
        BM_NAMESPACE::UniquePtr<BIGNUM> x(BN_new());
        if (!point || !peer_point || !ctx || !x ||
            !EC_POINT_oct2point(group, peer_point.get(), peer_value.get(),
                                peer_value_len, ctx.get()) ||
            !EC_POINT_mul(group, point.get(), nullptr, peer_point.get(),
                          EC_KEY_get0_private_key(key.get()), ctx.get()) ||
            !EC_POINT_get_affine_coordinates_GFp(group, point.get(), x.get(),
                                                 nullptr, ctx.get())) {
          return false;
        }

        return true;
      })) {
    return false;
  }

  results.Print(name);
  return true;
}

static bool SpeedECKeyGenCurve(const std::string &name, int nid,
                            const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  // Setup CTX for EC Operations
  BM_NAMESPACE::UniquePtr<EVP_PKEY_CTX> pkey_ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));

  // Setup CTX for Keygen Operations
  if (!pkey_ctx || EVP_PKEY_keygen_init(pkey_ctx.get()) != 1) {
    return false;
  }

  // Set CTX to use our curve
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkey_ctx.get(), nid) != 1) {
    return false;
  }

  EVP_PKEY *key = NULL;

  TimeResults results;
  if (!TimeFunction(&results, [&pkey_ctx, &key]() -> bool {
        return EVP_PKEY_keygen(pkey_ctx.get(), &key);
      })) {
      return false;
  }
  results.Print(name);
  return true;
}

static bool SpeedECDSACurve(const std::string &name, int nid,
                            const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  BM_NAMESPACE::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (!key ||
      !EC_KEY_generate_key(key.get())) {
    return false;
  }

  uint8_t signature[256];
  if (BM_ECDSA_size(key.get()) > sizeof(signature)) {
    return false;
  }
  uint8_t digest[20];
  BM_memset(digest, 42, sizeof(digest));
  unsigned sig_len;

  TimeResults results;
  if (!TimeFunction(&results, [&key, &signature, &digest, &sig_len]() -> bool {
        return ECDSA_sign(0, digest, sizeof(digest), signature, &sig_len,
                          key.get()) == 1;
      })) {
    return false;
  }

  results.Print(name + " signing");

  if (!TimeFunction(&results, [&key, &signature, &digest, sig_len]() -> bool {
        return ECDSA_verify(0, digest, sizeof(digest), signature, sig_len,
                            key.get()) == 1;
      })) {
    return false;
  }

  results.Print(name + " verify");

  return true;
}

static bool SpeedECDH(const std::string &selected) {
  return SpeedECDHCurve("ECDH P-224", NID_secp224r1, selected) &&
         SpeedECDHCurve("ECDH P-256", NID_X9_62_prime256v1, selected) &&
         SpeedECDHCurve("ECDH P-384", NID_secp384r1, selected) &&
         SpeedECDHCurve("ECDH P-521", NID_secp521r1, selected) &&
         SpeedECDHCurve("ECDH secp256k1", NID_secp256k1, selected);
}

static bool SpeedECKeyGen(const std::string &selected) {
  return SpeedECKeyGenCurve("Generate P-224", NID_secp224r1, selected) &&
         SpeedECKeyGenCurve("Generate P-256", NID_X9_62_prime256v1, selected) &&
         SpeedECKeyGenCurve("Generate P-384", NID_secp384r1, selected) &&
         SpeedECKeyGenCurve("Generate P-521", NID_secp521r1, selected) &&
         SpeedECKeyGenCurve("Generate secp256k1", NID_secp256k1, selected);
}

static bool SpeedECDSA(const std::string &selected) {
  return SpeedECDSACurve("ECDSA P-224", NID_secp224r1, selected) &&
         SpeedECDSACurve("ECDSA P-256", NID_X9_62_prime256v1, selected) &&
         SpeedECDSACurve("ECDSA P-384", NID_secp384r1, selected) &&
         SpeedECDSACurve("ECDSA P-521", NID_secp521r1, selected) &&
         SpeedECDSACurve("ECDSA secp256k1", NID_secp256k1, selected);
}


#if !defined(OPENSSL_1_0_BENCHMARK)
static bool SpeedECMULCurve(const std::string &name, int nid,
                       const std::string &selected) {
  if (!selected.empty() && name.find(selected) == std::string::npos) {
    return true;
  }

  EC_GROUP *group = EC_GROUP_new_by_curve_name(nid);
  BN_CTX   *ctx = BN_CTX_new();

  BIGNUM *scalar0 = BN_new();
  BIGNUM *scalar1 = BN_new();

  EC_POINT *pin0 = EC_POINT_new(group);
  EC_POINT *pout = EC_POINT_new(group);

  // Generate two random scalars modulo the EC group order.
  if (!BN_rand_range(scalar0, EC_GROUP_get0_order(group)) ||
      !BN_rand_range(scalar1, EC_GROUP_get0_order(group))) {
      return false;
  }

  // Generate one random EC point.
  EC_POINT_mul(group, pin0, scalar0, nullptr, nullptr, ctx);

  TimeResults results;

  // Measure scalar multiplication of an arbitrary curve point.
  if (!TimeFunction(&results, [group, pout, ctx, pin0, scalar0]() -> bool {
        if (!EC_POINT_mul(group, pout, nullptr, pin0, scalar0, ctx)) {
          return false;
        }

        return true;
      })) {
    return false;
  }
  results.Print(name + " mul");

  // Measure scalar multiplication of the curve based point.
  if (!TimeFunction(&results, [group, pout, ctx, scalar0]() -> bool {
        if (!EC_POINT_mul(group, pout, scalar0, nullptr, nullptr, ctx)) {
          return false;
        }

        return true;
      })) {
    return false;
  }
  results.Print(name + " mul base");

  // Measure scalar multiplication of based point and arbitrary point.
  if (!TimeFunction(&results, [group, pout, pin0, ctx, scalar0, scalar1]() -> bool {
        if (!EC_POINT_mul(group, pout, scalar1, pin0, scalar0, ctx)) {
          return false;
        }

        return true;
      })) {
    return false;
  }
  results.Print(name + " mul public");

  return true;
}

static bool SpeedECMUL(const std::string &selected) {
  return SpeedECMULCurve("ECMUL P-224", NID_secp224r1, selected) &&
         SpeedECMULCurve("ECMUL P-256", NID_X9_62_prime256v1, selected) &&
         SpeedECMULCurve("ECMUL P-384", NID_secp384r1, selected) &&
         SpeedECMULCurve("ECMUL P-521", NID_secp521r1, selected) &&
         SpeedECMULCurve("ECMUL secp256k1", NID_secp256k1, selected);
}
#endif

#if !defined(OPENSSL_BENCHMARK)
static bool Speed25519(const std::string &selected) {
  if (!selected.empty() && selected.find("25519") == std::string::npos) {
    return true;
  }

  TimeResults results;

  uint8_t public_key[32], private_key[64];

  if (!TimeFunction(&results, [&public_key, &private_key]() -> bool {
        ED25519_keypair(public_key, private_key);
        return true;
      })) {
    return false;
  }

  results.Print("Ed25519 key generation");

  static const uint8_t kMessage[] = {0, 1, 2, 3, 4, 5};
  uint8_t signature[64];

  if (!TimeFunction(&results, [&private_key, &signature]() -> bool {
        return ED25519_sign(signature, kMessage, sizeof(kMessage),
                            private_key) == 1;
      })) {
    return false;
  }

  results.Print("Ed25519 signing");

  if (!TimeFunction(&results, [&public_key, &signature]() -> bool {
        return ED25519_verify(kMessage, sizeof(kMessage), signature,
                              public_key) == 1;
      })) {
    fprintf(stderr, "Ed25519 verify failed.\n");
    return false;
  }

  results.Print("Ed25519 verify");

  if (!TimeFunction(&results, []() -> bool {
        uint8_t out[32], in[32];
        BM_memset(in, 0, sizeof(in));
        X25519_public_from_private(out, in);
        return true;
      })) {
    fprintf(stderr, "Curve25519 base-point multiplication failed.\n");
    return false;
  }

  results.Print("Curve25519 base-point multiplication");

  if (!TimeFunction(&results, []() -> bool {
        uint8_t out[32], in1[32], in2[32];
        BM_memset(in1, 0, sizeof(in1));
        BM_memset(in2, 0, sizeof(in2));
        in1[0] = 1;
        in2[0] = 9;
        return X25519(out, in1, in2) == 1;
      })) {
    fprintf(stderr, "Curve25519 arbitrary point multiplication failed.\n");
    return false;
  }

  results.Print("Curve25519 arbitrary point multiplication");

  if (!TimeFunction(&results, []() -> bool {
        uint8_t out_base[32], in_base[32];
        BM_memset(in_base, 0, sizeof(in_base));
        X25519_public_from_private(out_base, in_base);

        uint8_t out[32], in1[32], in2[32];
        BM_memset(in1, 0, sizeof(in1));
        BM_memset(in2, 0, sizeof(in2));
        in1[0] = 1;
        in2[0] = 9;
        return X25519(out, in1, in2) == 1;
      })) {
    fprintf(stderr, "ECDH X25519 failed.\n");
    return false;
  }

  results.Print("ECDH X25519");

  return true;
}

static bool SpeedSPAKE2(const std::string &selected) {
  if (!selected.empty() && selected.find("SPAKE2") == std::string::npos) {
    return true;
  }

  TimeResults results;

  static const uint8_t kAliceName[] = {'A'};
  static const uint8_t kBobName[] = {'B'};
  static const uint8_t kPassword[] = "password";
  BM_NAMESPACE::UniquePtr<SPAKE2_CTX> alice(SPAKE2_CTX_new(spake2_role_alice,
                                    kAliceName, sizeof(kAliceName), kBobName,
                                    sizeof(kBobName)));
  uint8_t alice_msg[SPAKE2_MAX_MSG_SIZE];
  size_t alice_msg_len;

  if (!SPAKE2_generate_msg(alice.get(), alice_msg, &alice_msg_len,
                           sizeof(alice_msg),
                           kPassword, sizeof(kPassword))) {
    fprintf(stderr, "SPAKE2_generate_msg failed.\n");
    return false;
  }

  if (!TimeFunction(&results, [&alice_msg, alice_msg_len]() -> bool {
        BM_NAMESPACE::UniquePtr<SPAKE2_CTX> bob(SPAKE2_CTX_new(spake2_role_bob,
                                        kBobName, sizeof(kBobName), kAliceName,
                                        sizeof(kAliceName)));
        uint8_t bob_msg[SPAKE2_MAX_MSG_SIZE], bob_key[64];
        size_t bob_msg_len, bob_key_len;
        if (!SPAKE2_generate_msg(bob.get(), bob_msg, &bob_msg_len,
                                 sizeof(bob_msg), kPassword,
                                 sizeof(kPassword)) ||
            !SPAKE2_process_msg(bob.get(), bob_key, &bob_key_len,
                                sizeof(bob_key), alice_msg, alice_msg_len)) {
          return false;
        }

        return true;
      })) {
    fprintf(stderr, "SPAKE2 failed.\n");
  }

  results.Print("SPAKE2 over Ed25519");

  return true;
}
#endif

#if !defined(OPENSSL_1_0_BENCHMARK)
static bool SpeedScrypt(const std::string &selected) {
  if (!selected.empty() && selected.find("scrypt") == std::string::npos) {
    return true;
  }

  TimeResults results;

  static const char kPassword[] = "passwordPASSWORD";
  static const uint8_t kSalt[] = "NaClSodiumChloride";

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t out[64];
        return !!EVP_PBE_scrypt(kPassword, sizeof(kPassword) - 1, kSalt,
                                sizeof(kSalt) - 1, 1024, 8, 16, 0 /* max_mem */,
                                out, sizeof(out));
      })) {
    fprintf(stderr, "scrypt failed.\n");
    return false;
  }
  results.Print("scrypt (N = 1024, r = 8, p = 16)");

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t out[64];
        return !!EVP_PBE_scrypt(kPassword, sizeof(kPassword) - 1, kSalt,
                                sizeof(kSalt) - 1, 16384, 8, 1, 0 /* max_mem */,
                                out, sizeof(out));
      })) {
    fprintf(stderr, "scrypt failed.\n");
    return false;
  }
  results.Print("scrypt (N = 16384, r = 8, p = 1)");

  return true;
}
#endif

#if !defined(OPENSSL_BENCHMARK)
static bool SpeedHRSS(const std::string &selected) {
  if (!selected.empty() && selected != "HRSS") {
    return true;
  }

  TimeResults results;

  if (!TimeFunction(&results, []() -> bool {
        struct HRSS_public_key pub;
        struct HRSS_private_key priv;
        uint8_t entropy[HRSS_GENERATE_KEY_BYTES];
        RAND_bytes(entropy, sizeof(entropy));
        return HRSS_generate_key(&pub, &priv, entropy);
      })) {
    fprintf(stderr, "Failed to time HRSS_generate_key.\n");
    return false;
  }

  results.Print("HRSS generate");

  struct HRSS_public_key pub;
  struct HRSS_private_key priv;
  uint8_t key_entropy[HRSS_GENERATE_KEY_BYTES];
  RAND_bytes(key_entropy, sizeof(key_entropy));
  if (!HRSS_generate_key(&pub, &priv, key_entropy)) {
    return false;
  }

  uint8_t ciphertext[HRSS_CIPHERTEXT_BYTES];
  if (!TimeFunction(&results, [&pub, &ciphertext]() -> bool {
        uint8_t entropy[HRSS_ENCAP_BYTES];
        uint8_t shared_key[HRSS_KEY_BYTES];
        RAND_bytes(entropy, sizeof(entropy));
        return HRSS_encap(ciphertext, shared_key, &pub, entropy);
      })) {
    fprintf(stderr, "Failed to time HRSS_encap.\n");
    return false;
  }

  results.Print("HRSS encap");

  if (!TimeFunction(&results, [&priv, &ciphertext]() -> bool {
        uint8_t shared_key[HRSS_KEY_BYTES];
        return HRSS_decap(shared_key, &priv, ciphertext, sizeof(ciphertext));
      })) {
    fprintf(stderr, "Failed to time HRSS_encap.\n");
    return false;
  }

  results.Print("HRSS decap");

  return true;
}

#if defined(INTERNAL_TOOL)
static bool SpeedHashToCurve(const std::string &selected) {
  if (!selected.empty() && selected.find("hashtocurve") == std::string::npos) {
    return true;
  }

  uint8_t input[64];
  RAND_bytes(input, sizeof(input));

  static const uint8_t kLabel[] = "label";

  TimeResults results;
  {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp384r1);
    if (group == NULL) {
      return false;
    }
    if (!TimeFunction(&results, [&]() -> bool {
          EC_RAW_POINT out;
          return ec_hash_to_curve_p384_xmd_sha512_sswu_draft07(
              group, &out, kLabel, sizeof(kLabel), input, sizeof(input));
        })) {
      fprintf(stderr, "hash-to-curve failed.\n");
      return false;
    }
    results.Print("hash-to-curve P384_XMD:SHA-512_SSWU_RO_");

    if (!TimeFunction(&results, [&]() -> bool {
          EC_SCALAR out;
          return ec_hash_to_scalar_p384_xmd_sha512_draft07(
              group, &out, kLabel, sizeof(kLabel), input, sizeof(input));
        })) {
      fprintf(stderr, "hash-to-scalar failed.\n");
      return false;
    }
    results.Print("hash-to-scalar P384_XMD:SHA-512");
  }

  return true;
}
#endif

static bool SpeedBase64(const std::string &selected) {
  if (!selected.empty() && selected.find("base64") == std::string::npos) {
    return true;
  }

  static const char kInput[] =
    "MIIDtTCCAp2gAwIBAgIJALW2IrlaBKUhMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV"
    "BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX"
    "aWRnaXRzIFB0eSBMdGQwHhcNMTYwNzA5MDQzODA5WhcNMTYwODA4MDQzODA5WjBF"
    "MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50"
    "ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB"
    "CgKCAQEAugvahBkSAUF1fC49vb1bvlPrcl80kop1iLpiuYoz4Qptwy57+EWssZBc"
    "HprZ5BkWf6PeGZ7F5AX1PyJbGHZLqvMCvViP6pd4MFox/igESISEHEixoiXCzepB"
    "rhtp5UQSjHD4D4hKtgdMgVxX+LRtwgW3mnu/vBu7rzpr/DS8io99p3lqZ1Aky+aN"
    "lcMj6MYy8U+YFEevb/V0lRY9oqwmW7BHnXikm/vi6sjIS350U8zb/mRzYeIs2R65"
    "LUduTL50+UMgat9ocewI2dv8aO9Dph+8NdGtg8LFYyTTHcUxJoMr1PTOgnmET19W"
    "JH4PrFwk7ZE1QJQQ1L4iKmPeQistuQIDAQABo4GnMIGkMB0GA1UdDgQWBBT5m6Vv"
    "zYjVYHG30iBE+j2XDhUE8jB1BgNVHSMEbjBsgBT5m6VvzYjVYHG30iBE+j2XDhUE"
    "8qFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNV"
    "BAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJALW2IrlaBKUhMAwGA1UdEwQF"
    "MAMBAf8wDQYJKoZIhvcNAQELBQADggEBAD7Jg68SArYWlcoHfZAB90Pmyrt5H6D8"
    "LRi+W2Ri1fBNxREELnezWJ2scjl4UMcsKYp4Pi950gVN+62IgrImcCNvtb5I1Cfy"
    "/MNNur9ffas6X334D0hYVIQTePyFk3umI+2mJQrtZZyMPIKSY/sYGQHhGGX6wGK+"
    "GO/og0PQk/Vu6D+GU2XRnDV0YZg1lsAsHd21XryK6fDmNkEMwbIWrts4xc7scRrG"
    "HWy+iMf6/7p/Ak/SIicM4XSwmlQ8pPxAZPr+E2LoVd9pMpWUwpW2UbtO5wsGTrY5"
    "sO45tFNN/y+jtUheB1C2ijObG/tXELaiyCdM+S/waeuv0MXtI4xnn1A=";

  std::vector<uint8_t> out(strlen(kInput));
  size_t len;
  TimeResults results;
  if (!TimeFunction(&results, [&]() -> bool {
        return EVP_DecodeBase64(out.data(), &len, out.size(),
                                reinterpret_cast<const uint8_t *>(kInput),
                                strlen(kInput));
      })) {
    fprintf(stderr, "base64 decode failed.\n");
    return false;
  }
  results.PrintWithBytes("base64 decode", strlen(kInput));
  return true;
}

static bool SpeedSipHash(const std::string &selected) {
  if (!selected.empty() && selected.find("siphash") == std::string::npos) {
    return true;
  }

  uint64_t key[2] = {0};
  for (size_t len : g_chunk_lengths) {
    std::vector<uint8_t> input(len);
    TimeResults results;
    if (!TimeFunction(&results, [&]() -> bool {
          SIPHASH_24(key, input.data(), input.size());
          return true;
        })) {
      fprintf(stderr, "SIPHASH_24 failed.\n");
      ERR_print_errors_fp(stderr);
      return false;
    }
    results.PrintWithBytes("SipHash-2-4", len);
  }

  return true;
}

#if defined(INTERNAL_TOOL)
static TRUST_TOKEN_PRETOKEN *trust_token_pretoken_dup(
    const TRUST_TOKEN_PRETOKEN *in) {
  return static_cast<TRUST_TOKEN_PRETOKEN *>(
      OPENSSL_memdup(in, sizeof(TRUST_TOKEN_PRETOKEN)));
}

static bool SpeedTrustToken(std::string name, const TRUST_TOKEN_METHOD *method,
                            size_t batchsize, const std::string &selected) {
  if (!selected.empty() && selected.find("trusttoken") == std::string::npos) {
    return true;
  }

  TimeResults results;
  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
        uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
        size_t priv_key_len, pub_key_len;
        return TRUST_TOKEN_generate_key(
            method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
            pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0);
      })) {
    fprintf(stderr, "TRUST_TOKEN_generate_key failed.\n");
    return false;
  }
  results.Print(name + " generate_key");

  BM_NAMESPACE::UniquePtr<TRUST_TOKEN_CLIENT> client(
      TRUST_TOKEN_CLIENT_new(method, batchsize));
  BM_NAMESPACE::UniquePtr<TRUST_TOKEN_ISSUER> issuer(
      TRUST_TOKEN_ISSUER_new(method, batchsize));
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len, key_index;
  if (!client || !issuer ||
      !TRUST_TOKEN_generate_key(
          method, priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
          pub_key, &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0) ||
      !TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                  pub_key_len) ||
      !TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len)) {
    fprintf(stderr, "failed to generate trust token key.\n");
    return false;
  }

  uint8_t public_key[32], private_key[64];
  ED25519_keypair(public_key, private_key);
  BM_NAMESPACE::UniquePtr<EVP_PKEY> priv(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key, 32));
  BM_NAMESPACE::UniquePtr<EVP_PKEY> pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key, 32));
  if (!priv || !pub) {
    fprintf(stderr, "failed to generate trust token SRR key.\n");
    return false;
  }

  TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
  TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
  uint8_t metadata_key[32];
  RAND_bytes(metadata_key, sizeof(metadata_key));
  if (!TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                           sizeof(metadata_key))) {
    fprintf(stderr, "failed to generate trust token metadata key.\n");
    return false;
  }

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t *issue_msg = NULL;
        size_t msg_len;
        int ok = TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                   &msg_len, batchsize);
        OPENSSL_free(issue_msg);
        // Clear pretokens.
        sk_TRUST_TOKEN_PRETOKEN_pop_free(client->pretokens,
                                         TRUST_TOKEN_PRETOKEN_free);
        client->pretokens = sk_TRUST_TOKEN_PRETOKEN_new_null();
        return ok;
      })) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_begin_issuance failed.\n");
    return false;
  }
  results.Print(name + " begin_issuance");

  uint8_t *issue_msg = NULL;
  size_t msg_len;
  if (!TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg, &msg_len,
                                         batchsize)) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_begin_issuance failed.\n");
    return false;
  }
  BM_NAMESPACE::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  BM_NAMESPACE::UniquePtr<STACK_OF(TRUST_TOKEN_PRETOKEN)> pretokens(
      sk_TRUST_TOKEN_PRETOKEN_deep_copy(client->pretokens,
                                        trust_token_pretoken_dup,
                                        TRUST_TOKEN_PRETOKEN_free));

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t *issue_resp = NULL;
        size_t resp_len, tokens_issued;
        int ok = TRUST_TOKEN_ISSUER_issue(issuer.get(), &issue_resp, &resp_len,
                                          &tokens_issued, issue_msg, msg_len,
                                          /*public_metadata=*/0,
                                          /*private_metadata=*/0,
                                          /*max_issuance=*/batchsize);
        OPENSSL_free(issue_resp);
        return ok;
      })) {
    fprintf(stderr, "TRUST_TOKEN_ISSUER_issue failed.\n");
    return false;
  }
  results.Print(name + " issue");

  uint8_t *issue_resp = NULL;
  size_t resp_len, tokens_issued;
  if (!TRUST_TOKEN_ISSUER_issue(issuer.get(), &issue_resp, &resp_len,
                                &tokens_issued, issue_msg, msg_len,
                                /*public_metadata=*/0, /*private_metadata=*/0,
                                /*max_issuance=*/batchsize)) {
    fprintf(stderr, "TRUST_TOKEN_ISSUER_issue failed.\n");
    return false;
  }
  BM_NAMESPACE::UniquePtr<uint8_t> free_issue_resp(issue_resp);

  if (!TimeFunction(&results, [&]() -> bool {
        size_t key_index2;
        BM_NAMESPACE::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
            TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index2,
                                               issue_resp, resp_len));

        // Reset pretokens.
        client->pretokens = sk_TRUST_TOKEN_PRETOKEN_deep_copy(
            pretokens.get(), trust_token_pretoken_dup,
            TRUST_TOKEN_PRETOKEN_free);
        return !!tokens;
      })) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_finish_issuance failed.\n");
    return false;
  }
  results.Print(name + " finish_issuance");

  BM_NAMESPACE::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  if (!tokens || sk_TRUST_TOKEN_num(tokens.get()) < 1) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_finish_issuance failed.\n");
    return false;
  }

  const TRUST_TOKEN *token = sk_TRUST_TOKEN_value(tokens.get(), 0);

  const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
  uint64_t kRedemptionTime = 13374242;

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t *redeem_msg = NULL;
        size_t redeem_msg_len;
        int ok = TRUST_TOKEN_CLIENT_begin_redemption(
            client.get(), &redeem_msg, &redeem_msg_len, token, kClientData,
            sizeof(kClientData) - 1, kRedemptionTime);
        OPENSSL_free(redeem_msg);
        return ok;
      })) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_begin_redemption failed.\n");
    return false;
  }
  results.Print(name + " begin_redemption");

  uint8_t *redeem_msg = NULL;
  size_t redeem_msg_len;
  if (!TRUST_TOKEN_CLIENT_begin_redemption(
          client.get(), &redeem_msg, &redeem_msg_len, token, kClientData,
          sizeof(kClientData) - 1, kRedemptionTime)) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_begin_redemption failed.\n");
    return false;
  }
  BM_NAMESPACE::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t *redeem_resp = NULL;
        size_t redeem_resp_len;
        TRUST_TOKEN *rtoken = NULL;
        uint8_t *client_data = NULL;
        size_t client_data_len;
        uint64_t redemption_time;
        int ok = TRUST_TOKEN_ISSUER_redeem(
            issuer.get(), &redeem_resp, &redeem_resp_len, &rtoken, &client_data,
            &client_data_len, &redemption_time, redeem_msg, redeem_msg_len,
            /*lifetime=*/600);
        OPENSSL_free(redeem_resp);
        OPENSSL_free(client_data);
        TRUST_TOKEN_free(rtoken);
        return ok;
      })) {
    fprintf(stderr, "TRUST_TOKEN_ISSUER_redeem failed.\n");
    return false;
  }
  results.Print(name + " redeem");

  uint8_t *redeem_resp = NULL;
  size_t redeem_resp_len;
  TRUST_TOKEN *rtoken = NULL;
  uint8_t *client_data = NULL;
  size_t client_data_len;
  uint64_t redemption_time;
  if (!TRUST_TOKEN_ISSUER_redeem(issuer.get(), &redeem_resp, &redeem_resp_len,
                                 &rtoken, &client_data, &client_data_len,
                                 &redemption_time, redeem_msg, redeem_msg_len,
                                 /*lifetime=*/600)) {
    fprintf(stderr, "TRUST_TOKEN_ISSUER_redeem failed.\n");
    return false;
  }
  BM_NAMESPACE::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
  BM_NAMESPACE::UniquePtr<uint8_t> free_client_data(client_data);
  BM_NAMESPACE::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

  if (!TimeFunction(&results, [&]() -> bool {
        uint8_t *srr = NULL, *sig = NULL;
        size_t srr_len, sig_len;
        int ok = TRUST_TOKEN_CLIENT_finish_redemption(
            client.get(), &srr, &srr_len, &sig, &sig_len, redeem_resp,
            redeem_resp_len);
        OPENSSL_free(srr);
        OPENSSL_free(sig);
        return ok;
      })) {
    fprintf(stderr, "TRUST_TOKEN_CLIENT_finish_redemption failed.\n");
    return false;
  }
  results.Print(name + " finish_redemption");

  return true;
}
#endif
#endif

#if defined(BORINGSSL_FIPS)
static bool SpeedSelfTest(const std::string &selected) {
  if (!selected.empty() && selected.find("self-test") == std::string::npos) {
    return true;
  }

  TimeResults results;
  if (!TimeFunction(&results, []() -> bool { return BORINGSSL_self_test(); })) {
    fprintf(stderr, "BORINGSSL_self_test faileid.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  results.Print("self-test");
  return true;
}
#endif

#if !defined(OPENSSL_BENCHMARK) && !defined(BORINGSSL_BENCHMARK)
static bool SpeedPKCS8(const std::string &selected) {
  if (!selected.empty() && selected.find("pkcs8") == std::string::npos) {
    return true;
  }

  uint8_t pubkey[ED25519_PUBLIC_KEY_LEN];
  uint8_t privkey[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair(pubkey, privkey);

  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, &privkey[0], ED25519_PRIVATE_KEY_SEED_LEN);

  if(!key) {
    return false;
  }

  CBB out;
  if (!CBB_init(&out, 1024)) {
    return false;
  }

  TimeResults results;
  if (!TimeFunction(&results, [&out, &key]() -> bool {
        if (!EVP_marshal_private_key(&out, key)) {
          return false;
        }
        return true;
      })) {
    EVP_PKEY_free(key);
    return false;
  }
  results.Print("Ed25519 PKCS#8 v1 encode");

  CBS in;

  CBS_init(&in, CBB_data(&out), CBB_len(&out));

  EVP_PKEY *parsed = NULL;

  if (!TimeFunction(&results, [&in, &parsed]() -> bool {
        parsed = EVP_parse_private_key(&in);
        if (!parsed) {
          return false;
        }
        return true;
      })) {
    EVP_PKEY_free(key);
    return false;
  }
  results.Print("Ed25519 PKCS#8 v1 decode");

  EVP_PKEY_free(parsed);

  CBB_cleanup(&out);

  if (!CBB_init(&out, 1024)) {
    return false;
  }

  if (!TimeFunction(&results, [&out, &key]() -> bool {
        if (!EVP_marshal_private_key_v2(&out, key)) {
          return false;
        }
        return true;
      })) {
    CBB_cleanup(&out);
    EVP_PKEY_free(key);
    return false;
  }
  results.Print("Ed25519 PKCS#8 v2 encode");

  CBS_init(&in, CBB_data(&out), CBB_len(&out));

  if (!TimeFunction(&results, [&in, &parsed]() -> bool {
        parsed = EVP_parse_private_key(&in);
        if (!parsed) {
          return false;
        }
        return true;
      })) {
    CBB_cleanup(&out);
    EVP_PKEY_free(key);
    return false;
  }
  results.Print("Ed25519 PKCS#8 v2 decode");

  EVP_PKEY_free(parsed);
  CBB_cleanup(&out);
  EVP_PKEY_free(key);

  return true;
}
#endif

static const argument_t kArguments[] = {
    {
        "-filter",
        kOptionalArgument,
        "A filter on the speed tests to run",
    },
    {
        "-timeout",
        kOptionalArgument,
        "The number of seconds to run each test for (default is 1)",
    },
    {
        "-chunks",
        kOptionalArgument,
        "A comma-separated list of input sizes to run tests at (default is "
        "16,256,1350,8192,16384)",
    },
    {
        "-json",
        kBooleanArgument,
        "If this flag is set, speed will print the output of each benchmark in "
        "JSON format as follows: \"{\"description\": "
        "\"descriptionOfOperation\", \"numCalls\": 1234, "
        "\"timeInMicroseconds\": 1234567, \"bytesPerCall\": 1234}\". When "
        "there is no information about the bytes per call for an  operation, "
        "the JSON field for bytesPerCall will be omitted.",
    },
    {
        "",
        kOptionalArgument,
        "",
    },
};

bool Speed(const std::vector<std::string> &args) {
  std::map<std::string, std::string> args_map;
  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  std::string selected;
  if (args_map.count("-filter") != 0) {
    selected = args_map["-filter"];
  }

  if (args_map.count("-json") != 0) {
    g_print_json = true;
  }

  if (args_map.count("-timeout") != 0) {
    g_timeout_seconds = atoi(args_map["-timeout"].c_str());
  }

  if (args_map.count("-chunks") != 0) {
    g_chunk_lengths.clear();
    const char *start = args_map["-chunks"].data();
    const char *end = start + args_map["-chunks"].size();
    while (start != end) {
      errno = 0;
      char *ptr;
      unsigned long long val = strtoull(start, &ptr, 10);
      if (ptr == start /* no numeric characters found */ ||
          errno == ERANGE /* overflow */ ||
          static_cast<size_t>(val) != val) {
        fprintf(stderr, "Error parsing -chunks argument\n");
        return false;
      }
      g_chunk_lengths.push_back(static_cast<size_t>(val));
      start = ptr;
      if (start != end) {
        if (*start != ',') {
          fprintf(stderr, "Error parsing -chunks argument\n");
          return false;
        }
        start++;
      }
    }
  }

  // kTLSADLen is the number of bytes of additional data that TLS passes to
  // AEADs.
  static const size_t kTLSADLen = 13;
#if !defined(OPENSSL_BENCHMARK)

  // kLegacyADLen is the number of bytes that TLS passes to the "legacy" AEADs.
  // These are AEADs that weren't originally defined as AEADs, but which we use
  // via the AEAD interface. In order for that to work, they have some TLS
  // knowledge in them and construct a couple of the AD bytes internally.
  static const size_t kLegacyADLen = kTLSADLen - 2;
#endif

#if defined(CMAKE_BUILD_TYPE_DEBUG)
  printf("Benchmarking in debug mode.\n");
#endif

  if (g_print_json) {
    puts("[");
  }
  if(!SpeedAESBlock("AES-128", 128, selected) ||
     !SpeedAESBlock("AES-192", 192, selected) ||
     !SpeedAESBlock("AES-256", 256, selected) ||
     !SpeedAESGCM(EVP_aes_128_gcm(), "EVP-AES-128-GCM", kTLSADLen, selected) ||
     !SpeedAESGCM(EVP_aes_192_gcm(), "EVP-AES-192-GCM", kTLSADLen, selected) ||
     !SpeedAESGCM(EVP_aes_256_gcm(), "EVP-AES-256-GCM", kTLSADLen, selected) ||
     !SpeedAES256XTS("AES-256-XTS", selected) ||
     // OpenSSL 3.0 doesn't allow MD4 calls
#if !defined(OPENSSL_3_0_BENCHMARK)
     !SpeedHash(EVP_md4(), "MD4", selected) ||
#endif
     !SpeedHash(EVP_md5(), "MD5", selected) ||
     !SpeedHash(EVP_sha1(), "SHA-1", selected) ||
     !SpeedHash(EVP_sha224(), "sha-224", selected) ||
     !SpeedHash(EVP_sha256(), "SHA-256", selected) ||
     !SpeedHash(EVP_sha384(), "SHA-384", selected) ||
     !SpeedHash(EVP_sha512(), "SHA-512", selected) ||
     // OpenSSL 1.0 doesn't support SHA3.
#if !defined(OPENSSL_1_0_BENCHMARK)
     !SpeedHash(EVP_sha3_224(), "SHA3-224", selected) ||
     !SpeedHash(EVP_sha3_256(), "SHA3-256", selected) ||
     !SpeedHash(EVP_sha3_384(), "SHA3-384", selected) ||
     !SpeedHash(EVP_sha3_512(), "SHA3-512", selected) ||
#endif
     !SpeedHmac(EVP_md5(), "HMAC-MD5", selected) ||
     !SpeedHmac(EVP_sha1(), "HMAC-SHA1", selected) ||
     !SpeedHmac(EVP_sha256(), "HMAC-SHA256", selected) ||
     !SpeedHmac(EVP_sha384(), "HMAC-SHA384", selected) ||
     !SpeedHmac(EVP_sha512(), "HMAC-SHA512", selected) ||
     !SpeedHmacOneShot(EVP_md5(), "HMAC-MD5-OneShot", selected) ||
     !SpeedHmacOneShot(EVP_sha1(), "HMAC-SHA1-OneShot", selected) ||
     !SpeedHmacOneShot(EVP_sha256(), "HMAC-SHA256-OneShot", selected) ||
     !SpeedHmacOneShot(EVP_sha384(), "HMAC-SHA384-OneShot", selected) ||
     !SpeedHmacOneShot(EVP_sha512(), "HMAC-SHA512-OneShot", selected) ||
     !SpeedRandom(selected) ||
     !SpeedECDH(selected) ||
     !SpeedECDSA(selected) ||
     !SpeedECKeyGen(selected) ||
#if !defined(OPENSSL_1_0_BENCHMARK)
     !SpeedECMUL(selected) ||
     // OpenSSL 1.0 doesn't support Scrypt
     !SpeedScrypt(selected) ||
#endif
     !SpeedRSA(selected) ||
     !SpeedRSAKeyGen(selected)
#if !defined(OPENSSL_BENCHMARK)
     ||
     !SpeedKEM(selected) ||
     !SpeedAEAD(EVP_aead_aes_128_gcm(), "AEAD-AES-128-GCM", kTLSADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_256_gcm(), "AEAD-AES-256-GCM", kTLSADLen, selected) ||
     !SpeedAEAD(EVP_aead_chacha20_poly1305(), "AEAD-ChaCha20-Poly1305", kTLSADLen, selected) ||
     !SpeedAEAD(EVP_aead_des_ede3_cbc_sha1_tls(), "AEAD-DES-EDE3-CBC-SHA1", kLegacyADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_128_cbc_sha1_tls(), "AEAD-AES-128-CBC-SHA1", kLegacyADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_256_cbc_sha1_tls(), "AEAD-AES-256-CBC-SHA1", kLegacyADLen, selected) ||
     !SpeedAEADOpen(EVP_aead_aes_128_cbc_sha1_tls(), "AEAD-AES-128-CBC-SHA1", kLegacyADLen, selected) ||
     !SpeedAEADOpen(EVP_aead_aes_256_cbc_sha1_tls(), "AEAD-AES-256-CBC-SHA1", kLegacyADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_128_gcm_siv(), "AEAD-AES-128-GCM-SIV", kTLSADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_256_gcm_siv(), "AEAD-AES-256-GCM-SIV", kTLSADLen, selected) ||
     !SpeedAEADOpen(EVP_aead_aes_128_gcm_siv(), "AEAD-AES-128-GCM-SIV", kTLSADLen, selected) ||
     !SpeedAEADOpen(EVP_aead_aes_256_gcm_siv(), "AEAD-AES-256-GCM-SIV", kTLSADLen, selected) ||
     !SpeedAEAD(EVP_aead_aes_128_ccm_bluetooth(), "AEAD-AES-128-CCM-Bluetooth", kTLSADLen, selected) ||
     !Speed25519(selected) ||
     !SpeedSPAKE2(selected) ||
     !SpeedRSAKeyGen(selected) ||
     !SpeedHRSS(selected) ||
     !SpeedHash(EVP_blake2b256(), "BLAKE2b-256", selected) ||
#if defined(INTERNAL_TOOL)
     !SpeedHashToCurve(selected) ||
     !SpeedTrustToken("TrustToken-Exp1-Batch1", TRUST_TOKEN_experiment_v1(), 1, selected) ||
     !SpeedTrustToken("TrustToken-Exp1-Batch10", TRUST_TOKEN_experiment_v1(), 10, selected) ||
     !SpeedTrustToken("TrustToken-Exp2VOfPRF-Batch1", TRUST_TOKEN_experiment_v2_voprf(), 1, selected) ||
     !SpeedTrustToken("TrustToken-Exp2VOPRF-Batch10", TRUST_TOKEN_experiment_v2_voprf(), 10, selected) ||
     !SpeedTrustToken("TrustToken-Exp2PMB-Batch1", TRUST_TOKEN_experiment_v2_pmb(), 1, selected) ||
     !SpeedTrustToken("TrustToken-Exp2PMB-Batch10", TRUST_TOKEN_experiment_v2_pmb(), 10, selected) ||
#endif
#if !defined(OPENSSL_BENCHMARK) && !defined(BORINGSSL_BENCHMARK)
     !SpeedPKCS8(selected) ||
#endif
     !SpeedBase64(selected) ||
     !SpeedSipHash(selected)
#endif
     ) {
    return false;
  }
#if defined(BORINGSSL_FIPS)
  if (!SpeedSelfTest(selected)) {
    return false;
  }
#endif
  if (g_print_json) {
    puts("\n]");
  }

  return true;
}
