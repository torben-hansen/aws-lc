// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/ctrdrbg.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../../delocate.h"
#include "../../../internal.h"
#include "../../../ube/internal.h"

// Implements a tree-DRBG with the following characteristics:
//  - A per-thread "seed"-DRBG that serves seed requests a thread-local
//    "frontend"-DRBG.
//  - A global "seed"-DRBG that serves seed requests from a thread-local seed
//    DRBG.
//  - A root seed source that serves seed requests from the global seed DRBG.
//  
//  per-thread
// +-----------+
// | CTR-DRBG  | -|
// +-----------+   -|
// +-----------+     --|     per-process         per-process
// | CTR-DRBG  | ---|   --> +-----------+     +---------------+
// +-----------+     -----> | CTR-DRBG  | --> |Jitter Entropy |
//     ...              --> +-----------+     +---------------+
// +-----------+  -----|
// | CTR-DRBG  |-|
// +-----------+


struct global_seed_drbg_t {
  CTR_DRBG_STATE drbg;

  // generate_calls_since_seed is the number of generate calls made on |drbg|
  // since it was last (re)seeded. Must be bounded by |kReseedInterval|.
  uint64_t generate_calls_since_seed;

  // reseed_calls_since_initialization is the number of reseed calls made of
  // |drbg| since its initialization.
  uint64_t reseed_calls_since_initialization;

  // generation_number caches the UBE generation number.
  uint64_t generation_number;

  char ube_protection;

#if 0
  // Jitter entropy state...
  struct rand_data *jitter_ec;
#endif

  CRYPTO_MUTEX lock;
};
static struct global_seed_drbg_t global_seed_drbg = {0};
DEFINE_STATIC_ONCE(global_seed_drbg_once)

struct per_thread_seed_drbg_t {
  CTR_DRBG_STATE drbg;

  // generate_calls_since_seed is the number of generate calls made on |drbg|
  // since it was last (re)seeded. Must be bounded by |kReseedInterval|.
  uint64_t generate_calls_since_seed;

  // reseed_calls_since_initialization is the number of reseed calls made of
  // |drbg| since its initialization.
  uint64_t reseed_calls_since_initialization;

  // generation_number caches the UBE generation number.
  uint64_t generation_number;
};

static void chain_jitter_global_drbg_get_entropy(void) {

}

static void chain_jitter_initialize_once(void) {
  global_seed_drbg.generate_calls_since_seed = 0;
  global_seed_drbg.reseed_calls_since_initialization = 0;
  uint64_t current_generation_number = 0;
  if (CRYPTO_get_ube_generation_number(&current_generation_number) != 1) {
    global_seed_drbg.ube_protection = 0;
    global_seed_drbg.generation_number = 0;
  } else {
    global_seed_drbg.ube_protection = 1;
    global_seed_drbg.generation_number = current_generation_number;  
  }

  // initialize jitter
  // get entropy from jitter entropy
  // initialise drbg
  // initialise lock
}

static void chain_jitter_thread_drbg_free(void) {}

static void chain_jitter_global_drbg_seed(void) {
  
}

static void chain_jitter_thread_drbg_get_entropy(
  struct per_thread_seed_drbg_t *state, uint8_t seed[CTR_DRBG_ENTROPY_LEN]) {

  uint64_t current_generation_number = 0;
  if (CRYPTO_get_ube_generation_number(&current_generation_number) != 1 &&
      current_generation_number != global_seed_drbg) {

  }

}

int chain_jitter_initialize(void) {

  // Initialize the global state.
  CRYPTO_once(global_seed_drbg_once_bss_get(), chain_jitter_initialize_once);

  // Initialize the per-thread seed drbg.
  struct per_thread_seed_drbg_t *state =
    OPENSSL_zalloc(sizeof(struct per_thread_seed_drbg_t));
  if (state == NULL ||
      CRYPTO_set_thread_local(AWS_LC_THREAD_LOCAL_CHAIN_JITTER_DRBG, state,
                                 chain_jitter_thread_drbg_free) != 1) {
    abort();
  }

  uint8_t seed[CTR_DRBG_ENTROPY_LEN];
  uint8_t personalization_string[CTR_DRBG_ENTROPY_LEN];
  size_t personalization_string_len = 0;

  chain_jitter_thread_drbg_get_entropy(state, seed, personalization_string,
    &personalization_string_len);
  if (!CTR_DRBG_init(&(state->drbg), seed, personalization_string,
        personalization_string_len)) {
    abort();
  }

  state->

  return 1;
}

void chain_jitter_cleanup(void) {}

int chain_jitter_get_seed(uint8_t seed[CTR_DRBG_ENTROPY_LEN]) {
  return 1;
}

int chain_jitter_randomize(void) {
  return 1;
}

