
#include <openssl/rand.h>
#include <openssl/mem.h>
#include <openssl/ctrdrbg.h>
#include <openssl/type_check.h>

#include "new_rand_internal.h"
#include "internal.h"
#include "../../internal.h"

#include "new_rand_prefix.h"

/////////////////////
//// ../../ube/ube.c
/////////////////////

static int rand_ensure_valid_state(void) {
  return 1;
}

/////////////////////
//// entropy/entropy_source.c
/////////////////////

// I could make these array types!
struct entropy_source {
  int is_initialized;
  int (*initialize)(void);
  int (*cleanup)(void);
  int (*seed)(uint8_t seed[CTR_DRBG_ENTROPY_LEN]);
  int (*personalization_string)(uint8_t personalization_string[CTR_DRBG_ENTROPY_LEN]);
  int (*prediction_resistance)(uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN]);
  int (*randomize)(void);
};

static int fake_void(void) {
  return 1;
}

static int fake_rand(uint8_t a[CTR_DRBG_ENTROPY_LEN]) {
  return 1;
}

static int fake_rand_array_32(uint8_t a[RAND_PRED_RESISTANCE_LEN]) {
  return 1;
}

static void get_entropy_source(struct entropy_source *entropy_source) {
  entropy_source->is_initialized = 1;
  entropy_source->initialize = fake_void;
  entropy_source->cleanup = fake_void;
  entropy_source->seed = fake_rand;
  entropy_source->personalization_string = fake_rand;
  entropy_source->prediction_resistance = fake_rand_array_32;
  entropy_source->randomize = fake_void;
}

/////////////////////
//// rand.c
/////////////////////

// rand_thread_state contains the per-thread state for the RNG.
struct rand_thread_local_state {
  // Thread-local CTR-DRBG state. UBE volatile memory.
  CTR_DRBG_STATE drbg;

  // generate_calls_since_seed is the number of generate calls made on |drbg|
  // since it was last (re)seeded. Must be bounded by |kReseedInterval|.
  uint64_t generate_calls_since_seed;

  // Entropy source. UBE volatile memory.
  struct entropy_source entropy_source;
};

// rand_thread_local_state frees a |rand_thread_local_state|. This is called when a
// thread exits.
static void rand_thread_local_state_free(void *state_in) {

  struct rand_thread_local_state *state = state_in;
  if (state_in == NULL) {
    return;
  }

  OPENSSL_free(state);
}

static int rand_ensure_ctr_drbg_uniquness(struct rand_thread_local_state *state,
  size_t out_len) {
  // TODO
  // For UBE.
  return 1;
}


static void rand_maybe_get_ctr_drbg_pred_resistance(
  struct rand_thread_local_state *state,
  uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN],
  size_t *pred_resistance_len) {

  *pred_resistance_len = 0;

  if (state->entropy_source.prediction_resistance != NULL) {
    state->entropy_source.prediction_resistance(pred_resistance);
    *pred_resistance_len = RAND_PRED_RESISTANCE_LEN;
  }
}

static void rand_get_ctr_drbg_seed_entropy(struct entropy_source *entropy_source,
  uint8_t seed[CTR_DRBG_ENTROPY_LEN],
  uint8_t personalization_string[CTR_DRBG_ENTROPY_LEN],
  size_t *personalization_string_len) {

  *personalization_string_len = 0;

  if (entropy_source == NULL || entropy_source->is_initialized == 0) {
    abort();
  }

  if (entropy_source->seed(seed) != 1) {
    abort();
  }

  if (entropy_source->personalization_string != NULL) {
    if(entropy_source->personalization_string(personalization_string) != 1) {
      abort();
    }
    *personalization_string_len = CTR_DRBG_ENTROPY_LEN;
  }
}

static void rand_ctr_drbg_reseed(struct rand_thread_local_state *state) {

  uint8_t seed[CTR_DRBG_ENTROPY_LEN];
  uint8_t personalization_string[CTR_DRBG_ENTROPY_LEN];
  size_t personalization_string_len = 0;
  rand_get_ctr_drbg_seed_entropy(&state->entropy_source, seed,
    personalization_string, &personalization_string_len);

  assert(*personalization_string_len == 0 ||
         *personalization_string_len == CTR_DRBG_ENTROPY_LEN);

  if (CTR_DRBG_reseed(&state->drbg, seed, personalization_string,
        personalization_string_len) != 1) {
    abort();
  }

  state->generate_calls_since_seed = 0;

  OPENSSL_cleanse(seed, CTR_DRBG_ENTROPY_LEN);
  OPENSSL_cleanse(personalization_string, CTR_DRBG_ENTROPY_LEN);
}

static void rand_state_initialize(struct rand_thread_local_state *state) {

  get_entropy_source(&state->entropy_source);

  uint8_t seed[CTR_DRBG_ENTROPY_LEN];
  uint8_t personalization_string[CTR_DRBG_ENTROPY_LEN];
  size_t personalization_string_len = 0;
  rand_get_ctr_drbg_seed_entropy(&state->entropy_source, seed,
    personalization_string, &personalization_string_len);

  assert(*personalization_string_len == 0 ||
         *personalization_string_len == CTR_DRBG_ENTROPY_LEN);

  if (!CTR_DRBG_init(&state->drbg, seed, personalization_string,
        personalization_string_len)) {
    abort();
  }

  state->generate_calls_since_seed = 0;

  OPENSSL_cleanse(seed, CTR_DRBG_ENTROPY_LEN);
  OPENSSL_cleanse(personalization_string, CTR_DRBG_ENTROPY_LEN);
}

static void RAND_bytes_core(
  struct rand_thread_local_state *state,
  uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN],
  int use_user_pred_resistance) {

  // Ensure CTR-DRBG state is unique.
  if (rand_ensure_ctr_drbg_uniquness(state, out_len) != 1) {
    rand_ctr_drbg_reseed(state);
  }

  // If a prediction resistance source is available, get it.
  size_t first_pred_resistance_len = 0;
  uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN] = {0};
  rand_maybe_get_ctr_drbg_pred_resistance(state, pred_resistance,
    &first_pred_resistance_len);

  // If caller input user-controlled prediction resistance, use it.
  if (use_user_pred_resistance == RAND_USE_USER_PRED_RESISTANCE) {
    for (size_t i = 0; i < RAND_PRED_RESISTANCE_LEN; i++) {
      pred_resistance[i] ^= user_pred_resistance[i];
    }
    first_pred_resistance_len = RAND_PRED_RESISTANCE_LEN;
  }

  assert(*first_pred_resistance_len == 0 ||
         *first_pred_resistance_len == RAND_PRED_RESISTANCE_LEN);

  // Iterate CTR-DRBG generate until we generated |out_len| bytes of randomness.
  while (out_len > 0) {
    size_t todo = out_len;
    if (todo > CTR_DRBG_MAX_GENERATE_LENGTH) {
      todo = CTR_DRBG_MAX_GENERATE_LENGTH;
    }

    // Each reseed interval can generate up to
    // |CTR_DRBG_MAX_GENERATE_LENGTH*2^{kCtrDrbgReseedInterval}| bytes.
    // Determining the time(s) to reseed prior to entering the CTR-DRBG generate
    // loop is a doable strategy. But tracking reseed times add unnecessary
    // complexity. Instead our strategy is optimizing for simplicity.
    // |out_len < CTR_DRBG_MAX_GENERATE_LENGTH| will be the majority case
    // (by far) and requires a single check in either strategy.
    // Note if we reseeded through |rand_is_reseed_required()| no reseed will
    // happen here.
    if( state->generate_calls_since_seed + 1 >= kCtrDrbgReseedInterval) {
      rand_ctr_drbg_reseed(state);
    }

    if (!CTR_DRBG_generate(&state->drbg, out, todo, pred_resistance,
          first_pred_resistance_len)) {
      abort();
    }

    out += todo;
    out_len -= todo;
    state->generate_calls_since_seed++;
    first_pred_resistance_len = 0;
  }

  OPENSSL_cleanse(pred_resistance, RAND_PRED_RESISTANCE_LEN);

  // reword this
  // Unexpected change to snapsafe generation.
  // A change in the snapsafe generation between the beginning of this
  // funtion and here indicates that a snapshot was taken (and is now being
  // used) while this function was executing. This is an invalid snapshot
  // and is not safe for use. Please ensure all processing is completed
  // prior to collecting a snapshot.
  if (rand_ensure_valid_state() != 1) {
    abort();
  }
}

static void RAND_bytes_private(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN],
  int use_user_pred_resistance) {

  if (out_len == 0) {
    return;
  }

  struct rand_thread_local_state *state =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_PRIVATE_RAND);

  if (state == NULL) {
    state = OPENSSL_zalloc(sizeof(struct rand_thread_local_state));
    if (state == NULL ||
        CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_PRIVATE_RAND, state,
                                   rand_thread_local_state_free) != 1) {
      abort();
    }

    rand_state_initialize(state);
  }

  RAND_bytes_core(state, out, out_len, user_pred_resistance,
    use_user_pred_resistance);
}

// TOOD
// Retire and replace call sites with RAND_bytes_with_user_prediction_resistance
int RAND_bytes_with_additional_data(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]) {
  
  RAND_bytes_private(out, out_len, user_pred_resistance,
    RAND_USE_USER_PRED_RESISTANCE);
  return 1;
}

int RAND_bytes_with_user_prediction_resistance(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]) {
  
  RAND_bytes_private(out, out_len, user_pred_resistance,
    RAND_USE_USER_PRED_RESISTANCE);
  return 1;
}

int RAND_bytes(uint8_t *out, size_t out_len) {

  static const uint8_t kZeroPredResistance[RAND_PRED_RESISTANCE_LEN] = {0};
  RAND_bytes_private(out, out_len, kZeroPredResistance,
    RAND_NO_USER_PRED_RESISTANCE);
  return 1;
}

int RAND_priv_bytes(uint8_t *out, size_t out_len) {
  return RAND_bytes(out, out_len);
}

int RAND_pseudo_bytes(uint8_t *out, size_t out_len) {
  return RAND_bytes(out, out_len);
}
