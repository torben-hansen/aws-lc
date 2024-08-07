
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

static int ube_ensure_good_state(void) {
  return 1;
}

/////////////////////
//// entropy/entropy_source.c
/////////////////////

// I could make these array types!
struct entropy_source {
  int (*initialize)(void);
  int (*cleanup)(void);
  int (*seed)(uint8_t *seed, size_t seed_len);
  int (*personalization_string)(uint8_t *personalization_string,
    size_t personalization_string_len);
  int (*prediction_resistance)(
    uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN], size_t pred_res_len);
  int (*randomize)(void);
};

static int fake_void(void) {
  return 1;
}

static int fake_rand(uint8_t *a, size_t b) {
  return 1;
}

static int fake_rand_array_32(uint8_t a[RAND_PRED_RESISTANCE_LEN], size_t b) {
  return 1;
}

static struct entropy_source * get_entropy_source(void) {
  struct entropy_source *entropy_source = OPENSSL_malloc(sizeof(entropy_source));
  entropy_source->initialize = fake_void;
  entropy_source->cleanup = fake_void;
  entropy_source->seed = fake_rand;
  entropy_source->personalization_string = fake_rand;
  entropy_source->prediction_resistance = fake_rand_array_32;
  entropy_source->randomize = fake_void;

  return entropy_source;
}

/////////////////////
//// rand.c
/////////////////////


// rand_thread_state contains the per-thread state for the RNG.
struct rand_thread_local_state {
  // Thread-local CTR-DRBG state. UBE volatile memory.
  CTR_DRBG_STATE drbg;

  // generate_calls is the number of generate calls made on |drbg| since it was
  // last (re)seeded. Must be bounded by |kReseedInterval|.
  uint32_t generate_calls;

  // Entropy source. UBE volatile memory.
  // Make flat.
  struct entropy_source *entropy_source;
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

static struct rand_thread_local_state * rand_initialise_thread_local_state(void) {
  struct rand_thread_local_state *state = OPENSSL_zalloc(sizeof(struct rand_thread_local_state));
  if (state == NULL ||
      CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_PRIVATE_RAND, state,
                                 rand_thread_local_state_free) != 1) {
    abort();
  }

  state->entropy_source = get_entropy_source();
  return state;
}

static int rand_is_reseed_required(void) {
  // reseed interval
  // UBE
  return 0;
}

static void rand_do_reseed(void) {

}

static int rand_is_prediction_resistance_available(void) {
  return 0;
}

static void rand_get_prediction_resistance(
  uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN]) {
  
  OPENSSL_cleanse(pred_resistance, RAND_PRED_RESISTANCE_LEN);
}

static void RAND_bytes_core(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN],
  int use_user_pred_resistance) {

  if (out_len == 0) {
    return;
  }

  struct rand_thread_local_state *state =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_PRIVATE_RAND);

  // STEP - initialise
  if (state == NULL) {
    state = rand_initialise_thread_local_state();
  }

  // STEP - reseed conditions
  if (rand_is_reseed_required() == 1) {
    rand_do_reseed();
  }

  // STEP - prediction resistance
  // reference to where it states that prediction resistance should only be
  // included in first generation.
  // We could call CTR_DRBG_reseed here. But it induces extra copying work, that
  // is not necessary. Simply prepare prediction resistance and use as input in
  // CTR_DRBG_generate that doesn't have extra work.
  size_t first_pred_resistance_len = 0;
  uint8_t pred_resistance[RAND_PRED_RESISTANCE_LEN] = {0};
  if (rand_is_prediction_resistance_available() == 1) {
    rand_get_prediction_resistance(pred_resistance);
    first_pred_resistance_len = RAND_PRED_RESISTANCE_LEN;
  }

  // Add caller prediction resistance data, if any.
  if (use_user_pred_resistance == RAND_USE_USER_PRED_RESISTANCE) {
    for (size_t i = 0; i < RAND_PRED_RESISTANCE_LEN; i++) {
      prediction_resistance[i] ^= user_pred_resistance[i];
    }
    first_pred_resistance_len = RAND_PRED_RESISTANCE_LEN;
  }

  // STEP - generate randomness
  while (out_len > 0) {
    size_t todo = out_len;
    if (todo > CTR_DRBG_MAX_GENERATE_LENGTH) {
      todo = CTR_DRBG_MAX_GENERATE_LENGTH;
    }

    if (!CTR_DRBG_generate(&state->drbg, out, todo, pred_resistance,
          first_pred_resistance_len)) {
      abort();
    }

    out += todo;
    out_len -= todo;
    // Though we only check before entering the loop, this cannot add enough to
    // overflow a |size_t|.
    state->generate_calls++;
    first_pred_resistance_len = 0;
  }

  // STEP - finalise
  OPENSSL_cleanse(pred_resistance, RAND_PRED_RESISTANCE_LEN);

  // reword this
  // Unexpected change to snapsafe generation.
  // A change in the snapsafe generation between the beginning of this
  // funtion and here indicates that a snapshot was taken (and is now being
  // used) while this function was executing. This is an invalid snapshot
  // and is not safe for use. Please ensure all processing is completed
  // prior to collecting a snapshot.
  if (ube_ensure_good_state() != 1) {
    abort();
  }
}

// Retire and replace call sites with RAND_bytes_with_user_prediction_resistance
int RAND_bytes_with_additional_data(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]) {
  
  RAND_bytes_core(out, out_len, user_pred_resistance, RAND_PRED_RESISTANCE_LEN);
  return 1;
}

int RAND_bytes_with_user_prediction_resistance(uint8_t *out, size_t out_len,
  const uint8_t user_pred_resistance[RAND_PRED_RESISTANCE_LEN]) {
  
  RAND_bytes_core(out, out_len, user_pred_resistance, RAND_PRED_RESISTANCE_LEN);
  return 1;
}

int RAND_bytes(uint8_t *out, size_t out_len) {
  static const uint8_t kZeroPredResistance[RAND_PRED_RESISTANCE_LEN] = {0};
  RAND_bytes_core(out, out_len, kZeroPredResistance, RAND_PRED_RESISTANCE_LEN);
  return 1;
}

int RAND_priv_bytes(uint8_t *out, size_t out_len) {
  return RAND_bytes(out, out_len);
}

int RAND_pseudo_bytes(uint8_t *out, size_t out_len) {
  return RAND_bytes(buf, len);
}
