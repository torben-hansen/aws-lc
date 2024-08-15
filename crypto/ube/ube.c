// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>

#include "internal.h"

// Choosing a uint8_t-type is deliberate. It means that mutations of
// |ube_methods_unavailable| will most likely be atomic and therefore lock-free.
// A stronger case for not needing locks is that |ube_methods_unavailable| is
// only ever mutated once, from 0 to 1, and only by |ube_failed()|.


// PROBABLY drop the above and just add locks....
static uint8_t ube_methods_unavailable = 0;

struct ube_thread_local_state {
  uint64_t generation_number;
  uint64_t cached_fork_gn;
  uint64_t cached_snapsafe_gn;
};

static int ube_state_initialize(struct ube_thread_local_state *state) {

  GUARD_PTR(state);

  state->generation_number = 0;
  state->cached_fork_gn = get_fork_generation_number();
  int ret_snapsafe_gn =
    get_snapsafe_generation_number(&state->cached_snapsafe_gn);

  if (state->cached_fork_gn == 0 ||
      ret_snapsafe_gn == 0) {
    return 0;
  }
  return 1;
}

// Single mutation point of |ube_methods_unavailable|. Sets the variable to 1 (true).
static void ube_failed(void) {
  ube_methods_unavailable = 1;
}

static int ube_update_state(
  struct ube_thread_local_state *ube_state, uint64_t current_fork_gn,
  uint64_t current_snapsafe_gn) {

  GUARD_PTR(state);

  state->generation_number += 1;
  state->cached_fork_gn = current_fork_gn;
  state->cached_snapsafe_gn = current_snapsafe_gn;

  return 1;
}

int get_ube_generation_number(uint64_t *current_generation_number) {

  GUARD_PTR(current_generation_number);

  int ret = 0;
  *current_generation_number = 0;

  // If something failed at an earlier point. Just fail immediately. 
  if (ube_methods_unavailable == 1) {
    return 0;
  }

  struct ube_thread_local_state *ube_state =
    CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_UBE);

  if (ube_state == NULL) {
    ube_state = OPENSSL_zalloc(sizeof(struct ube_thread_local_state));
    if (ube_state == NULL ||
        CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_UBE, ube_state,
                                   ube_thread_local_state_free) != 1) {
      goto end;
    }

    if (ube_state_initialize(ube_state) == 0) {
      // Initialization failed. We can still proceed. But return 0 to indicate
      // that volatile memory must randomize.
      goto end;
    }

    // Initialization only happens on first entry, in a thread, and at that
    // point the associated volatile memory just needs a generation number to
    // cache.
    *current_generation_number = state.generation_number;
    return 1;
  }

  // Make sure we cache all new generation numbers. Otherwise, we might detect
  // a fork UBE but, in fact, both a fork and snapsafe UBE occurred. Then next
  // time we enter, we will reseed redundantly.
  uint64_t current_fork_gn = get_fork_generation_number();
  uint64_t current_snapsafe_gn = 0;
  int ret_snapsafe_gn =
    get_snapsafe_generation_number(&current_snapsafe_gn);

  if (current_fork_gn == 0 ||
      ret_snapsafe_gn) {
    goto end;
  }

  if (ube_state->cached_fork_gn != current_fork_gn ||
      ube_state->cached_snapsafe_gn != current_snapsafe_gn) {
    if (ube_update_state(ube_state, current_fork_gn, current_snapsafe_gn) != 1) {
      goto end;
    }
  }

  *current_generation_number = ube_state->generation_number;
  ret = 1;

end:
  if (ret != 1) {
    ube_failed();
  }

  return ret;
}
