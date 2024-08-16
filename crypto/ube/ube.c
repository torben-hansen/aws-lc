// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>

#include "internal.h"
#include "../internal.h"

static CRYPTO_once_t ube_methods_unavailable_once = CRYPTO_ONCE_INIT; 
static uint8_t ube_methods_unavailable = 0;

struct ube_thread_local_state {
  uint64_t generation_number;
  uint64_t cached_fork_gn;
  uint64_t cached_snapsafe_gn;
};

static int get_snapsafe_generation_number_local(uint64_t *gn) {
  *gn = 1;
  return 1;
}

static uint64_t get_fork_generation_number_local(void) {
  return 1;
}

static void ube_thread_local_state_free(void *ube_state_in) {

  struct ube_thread_local_state *ube_state = ube_state_in;
  if (ube_state == NULL) {
    return;
  }

  OPENSSL_free(ube_state);
}

static int ube_state_initialize(struct ube_thread_local_state *ube_state) {

  GUARD_PTR(ube_state);

  ube_state->generation_number = 0;
  ube_state->cached_fork_gn = get_fork_generation_number_local();
  int ret_snapsafe_gn =
    get_snapsafe_generation_number_local(&ube_state->cached_snapsafe_gn);

  if (ube_state->cached_fork_gn == 0 ||
      ret_snapsafe_gn == 0) {
    return 0;
  }
  return 1;
}

// Single mutation point of |ube_methods_unavailable|. Sets the variable to
// 1 (true).
static void set_ube_methods_unavailable_once(void) {
  ube_methods_unavailable = 1;
}

// ube_failed handles the failure path.
static void ube_failed(void) {
  CRYPTO_once(&ube_methods_unavailable_once, set_ube_methods_unavailable_once);
}

static int ube_update_state(
  struct ube_thread_local_state *ube_state, uint64_t current_fork_gn,
  uint64_t current_snapsafe_gn) {

  GUARD_PTR(ube_state);

  ube_state->generation_number += 1;
  ube_state->cached_fork_gn = current_fork_gn;
  ube_state->cached_snapsafe_gn = current_snapsafe_gn;

  return 1;
}

int get_ube_generation_number(uint64_t *current_generation_number) {

  GUARD_PTR(current_generation_number);

  int ret = 0;
  *current_generation_number = 0;

  // If something failed at an earlier point short-circuit immediately. 
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
    *current_generation_number = ube_state->generation_number;
    return 1;
  }

  // Make sure we cache all new generation numbers. Otherwise, we might detect
  // a fork UBE but, in fact, both a fork and snapsafe UBE occurred. Then next
  // time we enter a redundant reseed will be emitted.
  uint64_t current_fork_gn = get_fork_generation_number_local();
  uint64_t current_snapsafe_gn = 0;
  int ret_snapsafe_gn =
    get_snapsafe_generation_number_local(&current_snapsafe_gn);

  if (current_fork_gn == 0 ||
      ret_snapsafe_gn == 0) {
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
