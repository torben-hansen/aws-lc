// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>

#include "internal.h"

static char ube_methods_unavailable = 0;

struct ube_thread_local_state {
  uint64_t *generation_number;
  uint64_t cached_fork_generation_number;
  uint64_t cached_snapsafe_generation_number;
};

static void ube_state_initialize(struct ube_thread_local_state *state) {
  state.generation_number = 0;
  state.cached_fork_generation_number = get_fork_generation_number();
  int ret_snapsafe_generation_number =
    get_snapsafe_generation_number(&state.cached_snapsafe_generation_number);
}

int get_ube_generation_number(uint64_t *current_generation_number) {

  // If something failed at an earlier point. Just fail immediately. 
  if (ube_methods_unavailable == 1) {
    *current_generation_number = 0;
    return 0;
  }

  struct ube_thread_local_state *ube_state =
    CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_UBE);

  if (ube_state == NULL) {
    ube_state = OPENSSL_zalloc(sizeof(struct ube_thread_local_state ));
    if (ube_state == NULL ||
        CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_UBE, ube_state,
                                   ube_thread_local_state_free) != 1) {
      abort();
    }

    // This only happens on first entry and at that point the state has just
    // been initialized. So, we can return immediately.
    ube_init_state(ube_state);
    *current_generation_number = state.generation_number;
    return 1;
  }

  uint64_t current_fork_generation_number = get_fork_generation_number();
  
  if (current_fork_generation_number == 0) {
    return 0;
  }

  if ()





  uint64_t current_snapsafe_generation_number = 0;
  int ret_snapsafe_generation_number =
    get_snapsafe_generation_number(&current_snapsafe_generation_number);

  if ()


  return 1;
}
