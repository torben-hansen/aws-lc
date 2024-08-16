// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/base.h>

#include "internal.h"
#include "../internal.h"

static int get_snapsafe_generation_number_mocked(uint64_t *gn) {
  *gn = 1;
  return 1;
}

static uint64_t get_fork_generation_number_mocked(void) {
  return 1;
}

// We define volatile
// memory as memory containing data that must be unique for each usage to
// maintain it's security properties. 

static CRYPTO_once_t ube_state_initialize_once = CRYPTO_ONCE_INIT;
static CRYPTO_once_t ube_methods_unavailable_once = CRYPTO_ONCE_INIT; 
static struct CRYPTO_STATIC_MUTEX ube_lock = CRYPTO_STATIC_MUTEX_INIT;
static uint8_t ube_methods_unavailable = 0;

struct ube_global_state {
  uint64_t generation_number;
  uint64_t cached_fork_gn;
  uint64_t cached_snapsafe_gn;
};

static struct ube_global_state ube_state = { 0 };

// Single mutation point of |ube_methods_unavailable|. Sets the variable to
// 1 (true).
static void set_ube_methods_unavailable_once(void) {
  ube_methods_unavailable = 1;
}

// ube_failed handles the failure path from 
static void ube_failed(void) {
  CRYPTO_once(&ube_methods_unavailable_once, set_ube_methods_unavailable_once);
}

static int ube_get_detection_generation_numbers(
  uint64_t *current_fork_gn,
  uint64_t *current_snapsafe_gn) {

  *current_fork_gn = get_fork_generation_number_mocked();
  int ret_snapsafe_gn =
    get_snapsafe_generation_number_mocked(current_snapsafe_gn);

  if (current_fork_gn == 0 ||
      ret_snapsafe_gn == 0) {
    return 0;
  }

  return 1;
}

static int ube_state_initialize(void) {

  ube_state.generation_number = 0;
  ube_state.cached_fork_gn = get_fork_generation_number_mocked();
  int ret_snapsafe_gn =
    get_snapsafe_generation_number_mocked(&ube_state->cached_snapsafe_gn);

  if (ube_state.cached_fork_gn == 0 ||
      ret_snapsafe_gn == 0) {
    return 0;
  }

  return 1;
}

static int ube_is_detected(
  uint64_t current_fork_gn,
  uint64_t current_snapsafe_gn) {

  if (ube_state.cached_fork_gn != current_fork_gn ||
      ube_state.cached_snapsafe_gn != current_snapsafe_gn) {
    return 1;
  }
  return 0;
}

static void ube_update_state(uint64_t current_fork_gn,
  uint64_t current_snapsafe_gn) {

  // Make sure we cache all new generation numbers. Otherwise, we might detect
  // a fork UBE but, in fact, both a fork and snapsafe UBE occurred. Then next
  // time we enter a redundant reseed will be emitted.
  ube_state.generation_number += 1;
  ube_state.cached_fork_gn = current_fork_gn;
  ube_state.cached_snapsafe_gn = current_snapsafe_gn;
}



int get_ube_generation_number(uint64_t *current_generation_number) {

  GUARD_PTR(current_generation_number);

  int ret = 0;
  *current_generation_number = 0;

  CRYPTO_once(ube_state_initialize_once, ube_state_initialize);

  // If something failed at an earlier point short-circuit immediately. 
  if (ube_methods_unavailable == 1) {
    return 0;
  }

  uint64_t current_fork_gn = 0;
  uint64_t current_snapsafe_gn = 0;

  // First read generation numbers for each detection method supported. We do
  // not mutate |ube_state|. So, a read lock is sufficient at this point. Each
  // individual detection method will have their own concurrency controls.

  CRYPTO_STATIC_MUTEX_lock_read(ube_lock);
  if (ube_get_detection_generation_numbers(
      &current_fork_gn, &current_snapsafe_gn)) {
    ube_failed();
    CRYPTO_STATIC_MUTEX_unlock_read(lock);
    return 0;
  }
  if (ube_is_detected(current_fork_gn, current_snapsafe_gn) == 0) {
    // No UBE detected, so just grab generation number from state.
    *current_generation_number = ube_state.generation_number;
    CRYPTO_STATIC_MUTEX_unlock_read(lock);
    return 1;
  }
  CRYPTO_STATIC_MUTEX_unlock_read(lock);

  // Reaching this point means that an UBE has been detected. We must now
  // synchronize an update to ube_state.generation_number. To avoid redundant
  // reseed, we must ensure the generation number is only incremented once for
  // the same UBE. Therefore, first take a write lock but before writing
  // mutation the state, check for an UBE again.

  CRYPTO_STATIC_MUTEX_lock_write(ube_lock);
#if 0 // I don't think this is needed?
  if (ube_get_detection_generation_numbers(
      &current_fork_gn, &current_snapsafe_gn)) {
    ube_failed();
    CRYPTO_STATIC_MUTEX_unlock_write(lock);
    return 0;
  }
#endif
  if (ube_is_detected(current_fork_gn, current_snapsafe_gn) == 0) {
    // No UBE detected, so just grab generation number from state.
    *current_generation_number = ube_state.generation_number;
    CRYPTO_STATIC_MUTEX_unlock_write(lock);
    return 1;
  }

  // Okay, we are really the first to update the state after detecting an UBE.
  ube_update_state(current_fork_gn, current_snapsafe_gn);
  *current_generation_number = ube_state.generation_number;
  CRYPTO_STATIC_MUTEX_unlock_write(lock);

  return 1;
}
