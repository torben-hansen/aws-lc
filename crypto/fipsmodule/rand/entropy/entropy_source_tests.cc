// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <gtest/gtest.h>

#include "internal.h"

#define MAX_MULTIPLE_FROM_RNG (16)

// In the future this test can be improved by being able to predict whether the
// test is running on hardware that we expect to support RNDR. This will require
// amending the CI with such information.
// For now, simply ensure we exercise all code-paths in the
// CRYPTO_rndr_multiple8 implementation.
TEST(EntropySupport, Aarch64) {
  uint8_t buf[MAX_MULTIPLE_FROM_RNG*8] = { 0 } ;

#if !defined(OPENSSL_AARCH64)
  ASSERT_FALSE(have_hw_rng_aarch64_for_testing());
  ASSERT_FALSE(rndr_multiple8(buf, 0));
  ASSERT_FALSE(rndr_multiple8(buf, 8));
#else
  if (have_hw_rng_aarch64_for_testing() != 1) {
    GTEST_SKIP() << "Compiled for Arm64, but Aarch64 hw rng is not available in run-time";
  }

  // Extracting 0 bytes is never supported.
  ASSERT_FALSE(rndr_multiple8(buf, 0));

  // Multiples of 8 allowed.
  for (size_t i = 8; i < MAX_MULTIPLE_FROM_RNG; i += 8) {
    ASSERT_TRUE(rndr_multiple8(buf, i));
  }

  // Must be multiples of 8.
  for (size_t i : {1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15}) {
    ASSERT_FALSE(rndr_multiple8(buf, i));
  }
#endif
}