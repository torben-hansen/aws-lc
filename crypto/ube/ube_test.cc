// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include  <gtest/gtest.h>

#include "internal.h"

TEST(Ube, Basic) {
  uint64_t generation_number = 0;
  ASSERT_TRUE(get_ube_generation_number(&generation_number));

  uint64_t current_generation_number = generation_number + 1;
  ASSERT_TRUE(get_ube_generation_number(&current_generation_number));

  ASSERT_EQ(current_generation_number, generation_number);
}