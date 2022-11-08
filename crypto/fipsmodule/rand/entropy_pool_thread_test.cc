// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <gtest/gtest.h>

#include "internal.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"

TEST(RandPoolTests, ThreadPoolBasic) {

  ASSERT_TRUE(thread_entropy_pool_start() == 1);

  uint8_t test_buffer_get[64] = {0};
  ASSERT_TRUE(thread_entropy_pool_get_entropy(test_buffer_get, 64) == 1);
  ASSERT_TRUE(thread_entropy_pool_get_entropy(test_buffer_get, 64) == 1);
  ASSERT_TRUE(thread_entropy_pool_get_entropy(test_buffer_get, 64) == 1);
}
