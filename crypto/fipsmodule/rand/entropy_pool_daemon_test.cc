// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <gtest/gtest.h>

#include <openssl/rand.h>

#include "internal.h"
#include "../../test/file_test.h"
#include "../../test/test_util.h"

TEST(RandPoolTests, DaemonPoolBasic) {

  if (!use_daemon_entropy_pool()) {
    return;
  }

  uint8_t test_buffer_get[256] = {0};

  ASSERT_TRUE(daemon_entropy_pool_get_entropy(test_buffer_get, 64) == 1);
  ASSERT_TRUE(daemon_entropy_pool_get_entropy(test_buffer_get, 128) == 1);
  ASSERT_TRUE(daemon_entropy_pool_get_entropy(test_buffer_get, 32) == 1);
  ASSERT_TRUE(daemon_entropy_pool_get_entropy(test_buffer_get, 64) == 1);
  ASSERT_TRUE(daemon_entropy_pool_get_entropy(test_buffer_get, 256) == 1);
  ASSERT_TRUE(RAND_bytes(test_buffer_get, 64));

  ASSERT_TRUE(daemon_entropy_pool_clean_thread() == 1);
}
