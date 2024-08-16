// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#ifndef OPENSSL_HEADER_CRYPTO_UBE_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_UBE_INTERNAL_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <openssl/base.h>

OPENSSL_EXPORT int get_ube_generation_number(uint64_t *current_generation_number);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_UBE_INTERNAL_H
