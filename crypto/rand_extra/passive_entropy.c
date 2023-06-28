// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include "../fipsmodule/rand/internal.h"

#if defined(AWSLC_FIPS)

void RAND_module_entropy_depleted(void) {
    uint8_t entropy_buffer[PASSIVE_ENTROPY_LEN] = { 0 };
    int want_additional_input = 0;
    CRYPTO_get_seed_entropy(entropy_buffer, sizeof(entropy_buffer),
        &want_additional_input);    
    RAND_load_entropy(entropy_buffer, sizeof(entropy_buffer),
        want_additional_input);
}

#endif
