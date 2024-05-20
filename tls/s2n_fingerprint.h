/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#pragma once

#include "api/s2n.h"
#include "utils/s2n_result.h"

struct s2n_fingerprint_type_impl {
    s2n_hash_algorithm hash_alg;
    uint32_t hashed_size;
    S2N_RESULT (*sort)(struct s2n_client_hello *ch);
    S2N_RESULT (*fingerprint)(struct s2n_client_hello *ch,
            struct s2n_fingerprint_state *state);
    S2N_RESULT (*digest)(struct s2n_hash_state *hash,
            uint32_t digest_size, struct s2n_stuffer *out);
};

extern const struct s2n_fingerprint_type_impl s2n_fingerprint_ja3_impl;
extern const struct s2n_fingerprint_type_impl s2n_fingerprint_ja3_hex_impl;
extern const struct s2n_fingerprint_type_impl s2n_fingerprint_ja4_impl;

typedef enum {
    S2N_FINGERPRINT_STR,
    S2N_FINGERPRINT_HASH,
} s2n_fingerprint_output_type;

struct s2n_fingerprint_state;
struct s2n_fingerprint_output;

S2N_RESULT s2n_fingerprint_output(struct s2n_fingerprint_state *state,
        s2n_fingerprint_output_type type, struct s2n_fingerprint_output *output);
S2N_RESULT s2n_fingerprint_write_char(struct s2n_fingerprint_output *output, char c);
S2N_RESULT s2n_fingerprint_write_str(struct s2n_fingerprint_output *output, const char *str);
S2N_RESULT s2n_fingerprint_finalize(struct s2n_fingerprint_output *output);

bool s2n_is_grease_value(uint16_t val);
S2N_RESULT s2n_iana_list_sort(void *values, size_t values_count);
