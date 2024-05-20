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
#include "api/unstable/fingerprint.h"
#include "utils/s2n_result.h"

bool s2n_is_grease_value(uint16_t val);
S2N_RESULT s2n_fingerprint_parse_extension(struct s2n_stuffer *input, uint16_t *iana);
S2N_RESULT s2n_fingerprint_reserve_space(struct s2n_stuffer *stuffer,
        struct s2n_hash_state *hash, size_t space);
S2N_RESULT s2n_fingerprint_write_char(struct s2n_stuffer *stuffer,
        char c, struct s2n_hash_state *hash);
S2N_RESULT s2n_fingerprint_write_str(struct s2n_stuffer *stuffer, const char *str,
        struct s2n_hash_state *hash);

S2N_RESULT s2n_fingerprint_ja3(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash, size_t *str_size);
