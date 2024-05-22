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
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_client_hello.h"
#include "utils/s2n_result.h"

#define S2N_HEX_PER_BYTE 2

struct s2n_fingerprint_method {
    uint32_t hash_size;
    S2N_RESULT (*hash)(struct s2n_fingerprint *fingerprint, struct s2n_stuffer *output);
};
extern struct s2n_fingerprint_method ja3_fingerprint;
extern struct s2n_fingerprint_method ja4_fingerprint;

struct s2n_fingerprint {
    const struct s2n_fingerprint_method *method;
    uint8_t workspace_mem[256];
    struct s2n_stuffer workspace;
    struct s2n_hash_state hash;
    struct s2n_client_hello *client_hello;
    unsigned int finalized : 1;
};

/* The maximum size of the hash input string is variable and could theoretically
 * be extremely large. However, we don't need enough memory to hold the full string
 * when calculating a hash. We can calculate and add the string to the hash in chunks,
 * similarly to how the TLS transcript hash is calculated by adding handshake
 * messages to the hash as they become available. After a chunk is added to the hash,
 * the buffer can be wiped and reused for the next chunk.
 *
 * This ensures that our calculation requires a constant amount of memory.
 *
 * The size of the buffer is chosen to be the block size of most hashes.
 */
struct s2n_fingerprint_hash {
    uint8_t buffer_mem[64];
    struct s2n_stuffer buffer;
    struct s2n_hash_state *hash;
};
S2N_RESULT s2n_fingerprint_hash_init(struct s2n_fingerprint_hash *hash,
        struct s2n_hash_state *hash_state, s2n_hash_algorithm hash_alg);
S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_fingerprint_hash *hash);
S2N_RESULT s2n_fingerprint_hash_add_char(struct s2n_fingerprint_hash *hash, char c);
S2N_RESULT s2n_fingerprint_hash_add_str(struct s2n_fingerprint_hash *hash, const char *str);

bool s2n_is_grease_value(uint16_t val);
S2N_RESULT s2n_fingerprint_parse_extension(struct s2n_stuffer *input, uint16_t *iana);
