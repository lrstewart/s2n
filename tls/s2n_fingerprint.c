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

#include "api/unstable/fingerprint.h"
#include "crypto/s2n_fips.h"
#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_crypto_constants.h"
#include "tls/s2n_fingerprint.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

struct s2n_fingerprint_state {
    const struct s2n_fingerprint_type_impl *impl;
    s2n_fingerprint_output_type output_type;
    struct s2n_stuffer *output;
    struct s2n_stuffer *hash_input;
    struct s2n_hash_state *hash;
    uint32_t string_size;
};

struct s2n_fingerprint_output {
    s2n_fingerprint_output_type type;
    struct s2n_stuffer *output;
    struct s2n_hash_state *hash;
    struct s2n_fingerprint_state *state;
};

static S2N_RESULT s2n_fingerprint_output_validate(struct s2n_fingerprint_output *output)
{
    RESULT_ENSURE_REF(output);
    RESULT_ENSURE_REF(output->output);
    if (output->type == S2N_FINGERPRINT_HASH) {
        RESULT_ENSURE_REF(output->hash);
    } else {
        RESULT_ENSURE_EQ(output->type, S2N_FINGERPRINT_STR);
    }
    RESULT_ENSURE_REF(output->state);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_output(struct s2n_fingerprint_state *state,
        s2n_fingerprint_output_type type, struct s2n_fingerprint_output *output)
{
    if (type == S2N_FINGERPRINT_HASH && state->output_type == S2N_FINGERPRINT_HASH) {
        *output = (struct s2n_fingerprint_output) {
            .output_type = S2N_FINGERPRINT_HASH,
            .output = state->hash_input,
            .hash = state->hash,
            .state = state,
        };
    } else {
        *output = (struct s2n_fingerprint_output) {
            .output_type = S2N_FINGERPRINT_STR,
            .output = state->output,
            .state = state,
        };
    }
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_finalize(struct s2n_fingerprint_output *output)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    struct s2n_fingerprint_state *state = output->state;

    if (output->type != S2N_FINGERPRINT_HASH) {
        return S2N_RESULT_OK;
    }

    RESULT_GUARD(s2n_fingerprint_hash_flush(output));

    uint64_t bytes_in_hash = 0;
    POSIX_GUARD(s2n_hash_get_currently_in_hash_total(output->hash, &bytes_in_hash));
    POSIX_ENSURE_LTE(bytes_in_hash, UINT32_MAX);
    state->string_size += bytes_in_hash;

    uint32_t digest_size = 0;
    RESULT_GUARD_POSIX(s2n_hash_digest_size(output->hash->alg, &digest_size));

    RESULT_ENSURE_REF(state->impl);
    RESULT_ENSURE_REF(state->impl->digest);
    RESULT_GUARD(state->impl->digest(output->hash, digest_size, state->output));

    RESULT_GUARD_POSIX(s2n_hash_reset(output->hash));
    return S2N_RESULT_OK;
}

/* See https://datatracker.ietf.org/doc/html/rfc8701
 * for an explanation of GREASE and lists of the GREASE values.
 */
static S2N_RESULT s2n_assert_grease_value(uint16_t val)
{
    uint8_t byte1 = val >> 8;
    uint8_t byte2 = val & 0x00FF;
    /* Both bytes of the GREASE values are identical */
    RESULT_ENSURE_EQ(byte1, byte2);
    /* The GREASE value bytes all follow the format 0x[0-F]A.
     * So 0x0A, 0x1A, 0x2A etc, up to 0xFA. */
    RESULT_ENSURE_EQ((byte1 | 0xF0), 0xFA);
    return S2N_RESULT_OK;
}

bool s2n_is_grease_value(uint16_t val)
{
    return s2n_result_is_ok(s2n_assert_grease_value(val));
}

static S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_fingerprint_output *output)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    uint32_t hash_data_len = s2n_stuffer_data_available(output->output);
    uint8_t *hash_data = s2n_stuffer_raw_read(output->output, hash_data_len);
    RESULT_ENSURE_REF(hash_data);
    RESULT_GUARD_POSIX(s2n_hash_update(output->hash, hash_data, hash_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(output->output));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_reserve_space(struct s2n_fingerprint_output *output, uint32_t space)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    if (s2n_stuffer_space_remaining(output->output) < space) {
        /* If the buffer is full and needs to be flushed, but no hash was provided,
         * then we have insufficient memory to complete the fingerprint.
         *
         * The application will need to provide a larger buffer.
         */
        RESULT_ENSURE(output->hash, S2N_ERR_INSUFFICIENT_MEM_SIZE);

        RESULT_GUARD(s2n_fingerprint_hash_flush(output));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_write_char(struct s2n_fingerprint_output *output, char c)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    RESULT_GUARD_POSIX(s2n_fingerprint_reserve_space(output, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output->output, c));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_write_str(struct s2n_fingerprint_output *output, const char *str)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));
    RESULT_GUARD_POSIX(s2n_fingerprint_reserve_space(output, strlen(str)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(output->output, str));
    return S2N_RESULT_OK;
}

static int s2n_fingerprint_network_order_iana_compare(const void * a, const void * b)
{
    uint8_t *iana_a = (uint8_t *) a;
    uint8_t *iana_b = (uint8_t *) b;
    if (iana_a[1] != iana_b[1]) {
        return iana_a[1] - iana_b[1];
    }
    return iana_a[0] - iana_b[0];
}

S2N_RESULT s2n_iana_list_sort(void *values, size_t values_count)
{
    qsort(values, values_count, 2, s2n_fingerprint_network_order_iana_compare);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_get_impl(s2n_fingerprint_type type, const struct s2n_fingerprint_type_impl **impl)
{
    RESULT_ENSURE_REF(impl);
    switch(type) {
        case S2N_FINGERPRINT_JA3:
            *impl = &s2n_fingerprint_ja3_impl;
            break;
        case S2N_FINGERPRINT_JA3_HEX:
            *impl = &s2n_fingerprint_ja3_hex_impl;
            break;
        case S2N_FINGERPRINT_JA4:
            *impl = &s2n_fingerprint_ja4_impl;
            break;
        default:
            RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }
    return S2N_RESULT_OK;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_hash_size, uint8_t *output, uint32_t *output_size, uint32_t *str_size)
{
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    POSIX_ENSURE_REF(str_size);
    *output_size = 0;
    *str_size = 0;

    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD_RESULT(s2n_blob_init(&output_stuffer.blob, output, output_size));

    const struct s2n_fingerprint_type_impl *impl = NULL;
    POSIX_GUARD_RESULT(s2n_fingerprint_get_impl(type, &impl));
    POSIX_ENSURE_REF(impl);
    POSIX_ENSURE(max_hash_size >= impl->hashed_size, S2N_ERR_INSUFFICIENT_MEM_SIZE);

    /* The maximum size of the JA3 string is variable and could theoretically
     * be extremely large. However, we don't need enough memory to hold the full
     * string when calculating a hash. We can calculate and add the JA3 string
     * to the hash in chunks, similarly to how the TLS transcript hash is
     * calculated by adding handshake messages to the hash as they become
     * available. After a chunk is added to the hash, the string buffer can be
     * wiped and reused for the next chunk.
     *
     * The size of this buffer was chosen to be the block size of most common hashes.
     */
    uint8_t string_mem[64] = { 0 };
    struct s2n_blob string_blob = { 0 };
    struct s2n_stuffer string_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&string_blob, string_mem, sizeof(string_mem)));
    POSIX_GUARD(s2n_stuffer_init(&string_stuffer, &string_blob));

    DEFER_CLEANUP(struct s2n_hash_state hash = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_hash_new(&hash));
    /* This hash is unrelated to TLS and does not affect FIPS.
     * We intentionally ignore failures here -- best effort. */
    s2n_hash_allow_md5_for_fips(&hash);
    RESULT_GUARD_POSIX(s2n_hash_init(&hash, impl->hash_alg));

    struct s2n_fingerprint_state state = {
        .impl = impl,
        .output_type = S2N_FINGERPRINT_HASH,
        .output = &output_stuffer,
        .hash_input = &string_stuffer,
        .hash = &hash,
    };
    RESULT_ENSURE_REF(impl->fingerprint);
    RESULT_GUARD(impl->fingerprint(state, ch));
    *str_size = state->string_size;

    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(max_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    *output_size = 0;

    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    struct s2n_blob output_blob = { 0 };
    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_blob, output, max_size));
    POSIX_GUARD(s2n_stuffer_init(&output_stuffer, &output_blob));

    const struct s2n_fingerprint_type_impl *impl = NULL;
    POSIX_GUARD_RESULT(s2n_fingerprint_get_impl(type, &impl));
    POSIX_ENSURE_REF(impl);

    struct s2n_fingerprint_state state = {
        .impl = impl,
        .output_type = S2N_FINGERPRINT_STR,
        .output = &output_stuffer,
    };
    RESULT_ENSURE_REF(impl->fingerprint);
    RESULT_GUARD(impl->fingerprint(state, ch));
    *output_size = s2n_stuffer_data_available(&output_stuffer);

    return S2N_SUCCESS;
}

S2N_API int s2n_client_hello_sort_for_fingerprint(struct s2n_client_hello *ch,
        s2n_fingerprint_type type)
{
    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);

    const struct s2n_fingerprint_type_impl *impl = NULL;
    POSIX_GUARD_RESULT(s2n_fingerprint_get_impl(type, &impl));
    POSIX_ENSURE_REF(impl);

    RESULT_ENSURE_REF(impl->sort);
    RESULT_GUARD(impl->sort(ch));

    return S2N_SUCCESS;
}
