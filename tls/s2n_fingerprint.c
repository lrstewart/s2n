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

#include "tls/s2n_fingerprint.h"

#include "crypto/s2n_hash.h"
#include "stuffer/s2n_stuffer.h"
#include "tls/s2n_client_hello.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_mem.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_fingerprint_hash_init(struct s2n_fingerprint_hash *hash,
        struct s2n_hash_state *hash_state, s2n_hash_algorithm hash_alg)
{
    RESULT_ENSURE_REF(hash);

    RESULT_ENSURE_REF(hash_state);
    RESULT_GUARD_POSIX(s2n_hash_init(hash_state, hash_alg));
    hash->hash = hash_state;

    RESULT_GUARD_POSIX(s2n_blob_init(&hash->buffer.blob, hash->buffer_mem,
            sizeof(hash->buffer_mem)));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_fingerprint_hash *hash)
{
    RESULT_ENSURE_REF(hash);

    uint32_t hash_data_len = s2n_stuffer_data_available(&hash->buffer);
    uint8_t *hash_data = s2n_stuffer_raw_read(&hash->buffer, hash_data_len);
    RESULT_GUARD_PTR(hash_data);

    RESULT_GUARD_POSIX(s2n_hash_update(hash->hash, hash_data, hash_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(&hash->buffer));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_hash_reserve_space(struct s2n_fingerprint_hash *hash, size_t size)
{
    RESULT_ENSURE_REF(hash);
    if (s2n_stuffer_space_remaining(&hash->buffer) < size) {
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_add_char(struct s2n_fingerprint_hash *hash, char c)
{
    RESULT_GUARD(s2n_fingerprint_hash_reserve_space(hash, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(&hash->buffer, c));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_hash_add_str(struct s2n_fingerprint_hash *hash, const char *str)
{
    RESULT_GUARD(s2n_fingerprint_hash_reserve_space(hash, strlen(str)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(&hash->buffer, str));
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

S2N_RESULT s2n_fingerprint_parse_extension(struct s2n_stuffer *input, uint16_t *iana)
{
    uint16_t size = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(input, iana));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(input, &size));
    RESULT_GUARD_POSIX(s2n_stuffer_skip_read(input, size));
    return S2N_RESULT_OK;
}

struct s2n_fingerprint *s2n_fingerprint_new(s2n_fingerprint_type type)
{
    DEFER_CLEANUP(struct s2n_blob mem = { 0 }, s2n_free);
    PTR_GUARD_POSIX(s2n_blob_zero(&mem));
    struct s2n_fingerprint *fingerprint = (struct s2n_fingerprint*) mem.data;
    PTR_ENSURE_REF(fingerprint);

    switch (type) {
        case S2N_FINGERPRINT_JA3:
            fingerprint->method = &ja3_fingerprint;
            break;
        case S2N_FINGERPRINT_JA4:
            fingerprint->method = &ja4_fingerprint;
            break;
        default:
            PTR_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }

    PTR_GUARD_POSIX(s2n_hash_new(&fingerprint->hash));
    s2n_hash_allow_md5_for_fips(&fingerprint->hash);

    PTR_GUARD_POSIX(s2n_fingerprint_wipe(fingerprint));
    ZERO_TO_DISABLE_DEFER_CLEANUP(mem);
    return fingerprint;
}

int s2n_fingerprint_wipe(struct s2n_fingerprint *fingerprint)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    const struct s2n_fingerprint_method *method = fingerprint->method;
    struct s2n_hash_state hash = fingerprint->hash;

    POSIX_CHECKED_MEMCPY(fingerprint, 0, sizeof(struct s2n_fingerprint));
    fingerprint->method = method;
    fingerprint->hash = hash;

    POSIX_GUARD(s2n_hash_reset(&fingerprint->hash));
    POSIX_GUARD(s2n_blob_init(&fingerprint->workspace.blob,
            fingerprint->workspace_mem, sizeof(fingerprint->workspace_mem)));
    return S2N_SUCCESS;
}

int s2n_fingerprint_free(struct s2n_fingerprint **fingerprint_ptr)
{
    if (fingerprint_ptr) {
        struct s2n_fingerprint *fingerprint = *fingerprint_ptr;
        POSIX_GUARD(s2n_hash_free(&fingerprint->hash));
        POSIX_GUARD(s2n_stuffer_free(&fingerprint->workspace));
    }
    POSIX_GUARD(s2n_free_object((uint8_t**) (void**) fingerprint_ptr,
            sizeof(struct s2n_fingerprint)));
    return S2N_SUCCESS;
}

int s2n_fingerprint_set_client_hello(struct s2n_fingerprint *fingerprint, struct s2n_client_hello *ch)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(ch, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    POSIX_ENSURE(!fingerprint->finalized, S2N_ERR_INVALID_STATE);
    fingerprint->client_hello = ch;
    return S2N_SUCCESS;
}

int s2n_fingerprint_set_working_buffer(struct s2n_fingerprint *fingerprint,
        uint8_t *mem, size_t mem_size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(mem, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(mem_size > 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(!fingerprint->finalized, S2N_ERR_INVALID_STATE);
    POSIX_GUARD(s2n_stuffer_free(&fingerprint->workspace));
    POSIX_GUARD(s2n_blob_init(&fingerprint->workspace.blob, mem, mem_size));
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_hash_size(struct s2n_fingerprint *fingerprint, uint32_t *size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(size, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE_REF(fingerprint->method);
    *size = fingerprint->method->hash_size;
    return S2N_SUCCESS;
}

int s2n_fingerprint_get_hash(struct s2n_fingerprint *fingerprint,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(fingerprint, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(!fingerprint->finalized, S2N_ERR_INVALID_STATE);
    POSIX_ENSURE_REF(fingerprint->method);
    POSIX_ENSURE(max_output_size <= fingerprint->method->hash_size,
            S2N_ERR_INSUFFICIENT_MEM_SIZE);

    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_stuffer.blob, output, max_output_size));

    POSIX_GUARD_RESULT(fingerprint->method->hash(fingerprint, &output_stuffer));
    fingerprint->finalized = true;
    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size, uint32_t *str_size)
{
    POSIX_ENSURE_REF(str_size);
    *str_size = 0;

    DEFER_CLEANUP(struct s2n_fingerprint *fingerprint = s2n_fingerprint_new(type),
            s2n_fingerprint_free);
    POSIX_GUARD_PTR(fingerprint);
    POSIX_GUARD(s2n_fingerprint_set_client_hello(fingerprint, ch));
    POSIX_GUARD(s2n_fingerprint_get_hash(fingerprint, max_output_size, output, output_size));
    return S2N_SUCCESS;
}
