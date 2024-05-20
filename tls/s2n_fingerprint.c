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
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

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

static S2N_RESULT s2n_fingerprint_hash_flush(struct s2n_hash_state *hash, struct s2n_stuffer *in)
{
    uint32_t hash_data_len = s2n_stuffer_data_available(in);
    uint8_t *hash_data = s2n_stuffer_raw_read(in, hash_data_len);
    RESULT_ENSURE_REF(hash_data);
    RESULT_GUARD_POSIX(s2n_hash_update(hash, hash_data, hash_data_len));
    RESULT_GUARD_POSIX(s2n_stuffer_wipe(in));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_reserve_space(struct s2n_stuffer *stuffer,
        struct s2n_hash_state *hash, size_t space)
{
    if (s2n_stuffer_space_remaining(stuffer) < space) {
        /* If the buffer is full and needs to be flushed, but no hash was provided,
         * then we have insufficient memory to complete the fingerprint.
         *
         * The application will need to provide a larger buffer.
         */
        RESULT_ENSURE(hash, S2N_ERR_INSUFFICIENT_MEM_SIZE);
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash, stuffer));
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_write_char(struct s2n_stuffer *stuffer,
        char c, struct s2n_hash_state *hash)
{
    RESULT_GUARD(s2n_fingerprint_reserve_space(stuffer, hash, 1));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(stuffer, c));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_write_str(struct s2n_stuffer *stuffer, const char *str,
        struct s2n_hash_state *hash)
{
    RESULT_GUARD(s2n_fingerprint_reserve_space(stuffer, hash, strlen(str)));
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(stuffer, str));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        struct s2n_stuffer *output, struct s2n_hash_state *hash, size_t *str_size)
{
    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE(!ch->sslv2, S2N_ERR_PROTOCOL_VERSION_UNSUPPORTED);
    switch(type) {
        case S2N_FINGERPRINT_JA3:
            RESULT_GUARD(s2n_fingerprint_ja3(ch, output, hash, str_size));
            break;
        default:
            RESULT_BAIL(S2N_ERR_INVALID_ARGUMENT);
    }
    return S2N_RESULT_OK;
}

int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size, uint32_t *str_size)
{
    POSIX_ENSURE(max_output_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    POSIX_ENSURE_REF(str_size);
    *output_size = 0;
    *str_size = 0;

    struct s2n_blob output_blob = { 0 };
    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_blob, output, max_output_size));
    POSIX_GUARD(s2n_stuffer_init(&output_stuffer, &output_blob));

    DEFER_CLEANUP(struct s2n_hash_state hash = { 0 }, s2n_hash_free);
    POSIX_GUARD(s2n_hash_new(&hash));

    POSIX_GUARD_RESULT(s2n_fingerprint(ch, type, &output_stuffer, &hash, str_size));
    *output_size = s2n_stuffer_data_available(&output_stuffer);

    return S2N_SUCCESS;
}

int s2n_client_hello_get_fingerprint_string(struct s2n_client_hello *ch, s2n_fingerprint_type type,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size)
{
    POSIX_ENSURE(max_output_size > 0, S2N_ERR_INSUFFICIENT_MEM_SIZE);
    POSIX_ENSURE_REF(output);
    POSIX_ENSURE_REF(output_size);
    *output_size = 0;

    struct s2n_blob output_blob = { 0 };
    struct s2n_stuffer output_stuffer = { 0 };
    POSIX_GUARD(s2n_blob_init(&output_blob, output, max_output_size));
    POSIX_GUARD(s2n_stuffer_init(&output_stuffer, &output_blob));

    POSIX_GUARD_RESULT(s2n_fingerprint(ch, type, &output_stuffer, NULL, NULL));
    *output_size = s2n_stuffer_data_available(&output_stuffer);

    return S2N_SUCCESS;
}
