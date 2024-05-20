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
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#define S2N_JA3_FIELD_DIV ','
#define S2N_JA3_LIST_DIV  '-'

#define S2N_HEX_CHAR_SIZE 2

/* UINT16_MAX == 65535 */
#define S2N_UINT16_STR_MAX_SIZE 5

static S2N_RESULT s2n_fingerprint_ja3_entry(struct s2n_fingerprint_output *output,
        bool *is_list, uint16_t value)
{
    RESULT_GUARD(s2n_fingerprint_output_validate(output));

    /* If we have already written at least one value for this field,
     * then we are writing a list and need to prepend a list divider before
     * writing the next value.
     */
    RESULT_ENSURE_REF(is_list);
    if (*is_list) {
        RESULT_GUARD(s2n_fingerprint_write_char(output, S2N_JA3_LIST_DIV));
    }
    *is_list = true;

    /* snprintf always appends a '\0' to the output,
     * but that extra '\0' is not included in the return value */
    uint8_t entry[S2N_UINT16_STR_MAX_SIZE + 1] = { 0 };
    int written = snprintf((char *) entry, sizeof(entry), "%u", value);
    RESULT_ENSURE_GT(written, 0);
    RESULT_ENSURE_LTE(written, S2N_UINT16_STR_MAX_SIZE);

    RESULT_GUARD_POSIX(s2n_fingerprint_write_str(output, entry));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_version(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);
    bool is_list = false;
    uint16_t version = 0;
    struct s2n_stuffer message = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&message, &ch->raw_message));
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&message, &version));
    RESULT_GUARD(s2n_fingerprint_ja3_entry(output, &is_list, version));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_ciphers(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);

    bool cipher_found = false;
    struct s2n_stuffer ciphers = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&ciphers, &ch->cipher_suites));
    while (s2n_stuffer_data_available(&ciphers)) {
        uint16_t cipher = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&ciphers, &cipher));
        if (s2n_is_grease_value(cipher)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_ja3_entry(output, &cipher_found, cipher));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_extensions(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);

    /* We have to use the raw extensions instead of the parsed extensions
     * because s2n-tls both intentionally ignores any unknown extensions
     * and reorders the extensions when parsing the list.
     */
    struct s2n_stuffer extensions = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&extensions, &ch->extensions.raw));

    bool extension_found = false;
    while (s2n_stuffer_data_available(&extensions)) {
        uint16_t extension = 0, extension_size = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&extensions, &extension));
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&extensions, &extension_size));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_read(&extensions, extension_size));
        if (s2n_is_grease_value(extension)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_ja3_entry(output, &extension_found, extension));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_elliptic_curves(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);

    s2n_parsed_extension *elliptic_curves_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SUPPORTED_GROUPS,
            &ch->extensions, &elliptic_curves_extension);
    if (result != S2N_SUCCESS) {
        return S2N_RESULT_OK;
    }

    struct s2n_stuffer elliptic_curves = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&elliptic_curves,
            &elliptic_curves_extension->extension));

    uint16_t count = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&elliptic_curves, &count));

    bool curve_found = false;
    while (s2n_stuffer_data_available(&elliptic_curves)) {
        uint16_t curve = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&elliptic_curves, &curve));
        if (s2n_is_grease_value(curve)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_ja3_entry(output, &curve_found, curve));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_point_formats(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);

    s2n_parsed_extension *point_formats_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_EC_POINT_FORMATS,
            &ch->extensions, &point_formats_extension);
    if (result != S2N_SUCCESS) {
        return S2N_RESULT_OK;
    }

    struct s2n_stuffer point_formats = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&point_formats,
            &point_formats_extension->extension));

    uint8_t count = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint8(&point_formats, &count));

    bool format_found = false;
    while (s2n_stuffer_data_available(&point_formats)) {
        uint8_t format = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint8(&point_formats, &format));
        RESULT_GUARD(s2n_fingerprint_ja3_entry(output, &format_found, format));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_digest(struct s2n_hash_state *hash,
        uint32_t digest_size, struct s2n_stuffer *out)
{
    uint8_t *output_bytes = s2n_stuffer_raw_write(out, digest_size);
    RESULT_GUARD_POSIX(s2n_hash_digest(hash, output_bytes, digest_size));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_hex_digest(struct s2n_hash_state *hash,
        uint32_t digest_size, struct s2n_stuffer *out)
{
    RESULT_ENSURE_EQ(digest_size, MD5_DIGEST_LENGTH);
    uint8_t digest_bytes[MD5_DIGEST_LENGTH] = { 0 };
    RESULT_GUARD_POSIX(s2n_hash_digest(hash, digest_bytes, digest_size));

    /* Add an extra char to account for the trailing '\0' */
    char hex[S2N_HEX_CHAR_SIZE + 1] = { 0 };

    /* Convert the digest to hex */
    for (size_t i = 0; i < MD5_DIGEST_LENGTH; i++) {
        int written = snprintf((char *) hex, sizeof(hex), "%02x", digest_bytes[i]);
        RESULT_ENSURE_EQ(written, S2N_HEX_CHAR_SIZE);
        RESULT_GUARD_POSIX(s2n_stuffer_write_str(out, hex));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja3_sort(struct s2n_client_hello *ch)
{
    return S2N_RESULT_OK;
}

/* JA3 involves concatenating a set of fields from the ClientHello:
 *      SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 * For example:
 *      "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
 * See https://github.com/salesforce/ja3
 */
static S2N_RESULT s2n_fingerprint_ja3(struct s2n_fingerprint_state *state, struct s2n_client_hello *ch)
{
    struct s2n_fingerprint_output output = { 0 };
    RESULT_GUARD(s2n_fingerprint_output(state, S2N_FINGERPRINT_HASH, &output));

    RESULT_GUARD(s2n_fingerprint_ja3_version(&output, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA3_FIELD_DIV));
    RESULT_GUARD(s2n_fingerprint_ja3_ciphers(&output, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA3_FIELD_DIV));
    RESULT_GUARD(s2n_fingerprint_ja3_extensions(&output, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA3_FIELD_DIV));
    RESULT_GUARD(s2n_fingerprint_ja3_elliptic_curves(&output, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA3_FIELD_DIV));
    RESULT_GUARD(s2n_fingerprint_ja3_point_formats(&output, ch));

    RESULT_GUARD(s2n_fingerprint_output_finalize(&output, s2n_fingerprint_ja3_digest));
    return S2N_RESULT_OK;
}

const struct s2n_fingerprint_type_impl s2n_fingerprint_ja3_impl = {
    .hash_alg = S2N_HASH_MD5,
    .hashed_size = MD5_DIGEST_LENGTH,
    .sort = s2n_fingerprint_ja3_sort,
    .fingerprint = s2n_fingerprint_ja3,
    .digest = s2n_fingerprint_ja3_digest,
};

const struct s2n_fingerprint_type_impl s2n_fingerprint_ja3_hex_impl = {
    .hash_alg = S2N_HASH_MD5,
    .hashed_size = MD5_DIGEST_LENGTH * 2,
    .sort = s2n_fingerprint_ja3_sort,
    .fingerprint = s2n_fingerprint_ja3,
    .digest = s2n_fingerprint_ja3_hex_digest,
};
