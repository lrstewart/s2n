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

#define S2N_JA4_LIST_DIV  ','
#define S2N_JA4_PART_DIV  '_'

#define S2N_JA4_DIGEST_HEX_CHAR_LIMIT 12
#define S2N_HEX_CHAR_SIZE             2
#define S2N_JA4_DIGEST_BYTE_LIMIT     (S2N_JA4_DIGEST_HEX_CHAR_LIMIT / S2N_HEX_CHAR_SIZE)

#define S2N_JA4_A_SIZE 10
#define S2N_JA4_B_SIZE S2N_JA4_DIGEST_HEX_CHAR_LIMIT
#define S2N_JA4_C_SIZE S2N_JA4_DIGEST_HEX_CHAR_LIMIT
#define S2N_JA4_SIZE   (S2N_JA4_A_SIZE + 1 + S2N_JA4_B_SIZE + 1 + S2N_JA4_C_SIZE)

#define S2N_JA4_LIST_LIMIT 99

const const char s2n_ja4_version_strings[][3] = {
        [s2n_unknown_protocol_version] = "00",
        [S2N_TLS13] = "13",
        [S2N_TLS12] = "12",
        [S2N_TLS11] = "11",
        [S2N_TLS10] = "10",
        [S2N_SSLv3] = "s3",
};

static S2N_RESULT s2n_fingerprint_ja4_digest(struct s2n_hash_state *hash,
        uint32_t digest_size, struct s2n_stuffer *out)
{
    RESULT_ENSURE_EQ(digest_size, SHA256_DIGEST_LENGTH);
    uint8_t digest_bytes[SHA256_DIGEST_LENGTH] = { 0 };
    RESULT_GUARD_POSIX(s2n_hash_digest(hash, digest_bytes, digest_size));

    /* Add an extra char to account for the trailing '\0' */
    char hex[S2N_HEX_CHAR_SIZE + 1] = { 0 };

    /* Convert the digest to hex and truncate it */
    for (size_t i = 0; i < S2N_JA4_DIGEST_BYTE_LIMIT; i++) {
        int written = snprintf((char *) hex, sizeof(hex), "%02x", digest_bytes[i]);
        RESULT_ENSURE_EQ(written, S2N_HEX_CHAR_SIZE);
        RESULT_GUARD_POSIX(s2n_stuffer_write_str(out, hex));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_version(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);

    uint8_t client_protocol_version = ch->legacy_version;

    s2n_parsed_extension *supported_versions_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SUPPORTED_VERSIONS,
            &ch->extensions, &supported_versions_extension);
    if (result == S2N_SUCCESS) {
        struct s2n_stuffer supported_versions = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_init_written(&supported_versions,
                &supported_versions_extension->extension));

        uint8_t actual_protocol_version = s2n_unknown_protocol_version;
        RESULT_GUARD_POSIX(s2n_extensions_client_supported_versions_process(supported_versions,
                UINT8_MAX, &client_protocol_version, &actual_protocol_version));
    }

    const char *version_str = s2n_ja4_version_strings[client_protocol_version];
    if (version_str == NULL) {
        version_str = s2n_ja4_version_strings[s2n_unknown_protocol_version];
    }
    RESULT_ENSURE_EQ(strlen(version_str), 2);
    RESULT_GUARD(s2n_fingerprint_write_str(output, version_str));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_client_hello_get_first_alpn(struct s2n_client_hello *ch, struct s2n_blob *first)
{
    s2n_parsed_extension *alpn_extension = NULL;
    RESULT_GUARD_POSIX(s2n_client_hello_get_parsed_extension(S2N_EXTENSION_EC_POINT_FORMATS,
            &ch->extensions, &alpn_extension));

    struct s2n_stuffer protocols = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&protocols, &alpn_extension->extension));
    RESULT_ENSURE_OK(s2n_protocol_preferences_read(&protocols, first), S2N_ERR_BAD_MESSAGE);
    RESULT_ENSURE_GTE(first->size, 2);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_alpn(struct s2n_fingerprint_output *output,
        struct s2n_client_hello *ch)
{
    struct s2n_blob protocol = { 0 };
    if (s2n_result_is_error(s2n_client_hello_get_first_alpn(ch, &protocol))) {
        RESULT_GUARD(s2n_fingerprint_write_str(output, "00"));
        return S2N_RESULT_OK;
    }

    RESULT_GUARD(s2n_fingerprint_write_char(output, protocol.data[0]));
    RESULT_GUARD(s2n_fingerprint_write_char(output, protocol.data[protocol.size - 1]));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_a(struct s2n_fingerprint_state *state, struct s2n_client_hello *ch)
{
    struct s2n_fingerprint_output output = { 0 };
    RESULT_GUARD(s2n_fingerprint_output(state, S2N_FINGERPRINT_STR, &output));

    /* “q”, "d" or “t”, denotes whether the hello packet is for QUIC, DTLS, or normal TLS. */
    bool is_quic = false;
    RESULT_GUARD_POSIX(s2n_client_hello_has_extension(ch, TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS, &is_quic));
    if (is_quic) {
        RESULT_GUARD(s2n_stuffer_write_char(output, 'q'));
    } else {
        RESULT_GUARD(s2n_stuffer_write_char(output, 't'));
    }

    /* version, including supported_versions */
    RESULT_GUARD(s2n_fingerprint_write_version(output, ch));

    /* If the SNI extension (0x0000) exists, then the destination of the connection
     * is a domain, or “d” in the fingerprint. If the SNI does not exist, then the
     * destination is an IP address, or “i”.
     */
    bool has_sni = false;
    RESULT_GUARD_POSIX(s2n_client_hello_has_extension(ch, TLS_EXTENSION_SERVER_NAME, &has_sni));
    if (has_sni) {
        RESULT_GUARD(s2n_stuffer_write_char(output, 'd'));
    } else {
        RESULT_GUARD(s2n_stuffer_write_char(output, 'i'));
    }

    /* 2 character number of cipher suites, so if there’s 6 cipher suites in the
     * hello packet, then the value should be “06”. If there’s > 99, which there
     * should never be, then output “99”. Remember, ignore GREASE values.
     * They don’t count.
     */

    /* Same as counting ciphers. Ignore GREASE. Include SNI and ALPN. */

    /* The first and last characters of the ALPN first value.
     * If there are no ALPN values or no ALPN extension then we print “00” as
     * the value in the fingerprint.
     */
    RESULT_GUARD(s2n_fingerprint_write_alpn(output, ch));

    RESULT_GUARD(s2n_fingerprint_output_finalize(output));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_b(struct s2n_fingerprint_state *state, struct s2n_client_hello *ch)
{
    struct s2n_fingerprint_output output = { 0 };
    RESULT_GUARD(s2n_fingerprint_output(state, S2N_FINGERPRINT_HASH, &output));

    struct s2n_stuffer cipher_suites = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&cipher_suites, &ch->cipher_suites));
    size_t cipher_suites_count = ch->cipher_suites.size / S2N_TLS_CIPHER_SUITE_LEN;

    uint16_t last_cipher_suite = 0;
    uint16_t sorted_count = 0;
    while (sorted_count < cipher_suites_count) {
        uint16_t next_cipher_suite = 0;
        uint16_t next_cipher_suite_count = 0;
        while (s2n_stuffer_data_available(&cipher_suites)) {
            uint16_t cipher_suite = 0;
            RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&cipher_suites, &cipher_suite));

            if (cipher_suite <= last_cipher_suite) {
                continue;
            }

            if (cipher_suite > next_cipher_suite) {
                continue;
            }

            if (cipher_suite == next_cipher_suite) {
                next_cipher_suite_count++;
                continue;
            }

            next_cipher_suite = cipher_suite;
            next_cipher_suite_count = 1;
        }

        for (size_t i = 0; i < next_cipher_suite_count; i++) {
            // write cipher suite
        }
        sorted_count += next_cipher_suite_count;
        last_cipher_suite = next_cipher_suite;
    }

    RESULT_GUARD(s2n_fingerprint_output_finalize(output, s2n_fingerprint_ja4_digest));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_c(struct s2n_fingerprint_state *state, struct s2n_client_hello *ch)
{
    struct s2n_fingerprint_output output = { 0 };
    RESULT_GUARD(s2n_fingerprint_output(state, S2N_FINGERPRINT_HASH, &output));

    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA4_PART_DIV));

    RESULT_GUARD(s2n_fingerprint_output_finalize(output, s2n_fingerprint_ja4_digest));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4(struct s2n_fingerprint_state *state, struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(state);
    RESULT_ENSURE_REF(ch);

    struct s2n_fingerprint_output output = { 0 };
    RESULT_GUARD(s2n_fingerprint_output(state, S2N_FINGERPRINT_STR, &output));

    RESULT_GUARD(s2n_fingerprint_ja4_a(state, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_b(state, ch));
    RESULT_GUARD(s2n_fingerprint_write_char(&output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_c(state, ch));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_sort(struct s2n_client_hello *ch)
{
    RESULT_GUARD(s2n_iana_list_sort(ch->cipher_suites.data, ch->cipher_suites.size / 2));
    RESULT_GUARD(s2n_iana_list_sort(ch->extensions));
    return S2N_RESULT_OK;
}

const struct s2n_fingerprint_type_impl s2n_fingerprint_ja3_impl = {
    .hash_alg = S2N_HASH_SHA256,
    .hashed_size = S2N_JA4_SIZE,
    .sort = s2n_fingerprint_ja4_sort,
    .fingerprint = s2n_fingerprint_ja4,
    .digest = s2n_fingerprint_ja4_digest,
};
