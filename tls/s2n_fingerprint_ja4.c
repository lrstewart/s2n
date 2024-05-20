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
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_client_hello.h"
#include "utils/s2n_blob.h"
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

static int s2n_fingerprint_network_order_iana_compare(const void * a, const void * b)
{
    uint8_t *iana_a = (uint8_t *) a;
    uint8_t *iana_b = (uint8_t *) b;
    if (iana_a[1] != iana_b[1]) {
        return iana_a[1] - iana_b[1];
    }
    return iana_a[0] - iana_b[0];
}

static S2N_RESULT s2n_fingerprint_write_ja4_iana(struct s2n_stuffer *out,
        uint16_t iana, struct s2n_hash_state *hash)
{
    char hex[5] = { 0 };
    int written = snprintf((char *) hex, sizeof(hex), "%04x", iana);
    RESULT_ENSURE_EQ(written, 4);
    RESULT_GUARD(s2n_fingerprint_write_str(out, hex, hash));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_write_ja4_iana_list(struct s2n_stuffer *out,
        uint16_t *iana_list, size_t iana_count, struct s2n_hash_state *hash)
{
    for (size_t i = 0; i < iana_count; i++) {
        if (i > 0) {
            RESULT_GUARD(s2n_fingerprint_write_char(out, S2N_JA4_LIST_DIV, hash));
        }
        RESULT_GUARD(s2n_fingerprint_write_ja4_iana(out, iana_list[i], hash));
    }
    return S2N_RESULT_OK;
}

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

    RESULT_GUARD_POSIX(s2n_hash_reset(hash));
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
    RESULT_GUARD_POSIX(s2n_client_hello_get_parsed_extension(S2N_EXTENSION_ALPN,
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

static S2N_RESULT s2n_fingerprint_ja4_c(struct s2n_client_hello *ch, struct s2n_stuffer *output,
        struct s2n_hash_state *hash, struct s2n_blob *sort_space, size_t *str_size)
{

    uint8_t hash_mem[64] = { 0 };
    struct s2n_blob hash_blob = { 0 };
    struct s2n_stuffer hash_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&hash_blob, hash_mem, sizeof(hash_mem)));
    RESULT_GUARD_POSIX(s2n_stuffer_init(&hash_stuffer, &hash_blob));

    uint16_t *extension_ianas = (uint16_t*) (void*) sort_space->data;
    size_t max_ianas = sort_space->size / sizeof(uint16_t);

    size_t ianas_count = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_get_extension_ianas(ch, max_ianas, extension_ianas, &ianas_count));
    qsort(extension_ianas, ianas_count, sizeof(uint16_t), s2n_fingerprint_network_order_iana_compare);

    struct s2n_stuffer *write_to = hash ? hash_stuffer : output;
    RESULT_GUARD(s2n_fingerprint_write_ja4_iana_list(output, extension_ianas, ianas_count, hash));

    s2n_parsed_extension *sig_alg_extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SIGNATURE_ALGORITHMS,
            &ch->extensions, &sig_alg_extension);
    if (result == S2N_SUCCESS) {
        struct s2n_stuffer sig_algs = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_init_written(&sig_algs, &sig_alg_extension->extension));

        POSIX_GUARD(s2n_stuffer_skip_read(&sig_algs, sizeof(uint16_t)));

        const char div_chr = S2N_JA4_PART_DIV;
        while (s2n_stuffer_data_available(&sig_algs)) {
            RESULT_GUARD(s2n_fingerprint_write_char(write_to, div_chr, hash));
            uint16_t iana = 0;
            RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(sig_algs, &iana));
            RESULT_GUARD(s2n_fingerprint_write_ja4_iana(write_to, iana, hash));
            div_chr = S2N_JA4_LIST_DIV;
        }
    }

    if (hash) {
        RESULT_GUARD(s2n_fingerprint_hash_flush(hash, &hash_stuffer));
        RESULT_GUARD(s2n_fingerprint_ja4_digest(hash, SHA256_DIGEST_LENGTH, output));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_b(struct s2n_client_hello *ch, struct s2n_stuffer *output,
        struct s2n_hash_state *hash, struct s2n_blob *sort_space, size_t *str_size)
{
    uint16_t *ianas = (uint16_t*) (void*) sort_space->data;
    size_t max_ianas = sort_space->size / sizeof(uint16_t);

    size_t ianas_count = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_get_cipher_suite_ianas(ch, max_ianas, ianas, &ianas_count));
    qsort(ianas, ianas_count, sizeof(uint16_t), s2n_fingerprint_network_order_iana_compare);

    if (!hash) {
        return s2n_fingerprint_write_ja4_iana_list(output, ianas, ianas_count, hash);
    }

    uint8_t hash_mem[64] = { 0 };
    struct s2n_blob hash_blob = { 0 };
    struct s2n_stuffer hash_stuffer = { 0 };
    RESULT_GUARD_POSIX(s2n_blob_init(&hash_blob, hash_mem, sizeof(hash_mem)));
    RESULT_GUARD_POSIX(s2n_stuffer_init(&hash_stuffer, &hash_blob));

    RESULT_GUARD(s2n_fingerprint_write_ja4_iana_list(output, ianas, ianas_count, hash));
    RESULT_GUARD(s2n_fingerprint_hash_flush(hash, &hash_stuffer));
    RESULT_GUARD(s2n_fingerprint_ja4_digest(hash, SHA256_DIGEST_LENGTH, output));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_get_cipher_suite_ianas(struct s2n_client_hello *ch,
        size_t max_ianas, uint16_t *ianas, size_t *ianas_count)
{
    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE_REF(ianas_count);
    *ianas_count = 0;

    struct s2n_stuffer cipher_suites = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&cipher_suites, &ch->cipher_suites));

    size_t count = 0;
    while (s2n_stuffer_data_available(&cipher_suites)) {
        uint16_t iana = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&cipher_suites, &iana));
        if (s2n_is_grease_value(iana)) {
            continue;
        }

        if (ianas) {
            RESULT_ENSURE_LT(count, max_ianas);
            ianas[count] = iana;
        }
        count++;
    }
    *ianas_count = count;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_get_extension_ianas(struct s2n_client_hello *ch,
        size_t max_ianas, uint16_t *ianas, size_t *ianas_count)
{
    RESULT_ENSURE_REF(ch);
    RESULT_ENSURE_REF(ianas_count);
    *ianas_count = 0;

    struct s2n_stuffer extensions = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&extensions, &ch->extensions.raw));

    size_t count = 0;
    while (s2n_stuffer_data_available(&extensions)) {
        uint16_t iana = 0;
        RESULT_GUARD_POSIX(s2n_fingerprint_parse_extension(&extensions, &iana));
        if (s2n_is_grease_value(iana)) {
            continue;
        }
        if (ianas) {
            /* We consider the server_name and alpn extension when counting
             * extensions, but not when actually listing extensions.
             */
            if (iana == TLS_EXTENSION_SERVER_NAME) {
                continue;
            }
            if (iana == S2N_EXTENSION_ALPN) {
                continue;
            }

            RESULT_ENSURE_LT(count, max_ianas);
            ianas[count] = iana;
        }
        count++;
    }
    *ianas_count = count;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_a(struct s2n_client_hello *ch, struct s2n_stuffer *output,
        size_t *required_sort_space)
{
    RESULT_ENSURE_REF(required_sort_space);
    *required_sort_space = 0;

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
    size_t cipher_suite_count = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_get_cipher_suite_ianas(ch, 0, NULL, &cipher_suite_count));

    /* Same as counting ciphers. Ignore GREASE. Include SNI and ALPN. */
    size_t extension_count = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_get_extension_ianas(ch, 0, NULL, &extension_count));

    /* The first and last characters of the ALPN first value.
     * If there are no ALPN values or no ALPN extension then we print “00” as
     * the value in the fingerprint.
     */
    RESULT_GUARD(s2n_fingerprint_write_alpn(output, ch));

    *required_sort_space = MAX(cipher_suite_count, extension_count) * sizeof(uint16_t);
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_fingerprint_ja4(struct s2n_client_hello *ch,
        struct s2n_stuffer *output, struct s2n_hash_state *hash, size_t *str_size)
{
    RESULT_ENSURE_REF(ch);

    size_t required_sort_space = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_a(ch, output, &required_sort_space));

    uint16_t sort_space_mem[100] = { 0 };
    DEFER_CLEANUP(struct s2n_blob sort_space = { 0 }, s2n_free_or_wipe);
    if (required_sort_space < sizeof(sort_space_mem)) {
        RESULT_GUARD_POSIX(s2n_alloc(&sort_space, required_sort_space));
    } else {
        RESULT_GUARD_POSIX(s2n_blob_init(&sort_space, sort_space_mem, sizeof(sort_space_mem)));
    }

    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_b(ch, output, hash, &sort_space, str_size));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_c(ch, output, hash, &sort_space, str_size));

    return S2N_RESULT_OK;
}
