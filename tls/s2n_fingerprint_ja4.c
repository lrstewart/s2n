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
#include "tls/extensions/s2n_client_supported_versions.h"
#include "tls/extensions/s2n_extension_list.h"
#include "tls/s2n_client_hello.h"
#include "tls/s2n_protocol_preferences.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_safety.h"

#define S2N_JA4_LIST_DIV  ','
#define S2N_JA4_PART_DIV  '_'

#define S2N_JA4_COUNT_MAX       99
#define S2N_JA4_COUNT_SIZE      2

#define S2N_JA4_HEX_PER_IANA          (S2N_HEX_PER_BYTE * sizeof(uint16_t))
#define S2N_JA4_DIGEST_HEX_CHAR_LIMIT 12
#define S2N_JA4_DIGEST_BYTE_LIMIT     (S2N_JA4_DIGEST_HEX_CHAR_LIMIT / S2N_HEX_PER_BYTE)

#define S2N_JA4_A_SIZE 10
#define S2N_JA4_B_SIZE S2N_JA4_DIGEST_HEX_CHAR_LIMIT
#define S2N_JA4_C_SIZE S2N_JA4_DIGEST_HEX_CHAR_LIMIT
#define S2N_JA4_SIZE   (S2N_JA4_A_SIZE + 1 + S2N_JA4_B_SIZE + 1 + S2N_JA4_C_SIZE)

#define S2N_JA4_LIST_LIMIT 99

const char s2n_ja4_version_strings[][3] = {
        [S2N_UNKNOWN_PROTOCOL_VERSION] = "00",
        [S2N_TLS13] = "13",
        [S2N_TLS12] = "12",
        [S2N_TLS11] = "11",
        [S2N_TLS10] = "10",
        [S2N_SSLv3] = "s3",
};

DEFINE_POINTER_CLEANUP_FUNC(struct s2n_stuffer *, s2n_stuffer_wipe);

static int s2n_fingerprint_ja4_iana_compare(const void * a, const void * b)
{
    const uint8_t *iana_a = (const uint8_t *) a;
    const uint8_t *iana_b = (const uint8_t *) b;
    if (iana_a[1] != iana_b[1]) {
        return iana_a[1] - iana_b[1];
    }
    return iana_a[0] - iana_b[0];
}

static S2N_RESULT s2n_fingerprint_ja4_iana(struct s2n_fingerprint_hash *hash, uint16_t iana)
{
    char hex[S2N_JA4_HEX_PER_IANA + 1] = { 0 };
    int written = snprintf((char *) hex, sizeof(hex), "%.*x",
            (int) S2N_JA4_HEX_PER_IANA, iana);
    RESULT_ENSURE_EQ(written, S2N_JA4_HEX_PER_IANA);
    RESULT_GUARD(s2n_fingerprint_hash_add_str(hash, hex));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_iana_list(struct s2n_fingerprint_hash *hash,
        uint16_t *iana_list, size_t iana_count)
{
    for (size_t i = 0; i < iana_count; i++) {
        if (i > 0) {
            RESULT_GUARD(s2n_fingerprint_hash_add_char(hash, S2N_JA4_LIST_DIV));
        }
        RESULT_GUARD(s2n_fingerprint_ja4_iana(hash, iana_list[i]));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_digest(struct s2n_fingerprint_hash *hash,
        struct s2n_stuffer *out)
{
    RESULT_GUARD(s2n_fingerprint_hash_flush(hash));

    uint8_t digest_bytes[SHA256_DIGEST_LENGTH] = { 0 };
    RESULT_GUARD_POSIX(s2n_hash_digest(hash->hash, digest_bytes, sizeof(digest_bytes)));
    RESULT_GUARD_POSIX(s2n_hash_reset(hash->hash));

    /* Add an extra char to account for the trailing '\0' */
    char hex[S2N_HEX_PER_BYTE + 1] = { 0 };

    /* Convert the digest to hex and truncate it */
    for (size_t i = 0; i < S2N_JA4_DIGEST_BYTE_LIMIT; i++) {
        int written = snprintf((char *) hex, sizeof(hex), "%.*x",
                S2N_HEX_PER_BYTE, digest_bytes[i]);
        RESULT_ENSURE_EQ(written, S2N_HEX_PER_BYTE);
        RESULT_GUARD_POSIX(s2n_stuffer_write_str(out, hex));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_count(struct s2n_blob *output, uint16_t count)
{
    RESULT_ENSURE_EQ(output->size, S2N_JA4_COUNT_SIZE);
    count = MIN(count, S2N_JA4_COUNT_MAX);

    /* We can't write directly to output because the trailing '\0' requires
     * one extra byte and would overflow output */
    char count_str[S2N_JA4_COUNT_SIZE + 1] = { 0 };
    int written = snprintf(count_str, sizeof(count_str), "%.*u",
            S2N_JA4_COUNT_SIZE, count);
    RESULT_ENSURE_EQ(written, S2N_JA4_COUNT_SIZE);

    RESULT_CHECKED_MEMCPY(output->data, count_str, output->size);
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_version(struct s2n_stuffer *output,
        struct s2n_client_hello *ch)
{
    RESULT_ENSURE_REF(ch);
    uint8_t client_protocol_version = ch->legacy_version;

    s2n_parsed_extension *extension = NULL;
    int result = s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SUPPORTED_VERSIONS,
            &ch->extensions, &extension);
    if (result == S2N_SUCCESS) {
        struct s2n_stuffer supported_versions = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_init_written(&supported_versions, &extension->extension));

        uint8_t actual_protocol_version = S2N_UNKNOWN_PROTOCOL_VERSION;
        RESULT_GUARD_POSIX(s2n_extensions_client_supported_versions_process(&supported_versions,
                UINT8_MAX, &client_protocol_version, &actual_protocol_version));
    }

    const char *version_str = s2n_ja4_version_strings[client_protocol_version];
    if (version_str == NULL) {
        version_str = s2n_ja4_version_strings[S2N_UNKNOWN_PROTOCOL_VERSION];
    }
    RESULT_GUARD_POSIX(s2n_stuffer_write_str(output, version_str));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_client_hello_get_first_alpn(struct s2n_client_hello *ch, struct s2n_blob *first)
{
    s2n_parsed_extension *extension = NULL;
    RESULT_GUARD_POSIX(s2n_client_hello_get_parsed_extension(S2N_EXTENSION_ALPN,
            &ch->extensions, &extension));

    struct s2n_stuffer protocols = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&protocols, &extension->extension));
    RESULT_ENSURE(s2n_result_is_ok(s2n_protocol_preferences_read(&protocols, first)),
            S2N_ERR_BAD_MESSAGE);
    RESULT_ENSURE_GTE(first->size, 2);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_alpn(struct s2n_stuffer *output,
        struct s2n_client_hello *ch)
{
    struct s2n_blob protocol = { 0 };
    if (s2n_result_is_error(s2n_client_hello_get_first_alpn(ch, &protocol))) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_str(output, "00"));
        return S2N_RESULT_OK;
    }

    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, protocol.data[0]));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, protocol.data[protocol.size - 1]));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_sig_algs(struct s2n_fingerprint_hash *hash,
        struct s2n_client_hello *ch)
{
    s2n_parsed_extension *extension = NULL;
    RESULT_GUARD_POSIX(s2n_client_hello_get_parsed_extension(S2N_EXTENSION_SIGNATURE_ALGORITHMS,
            &ch->extensions, &extension));

    struct s2n_stuffer sig_algs = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&sig_algs, &extension->extension));

    while (s2n_stuffer_data_available(&sig_algs)) {
        uint16_t iana = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&sig_algs, &iana));
        if (s2n_is_grease_value(iana)) {
            continue;
        }
        RESULT_GUARD(s2n_fingerprint_ja4_iana(hash, iana));
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_extensions(struct s2n_fingerprint_hash *hash,
        struct s2n_client_hello *ch, struct s2n_stuffer *sort_space, uint16_t *extensions_count)
{
    struct s2n_stuffer extensions = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&extensions, &ch->extensions.raw));

    size_t unlisted_count = 0;

    DEFER_CLEANUP(struct s2n_stuffer *iana_list = sort_space, s2n_stuffer_wipe_pointer);
    while (s2n_stuffer_data_available(&extensions)) {
        uint16_t iana = 0;
        RESULT_GUARD(s2n_fingerprint_parse_extension(&extensions, &iana));
        if (s2n_is_grease_value(iana)) {
            continue;
        }

        /* We consider the server_name and alpn extension when counting
         * extensions, but not when actually listing extensions.
         */
        if (iana == TLS_EXTENSION_SERVER_NAME || iana == S2N_EXTENSION_ALPN) {
            unlisted_count++;
            continue;
        }

        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(iana_list, iana));
    }

    size_t iana_list_size = s2n_stuffer_data_available(iana_list);
    size_t iana_count = iana_list_size / sizeof(uint16_t);
    uint16_t *ianas = s2n_stuffer_raw_read(iana_list, iana_list_size);
    RESULT_GUARD_PTR(ianas);
    qsort(ianas, iana_count, sizeof(uint16_t), s2n_fingerprint_ja4_iana_compare);

    RESULT_GUARD(s2n_fingerprint_ja4_iana_list(hash, ianas, iana_count));
    *extensions_count = iana_count + unlisted_count;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_ciphers(struct s2n_fingerprint_hash *hash,
        struct s2n_client_hello *ch, struct s2n_stuffer *sort_space, uint16_t *ciphers_count)
{
    struct s2n_stuffer cipher_suites = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&cipher_suites, &ch->cipher_suites));

    DEFER_CLEANUP(struct s2n_stuffer *iana_list = sort_space, s2n_stuffer_wipe_pointer);
    while (s2n_stuffer_data_available(&cipher_suites)) {
        uint16_t iana = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&cipher_suites, &iana));
        if (s2n_is_grease_value(iana)) {
            continue;
        }
        RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(iana_list, iana));
    }

    size_t iana_list_size = s2n_stuffer_data_available(iana_list);
    size_t iana_count = iana_list_size / sizeof(uint16_t);
    uint16_t *ianas = s2n_stuffer_raw_read(iana_list, iana_list_size);
    RESULT_GUARD_PTR(ianas);
    qsort(ianas, iana_count, sizeof(uint16_t), s2n_fingerprint_ja4_iana_compare);

    RESULT_GUARD(s2n_fingerprint_ja4_iana_list(hash, ianas, iana_count));
    *ciphers_count = iana_count;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_a(struct s2n_fingerprint *fingerprint,
        struct s2n_stuffer *output, struct s2n_blob *ciphers_count, struct s2n_blob *extensions_count)
{
    /* “q”, "d" or “t”, denotes whether the hello packet is for QUIC, DTLS, or normal TLS. */
    bool is_quic = false;
    RESULT_GUARD_POSIX(s2n_client_hello_has_extension(fingerprint->client_hello,
            TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS, &is_quic));
    if (is_quic) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, 'q'));
    } else {
        RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, 't'));
    }

    /* version, including supported_versions */
    RESULT_GUARD(s2n_fingerprint_ja4_version(output, fingerprint->client_hello));

    /* If the SNI extension (0x0000) exists, then the destination of the connection
     * is a domain, or “d” in the fingerprint. If the SNI does not exist, then the
     * destination is an IP address, or “i”.
     */
    bool has_sni = false;
    RESULT_GUARD_POSIX(s2n_client_hello_has_extension(fingerprint->client_hello,
            TLS_EXTENSION_SERVER_NAME, &has_sni));
    if (has_sni) {
        RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, 'd'));
    } else {
        RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, 'i'));
    }

    uint8_t *ciphers_count_mem = s2n_stuffer_raw_write(output, S2N_JA4_HEX_PER_IANA);
    RESULT_GUARD_PTR(ciphers_count_mem);
    RESULT_GUARD_POSIX(s2n_blob_init(ciphers_count, ciphers_count_mem, S2N_JA4_HEX_PER_IANA));

    uint8_t *extensions_count_mem = s2n_stuffer_raw_write(output, S2N_JA4_HEX_PER_IANA);
    RESULT_GUARD_PTR(extensions_count_mem);
    RESULT_GUARD_POSIX(s2n_blob_init(extensions_count, extensions_count_mem, S2N_JA4_HEX_PER_IANA));

    /* The first and last characters of the ALPN first value.
     * If there are no ALPN values or no ALPN extension then we print “00” as
     * the value in the fingerprint.
     */
    RESULT_GUARD(s2n_fingerprint_ja4_alpn(output, fingerprint->client_hello));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_b(struct s2n_fingerprint *fingerprint,
        struct s2n_stuffer *output, struct s2n_blob *ciphers_count)
{
    struct s2n_fingerprint_hash hash = { 0 };
    RESULT_GUARD(s2n_fingerprint_hash_init(&hash, &fingerprint->hash, S2N_HASH_SHA256));

    uint16_t ciphers_count_value = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_ciphers(&hash, fingerprint->client_hello,
            &fingerprint->workspace, &ciphers_count_value));

    RESULT_GUARD(s2n_fingerprint_ja4_digest(&hash, output));
    RESULT_GUARD(s2n_fingerprint_ja4_count(ciphers_count, ciphers_count_value));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4_c(struct s2n_fingerprint *fingerprint,
        struct s2n_stuffer *output, struct s2n_blob *extensions_count)
{
    struct s2n_fingerprint_hash hash = { 0 };
    RESULT_GUARD(s2n_fingerprint_hash_init(&hash, &fingerprint->hash, S2N_HASH_SHA256));

    uint16_t extensions_count_value = 0;
    RESULT_GUARD(s2n_fingerprint_ja4_extensions(&hash, fingerprint->client_hello,
            &fingerprint->workspace, &extensions_count_value));
    RESULT_GUARD(s2n_fingerprint_hash_add_char(&hash, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_sig_algs(&hash, fingerprint->client_hello));

    RESULT_GUARD(s2n_fingerprint_ja4_digest(&hash, output));
    RESULT_GUARD(s2n_fingerprint_ja4_count(extensions_count, extensions_count_value));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_fingerprint_ja4(struct s2n_fingerprint *fingerprint,
        struct s2n_stuffer *output)
{
    RESULT_ENSURE_REF(fingerprint);

    struct s2n_blob ciphers_count = { 0 };
    struct s2n_blob extensions_count = { 0 };
    RESULT_GUARD(s2n_fingerprint_ja4_a(fingerprint, output,
            &ciphers_count, &extensions_count));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_b(fingerprint, output, &ciphers_count));
    RESULT_GUARD_POSIX(s2n_stuffer_write_char(output, S2N_JA4_PART_DIV));
    RESULT_GUARD(s2n_fingerprint_ja4_c(fingerprint, output, &extensions_count));

    return S2N_RESULT_OK;
}

struct s2n_fingerprint_method ja4_fingerprint = {
    .hash_size = S2N_JA4_SIZE,
    .hash = s2n_fingerprint_ja4,
};
