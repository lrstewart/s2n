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

#include "tls/s2n_signature_algorithms.h"

#include "crypto/s2n_fips.h"
#include "crypto/s2n_rsa_pss.h"
#include "crypto/s2n_rsa_signing.h"
#include "error/s2n_errno.h"
#include "tls/s2n_auth_selection.h"
#include "tls/s2n_cipher_suites.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_kex.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_signature_scheme.h"
#include "utils/s2n_safety.h"

static S2N_RESULT s2n_signature_scheme_validate_for_send(struct s2n_connection *conn,
        const struct s2n_signature_scheme *scheme)
{
    RESULT_ENSURE_REF(conn);

    /* We don't know what protocol version we will eventually negotiate,
     * but we know that it won't be any higher. */
    RESULT_ENSURE_GTE(conn->actual_protocol_version, scheme->minimum_protocol_version);

    /* QUIC only supports TLS1.3 */
    if (s2n_connection_is_quic_enabled(conn) && scheme->maximum_protocol_version) {
        RESULT_ENSURE_GTE(scheme->maximum_protocol_version, S2N_TLS13);
    }

    if (!s2n_is_rsa_pss_signing_supported()) {
        RESULT_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_RSAE);
    }

    if (!s2n_is_rsa_pss_certs_supported()) {
        RESULT_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_signature_scheme_validate_for_recv(struct s2n_connection *conn,
        const struct s2n_signature_scheme *scheme)
{
    RESULT_ENSURE_REF(scheme);
    RESULT_ENSURE_REF(conn);

    RESULT_GUARD(s2n_signature_scheme_validate_for_send(conn, scheme));

    if (scheme->maximum_protocol_version != S2N_UNKNOWN_PROTOCOL_VERSION) {
        RESULT_ENSURE_LTE(conn->actual_protocol_version, scheme->maximum_protocol_version);
    }

    RESULT_ENSURE_NE(conn->actual_protocol_version, S2N_UNKNOWN_PROTOCOL_VERSION);
    if (conn->actual_protocol_version >= S2N_TLS13) {
        RESULT_ENSURE_NE(scheme->hash_alg, S2N_HASH_SHA1);
        RESULT_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA);
    } else {
        RESULT_ENSURE_NE(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_get_legacy_default_signature_scheme(struct s2n_connection *conn,
        s2n_mode signer, const struct s2n_signature_scheme **default_sig_scheme)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(default_sig_scheme);

    s2n_authentication_method auth_method = 0;
    if (signer == S2N_CLIENT) {
        RESULT_GUARD_POSIX(s2n_get_auth_method_for_cert_type(
                conn->handshake_params.client_cert_pkey_type, &auth_method));
    } else {
        RESULT_ENSURE_REF(conn->secure);
        RESULT_ENSURE_REF(conn->secure->cipher_suite);
        auth_method = conn->secure->cipher_suite->auth_method;
    }

    if (auth_method == S2N_AUTHENTICATION_ECDSA) {
        *default_sig_scheme = &s2n_ecdsa_sha1;
    } else {
        *default_sig_scheme = &s2n_rsa_pkcs1_md5_sha1;
    }
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_signature_algorithm_recv(struct s2n_connection *conn, struct s2n_stuffer *in)
{
    RESULT_ENSURE_REF(conn);

    const struct s2n_signature_scheme **chosen_sig_scheme = &conn->handshake_params.server_cert_sig_scheme;
    if (conn->mode == S2N_SERVER) {
        chosen_sig_scheme = &conn->handshake_params.client_cert_sig_scheme;
    }

    if (conn->actual_protocol_version < S2N_TLS12) {
        const struct s2n_signature_scheme *legacy_scheme = NULL;
        RESULT_GUARD(s2n_get_legacy_default_signature_scheme(conn, S2N_PEER_MODE(conn->mode),
                &legacy_scheme));
        *chosen_sig_scheme = legacy_scheme;
        return S2N_RESULT_OK;
    }

    uint16_t iana_value = 0;
    RESULT_ENSURE(s2n_stuffer_read_uint16(in, &iana_value) == S2N_SUCCESS,
            S2N_ERR_BAD_MESSAGE);

    const struct s2n_signature_preferences *signature_preferences = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    RESULT_ENSURE_REF(signature_preferences);

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (candidate->iana_value != iana_value) {
            continue;
        }

        if (s2n_result_is_error(s2n_signature_scheme_validate_for_recv(conn, candidate))) {
            continue;
        }

        *chosen_sig_scheme = candidate;
        return S2N_RESULT_OK;
    }

    RESULT_BAIL(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

S2N_RESULT s2n_signature_algorithms_supported_list_send(struct s2n_connection *conn, struct s2n_stuffer *out)
{
    const struct s2n_signature_preferences *signature_preferences = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    RESULT_ENSURE_REF(signature_preferences);

    struct s2n_stuffer_reservation size = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_reserve_uint16(out, &size));

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *const scheme = signature_preferences->signature_schemes[i];
        RESULT_ENSURE_REF(scheme);
        if (s2n_result_is_ok(s2n_signature_scheme_validate_for_send(conn, scheme))) {
            RESULT_GUARD_POSIX(s2n_stuffer_write_uint16(out, scheme->iana_value));
        }
    }
    RESULT_GUARD_POSIX(s2n_stuffer_write_vector_size(&size));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_validate_signature_algorithms_contain_iana(
        struct s2n_blob *peer_list, uint16_t our_iana)
{
    struct s2n_stuffer list = { 0 };
    RESULT_GUARD_POSIX(s2n_stuffer_init_written(&list, peer_list));
    while(s2n_stuffer_data_available(&list)) {
        uint16_t iana = 0;
        RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(&list, &iana));
        if (iana == our_iana) {
            return S2N_RESULT_OK;
        }
    }
    RESULT_BAIL(S2N_ERR_INVALID_SIGNATURE_SCHEME);
}

S2N_RESULT s2n_signature_algorithms_supported_list_process(struct s2n_connection *conn,
        struct s2n_blob *peer_list)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(peer_list);
    RESULT_ENSURE_REF(conn->secure);
    struct s2n_cipher_suite *cipher_suite = conn->secure->cipher_suite;
    RESULT_ENSURE_REF(cipher_suite);

    const struct s2n_signature_scheme **chosen_sig_scheme = &conn->handshake_params.server_cert_sig_scheme;
    if (conn->mode == S2N_CLIENT) {
        chosen_sig_scheme = &conn->handshake_params.client_cert_sig_scheme;
    }

    if (conn->actual_protocol_version < S2N_TLS12) {
        const struct s2n_signature_scheme *legacy_scheme = NULL;
        RESULT_GUARD(s2n_get_legacy_default_signature_scheme(conn, conn->mode,
                &legacy_scheme));
        *chosen_sig_scheme = legacy_scheme;
        return S2N_RESULT_OK;
    }

    const struct s2n_signature_preferences *signature_preferences = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_signature_preferences(conn, &signature_preferences));
    RESULT_ENSURE_REF(signature_preferences);

    const struct s2n_signature_scheme *fallback_candidate = NULL;

    for (size_t i = 0; i < signature_preferences->count; i++) {
        const struct s2n_signature_scheme *candidate = signature_preferences->signature_schemes[i];

        if (s2n_result_is_error(s2n_signature_scheme_validate_for_recv(conn, candidate))) {
            continue;
        }

        if (s2n_is_sig_scheme_valid_for_auth(conn, candidate) != S2N_SUCCESS) {
            continue;
        }

        bool is_peer_supported = s2n_result_is_ok(s2n_validate_signature_algorithms_contain_iana(
                peer_list, candidate->iana_value));
        bool is_default = (candidate == &s2n_ecdsa_sha1 || candidate == &s2n_rsa_pkcs1_sha1);

        if (is_peer_supported) {
            *chosen_sig_scheme = candidate;
            return S2N_RESULT_OK;
        }

        if (is_default) {
            fallback_candidate = candidate;
        } else if (fallback_candidate == NULL) {
            fallback_candidate = candidate;
        }
    }

    if (fallback_candidate) {
        *chosen_sig_scheme = fallback_candidate;
    } else {
        RESULT_BAIL(S2N_ERR_INVALID_SIGNATURE_SCHEME);
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_signature_algorithms_supported_list_parse(struct s2n_connection *conn,
        struct s2n_stuffer *in, struct s2n_blob *peer_list)
{
    uint16_t peer_list_size = 0;
    RESULT_GUARD_POSIX(s2n_stuffer_read_uint16(in, &peer_list_size));

    uint8_t *peer_list_data = s2n_stuffer_raw_read(in, peer_list_size);
    RESULT_ENSURE_REF(peer_list_data);

    RESULT_GUARD_POSIX(s2n_blob_init(peer_list, peer_list_data, peer_list_size));
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_signature_algorithms_supported_list_recv(struct s2n_connection *conn,
        struct s2n_stuffer *in)
{
    struct s2n_blob peer_list = { 0 };
    if (s2n_result_is_error(s2n_signature_algorithms_supported_list_parse(conn, in, &peer_list))) {
        peer_list = (struct s2n_blob){ 0 };
    }
    RESULT_GUARD(s2n_signature_algorithms_supported_list_process(conn, &peer_list));
    return S2N_RESULT_OK;
}
