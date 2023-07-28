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

#include "api/s2n.h"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_x509_validator.h"

#define S2N_TEST_CERT_CHAIN S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN

struct s2n_test_certificate_cb_call_info {
    struct s2n_connection *conn;
    struct s2n_peer_certificate peer_certificate;
};

struct s2n_test_certificate_cb_call_list {
    struct s2n_test_certificate_cb_call_info calls[10];
    size_t call_count;
};

static int s2n_test_certificate_cb(struct s2n_connection *conn, void *context,
        struct s2n_peer_certificate *peer_certificate)
{
    struct s2n_test_certificate_cb_call_list *call_list =
            (struct s2n_test_certificate_cb_call_list*) context;
    POSIX_ENSURE_REF(call_list);
    POSIX_ENSURE_LT(call_list->call_count, s2n_array_len(call_list->calls));

    struct s2n_test_certificate_cb_call_info *call = &call_list->calls[call_list->call_count];
    call->conn = conn;
    call->peer_certificate = *peer_certificate;
    call_list->call_count++;

    return S2N_SUCCESS;
}

static uint8_t s2n_test_verify_host(const char *host_name, size_t host_name_len, void *data)
{
    return 1;
}

static S2N_RESULT s2n_assert_basic_call_info(struct s2n_test_certificate_cb_call_list *call_list,
        struct s2n_connection *conn, struct s2n_blob *raw)
{
    for (size_t i = 0; i < call_list->call_count; i++) {
        struct s2n_test_certificate_cb_call_info *call = &call_list->calls[i];
        RESULT_ENSURE_EQ(conn, call->conn);
        RESULT_ENSURE_EQ(conn, call->peer_certificate.conn);
        RESULT_ENSURE_EQ(raw->size, call->peer_certificate.raw.size);
        RESULT_ENSURE_EQ(memcmp(raw->data, call->peer_certificate.raw.data,
                call->peer_certificate.raw.size), 0);
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_validate_cert(struct s2n_config *config,
        struct s2n_x509_trust_store *trust_store, struct s2n_blob *raw_cert,
        struct s2n_connection **new_conn)
{
    *new_conn = s2n_connection_new(S2N_CLIENT);

    struct s2n_connection *conn = *new_conn;
    RESULT_ENSURE_REF(conn);
    RESULT_GUARD_POSIX(s2n_connection_set_verify_host_callback(conn, s2n_test_verify_host, NULL));
    RESULT_GUARD_POSIX(s2n_connection_set_config(conn, config));

    struct s2n_x509_validator *validator = &conn->x509_validator;
    RESULT_GUARD_POSIX(s2n_x509_validator_init(validator, trust_store, false));

    DEFER_CLEANUP(struct s2n_pkey public_key_out = { 0 }, s2n_pkey_free);
    RESULT_GUARD_POSIX(s2n_pkey_zero_init(&public_key_out));
    s2n_pkey_type pkey_type = S2N_PKEY_TYPE_UNKNOWN;
    RESULT_GUARD(s2n_x509_validator_validate_cert_chain(validator, conn,
            raw_cert, &pkey_type, &public_key_out));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_x509_trust_store empty_trust_store = { 0 }, s2n_x509_trust_store_wipe);
    s2n_x509_trust_store_init_empty(&empty_trust_store);

    DEFER_CLEANUP(struct s2n_x509_trust_store trust_store = { 0 }, s2n_x509_trust_store_wipe);
    s2n_x509_trust_store_init_empty(&trust_store);
    EXPECT_SUCCESS(s2n_x509_trust_store_from_ca_file(&trust_store, S2N_TEST_CERT_CHAIN, NULL));

    DEFER_CLEANUP(struct s2n_blob raw_cert_chain = { 0 }, s2n_free);
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_stuffer cert_chain_stuffer = { 0 }, s2n_stuffer_free);
        EXPECT_OK(s2n_test_cert_chain_data_from_pem(conn, S2N_TEST_CERT_CHAIN, &cert_chain_stuffer));
        uint32_t chain_len = s2n_stuffer_data_available(&cert_chain_stuffer);

        EXPECT_SUCCESS(s2n_realloc(&raw_cert_chain, chain_len));
        EXPECT_SUCCESS(s2n_stuffer_read(&cert_chain_stuffer, &raw_cert_chain));
    }

    /* Test certificate callback triggered for successful validation */
    {
        struct s2n_test_certificate_cb_call_list call_list = { 0 };
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_certificate_cb(config, s2n_test_certificate_cb, (void*) &call_list));

        DEFER_CLEANUP(struct s2n_connection *conn = NULL, s2n_connection_ptr_free);
        EXPECT_OK(s2n_test_validate_cert(config, &trust_store, &raw_cert_chain, &conn));

        EXPECT_EQUAL(call_list.call_count, 2);
        EXPECT_OK(s2n_assert_basic_call_info(&call_list, conn, &raw_cert_chain));
        EXPECT_EQUAL(call_list.calls[0].peer_certificate.status, S2N_CERT_CHAIN_RECEIVED);
        EXPECT_EQUAL(call_list.calls[1].peer_certificate.status, S2N_CERT_CHAIN_VALIDATED);
    };

    /* Test certificate callback can modify validation */
    {
    };

    /* Test certificate callback triggered for failed validation */
    {
        struct s2n_test_certificate_cb_call_list call_list = { 0 };
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_set_certificate_cb(config, s2n_test_certificate_cb, (void*) &call_list));

        DEFER_CLEANUP(struct s2n_connection *conn = NULL, s2n_connection_ptr_free);
        EXPECT_ERROR_WITH_ERRNO(s2n_test_validate_cert(config, &empty_trust_store, &raw_cert_chain, &conn),
                S2N_ERR_CERT_UNTRUSTED);

        EXPECT_EQUAL(call_list.call_count, 2);
        EXPECT_OK(s2n_assert_basic_call_info(&call_list, conn, &raw_cert_chain));
        EXPECT_EQUAL(call_list.calls[0].peer_certificate.status, S2N_CERT_CHAIN_RECEIVED);
        EXPECT_EQUAL(call_list.calls[1].peer_certificate.status, S2N_CERT_CHAIN_REJECTED);
    };

    /* Test certificate callback triggered when validation skipped */
    {

    };

    /* Test certificate callback with async CRL callback */
    {
    };

    END_TEST();
}
