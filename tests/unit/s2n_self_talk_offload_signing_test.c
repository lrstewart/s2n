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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#define S2N_TEST_CERT_MEM 2048

struct s2n_async_pkey_op *pkey_op = NULL;
struct s2n_connection *pkey_op_conn = NULL;
static int s2n_test_async_pkey_cb(struct s2n_connection *conn, struct s2n_async_pkey_op *op)
{
    pkey_op = op;
    pkey_op_conn = conn;
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_async_pkey_sign(struct s2n_connection *conn, struct s2n_cert_chain_and_key *complete_chain)
{
    RESULT_ENSURE_REF(pkey_op);
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(complete_chain);

    /* Get input */
    uint32_t input_len = 0;
    DEFER_CLEANUP(struct s2n_blob input = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_input_size(pkey_op, &input_len));
    RESULT_GUARD_POSIX(s2n_realloc(&input, input_len));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_input(pkey_op, input.data, input.size));

    /* Setup output */
    DEFER_CLEANUP(struct s2n_blob output = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_realloc(&output, input_len * 3));

    /* Verify correct op type */
    s2n_async_pkey_op_type op_type = 0;
    RESULT_GUARD_POSIX(s2n_async_pkey_op_get_op_type(pkey_op, &op_type));
    RESULT_ENSURE_EQ(op_type, S2N_ASYNC_SIGN);

    /* Sign */
    RESULT_ENSURE_REF(complete_chain->private_key);
    EC_KEY *private_key = complete_chain->private_key->key.ecdsa_key.ec_key;
    RESULT_GUARD_OSSL(ECDSA_sign(0, input.data, input.size, output.data, &output.size, private_key), S2N_ERR_SIGN);

    /* Complete async_op */
    RESULT_GUARD_POSIX(s2n_async_pkey_op_set_output(pkey_op, output.data, output.size));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_apply(pkey_op, conn));
    RESULT_GUARD_POSIX(s2n_async_pkey_op_free(pkey_op));
    pkey_op = NULL;
    pkey_op_conn = NULL;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_do_test_handshake(struct s2n_config *config,
        struct s2n_cert_chain_and_key *cert_only_chain, struct s2n_cert_chain_and_key *complete_chain)
{
    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    RESULT_ENSURE_REF(client_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, config));

    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    RESULT_ENSURE_REF(server_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, config));

    struct s2n_test_io_pair io_pair = { 0 };
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&io_pair));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(client_conn, &io_pair));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(server_conn, &io_pair));

    while (s2n_negotiate_test_server_and_client(server_conn, client_conn) != S2N_SUCCESS) {
        RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_ASYNC_BLOCKED);
        RESULT_GUARD(s2n_async_pkey_sign(pkey_op_conn, complete_chain));
    }

    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    RESULT_GUARD_POSIX(s2n_connection_free(server_conn));
    RESULT_GUARD_POSIX(s2n_connection_free(client_conn));
    RESULT_GUARD_POSIX(s2n_io_pair_close(&io_pair));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    uint32_t pem_len = 0;
    uint8_t pem[S2N_TEST_CERT_MEM] = { 0 };

    /* Create complete cert chains.
     * We need these to do the actual signing / decrypting, but they are not
     * added to any configs. */
    struct s2n_cert_chain_and_key *ecdsa_complete_chain = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_complete_chain,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    /* Create cert chains with only public certificates.
     * These are passed to the connections. */
    struct s2n_cert_chain_and_key *ecdsa_cert_only_chain = s2n_cert_chain_and_key_new();
    EXPECT_NOT_NULL(ecdsa_cert_only_chain);
    EXPECT_SUCCESS(s2n_read_test_pem_and_len(S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, pem, &pem_len, sizeof(pem)));
    EXPECT_SUCCESS(s2n_cert_chain_load_pem_bytes(ecdsa_cert_only_chain, pem, pem_len));

    /* Basic config */
    struct s2n_config *config = s2n_config_new();
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, ecdsa_cert_only_chain));
    EXPECT_SUCCESS(s2n_config_set_async_pkey_callback(config, s2n_test_async_pkey_cb));

    /* Test: TLS1.2 + ECDSA */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
    EXPECT_OK(s2n_do_test_handshake(config, ecdsa_cert_only_chain, ecdsa_complete_chain));

    /* Test: TLS1.3 + ECDSA */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_OK(s2n_do_test_handshake(config, ecdsa_cert_only_chain, ecdsa_complete_chain));

    /* Enable client auth */
    EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, S2N_CERT_AUTH_REQUIRED));

    /* Test: TLS1.2 + ECDSA + client auth */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
    EXPECT_OK(s2n_do_test_handshake(config, ecdsa_cert_only_chain, ecdsa_complete_chain));

    /* Test: TLS1.3 + ECDSA + client auth */
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_OK(s2n_do_test_handshake(config, ecdsa_cert_only_chain, ecdsa_complete_chain));

    EXPECT_SUCCESS(s2n_config_free(config));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_complete_chain));
    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(ecdsa_cert_only_chain));

    END_TEST();
}
