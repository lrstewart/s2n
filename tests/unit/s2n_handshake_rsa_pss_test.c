/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <s2n.h>
#include "s2n_test.h"

#include "testlib/s2n_testlib.h"

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

#include <s2n.h>

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_cipher_preferences.h"
#include "tls/s2n_tls13.h"
#include "tls/s2n_tls.h"
#include "stuffer/s2n_stuffer.h"
#include "utils/s2n_safety.h"

#include "tls/s2n_handshake_io.c"

int s2n_test_handshake_step(int (*write_method) (struct s2n_connection * conn), struct s2n_connection *writer,
        int (*read_method) (struct s2n_connection * conn), struct s2n_connection *reader)
{
    EXPECT_SUCCESS(write_method(writer));

    EXPECT_SUCCESS(s2n_stuffer_copy(&writer->handshake.io, &reader->handshake.io,
            s2n_stuffer_data_available(&writer->handshake.io)));

    EXPECT_SUCCESS(read_method(reader));

    EXPECT_SUCCESS(s2n_stuffer_wipe(&writer->handshake.io));
    EXPECT_SUCCESS(s2n_stuffer_wipe(&reader->handshake.io));

    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

#if !RSA_PSS_SUPPORTED
    END_TEST();
#endif

    struct s2n_signature_preferences s2n_test_sig_prefs = { .count = 1, .signature_schemes = NULL };
    EXPECT_NOT_EQUAL(s2n_test_sig_prefs.count, 0);

    /*
     * Test: RSA_PSS cert with RSA_PSS signatures.
     * This test self-talks by calling handlers directly, without going through s2n_handshake_io.
     * This is to work around https://github.com/awslabs/s2n/issues/1545
     */
    {
        s2n_enable_tls13();

        struct s2n_config *server_config, *client_config;

        struct s2n_cert_chain_and_key *chain_and_key;
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

        EXPECT_NOT_NULL(server_config = s2n_config_new());
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
        server_config->signature_preferences = &s2n_test_sig_prefs;

        EXPECT_NOT_NULL(client_config = s2n_config_new());
        client_config->signature_preferences = &s2n_test_sig_prefs;
        client_config->client_cert_auth_type = S2N_CERT_AUTH_NONE;
        client_config->check_ocsp = 0;
        client_config->disable_x509_validation = 1;

        for(int i = 0; i < s2n_signature_preferences_20140601.count; i++) {
            if (s2n_signature_preferences_20140601.signature_schemes[i]->sig_alg != S2N_SIGNATURE_RSA_PSS_PSS) {
                continue;
            }
            s2n_test_sig_prefs.signature_schemes = &s2n_signature_preferences_20140601.signature_schemes[i];

            struct s2n_connection *server_conn, *client_conn;
            EXPECT_NOT_NULL(server_conn = s2n_connection_new(S2N_SERVER));
            EXPECT_NOT_NULL(client_conn = s2n_connection_new(S2N_CLIENT));
            EXPECT_SUCCESS(s2n_connection_set_config(server_conn, server_config));
            EXPECT_SUCCESS(s2n_connection_set_config(client_conn, client_config));

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_client_hello_send, client_conn,
                    s2n_client_hello_recv, server_conn));

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_server_hello_send, server_conn,
                    s2n_server_hello_recv, client_conn));

            EXPECT_EQUAL(server_conn->handshake_params.our_chain_and_key, chain_and_key);

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_encrypted_extensions_send, server_conn,
                    s2n_encrypted_extensions_recv, client_conn));

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_server_cert_send, server_conn,
                    s2n_server_cert_recv, client_conn));

            EXPECT_SUCCESS(client_conn->secure.server_public_key.match(
                    &client_conn->secure.server_public_key,
                    server_conn->handshake_params.our_chain_and_key->private_key));

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_server_cert_verify_send, server_conn,
                    s2n_server_cert_verify_recv, client_conn));

            EXPECT_EQUAL(client_conn->secure.conn_sig_scheme.iana_value,
                    server_conn->secure.conn_sig_scheme.iana_value);
            EXPECT_EQUAL(client_conn->secure.conn_sig_scheme.iana_value,
                    s2n_signature_preferences_20140601.signature_schemes[i]->iana_value);

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_tls13_server_finished_send, server_conn,
                    s2n_tls13_server_finished_recv, client_conn));

            EXPECT_SUCCESS(s2n_test_handshake_step(s2n_tls13_client_finished_send, server_conn,
                    s2n_tls13_client_finished_recv, client_conn));

            /* Clean up */

            EXPECT_SUCCESS(s2n_connection_free(server_conn));
            EXPECT_SUCCESS(s2n_connection_free(client_conn));
        }

        EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));
        EXPECT_SUCCESS(s2n_config_free(server_config));
        EXPECT_SUCCESS(s2n_config_free(client_config));

        s2n_disable_tls13();
    }

    END_TEST();
    return 0;
}

