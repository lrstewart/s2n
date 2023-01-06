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

#include "tls/s2n_shutdown.c"

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_alerts.h"

#define ALERT_LEN (sizeof(uint16_t))

static S2N_RESULT s2n_test_shutdown_server_and_client(struct s2n_connection *server_conn,
        struct s2n_connection *client_conn, s2n_mode requester)
{
    struct s2n_connection *request = server_conn;
    struct s2n_connection *response = client_conn;
    if (requester == S2N_CLIENT) {
        request = client_conn;
        response = server_conn;
    }

    /* The first shutdown attempt blocks on the peer's close_notify */
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    RESULT_ENSURE_NE(s2n_shutdown(request, &blocked), S2N_SUCCESS);
    RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_IO_BLOCKED);
    RESULT_ENSURE_EQ(blocked, S2N_BLOCKED_ON_READ);

    /* The next shutdown attempts should succeed */
    RESULT_GUARD_POSIX(s2n_shutdown(response, &blocked));
    RESULT_GUARD_POSIX(s2n_shutdown(request, &blocked));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const s2n_mode modes[] = { S2N_CLIENT, S2N_SERVER };

    const uint8_t close_notify_alert[] = {
        2,
        0,
    };

    const uint8_t alert_record_header[] = {
        /* record type */
        TLS_ALERT,
        /* protocol version */
        S2N_TLS12 / 10,
        S2N_TLS12 % 10,
        /* length */
        0,
        S2N_ALERT_LENGTH,
    };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default"));

    /* Test s2n_shutdown */
    {
        /* Await close_notify if close_notify_received is not set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer input;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            struct s2n_stuffer output;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            s2n_blocked_status blocked;
            EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
            EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

            /* Verify state after shutdown attempt */
            EXPECT_FALSE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        };

        /* Do not await close_notify if close_notify_received is set */
        {
            struct s2n_connection *conn;
            EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

            struct s2n_stuffer input;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
            struct s2n_stuffer output;
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
            EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

            /* Verify state prior to alert */
            EXPECT_FALSE(conn->close_notify_received);

            /* Write and process the alert */
            EXPECT_SUCCESS(s2n_stuffer_write_bytes(&conn->in, close_notify_alert, sizeof(close_notify_alert)));
            EXPECT_SUCCESS(s2n_process_alert_fragment(conn));

            /* Verify state after alert */
            EXPECT_TRUE(conn->close_notify_received);

            s2n_blocked_status blocked;
            EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
            EXPECT_EQUAL(blocked, S2N_NOT_BLOCKED);

            /* Verify state after shutdown attempt */
            EXPECT_TRUE(conn->close_notify_received);

            EXPECT_SUCCESS(s2n_connection_free(conn));
            EXPECT_SUCCESS(s2n_stuffer_free(&input));
            EXPECT_SUCCESS(s2n_stuffer_free(&output));
        };
    };

    /* Test that s2n_shutdown ignores data received after a close_notify
     *
     *= https://www.rfc-editor.org/rfc/rfc5246#section-7.2.1
     *= type=test
     *# Any data received after a closure alert is ignored.
     *
     *= https://www.rfc-editor.org/rfc/rfc8446#section-6.1
     *= type=test
     *# This does not have any effect on its read side of the connection.
     *# Note that this is a change from versions of TLS prior to TLS 1.3 in
     *# which implementations were required to react to a "close_notify" by
     *# discarding pending writes and sending an immediate "close_notify"
     *# alert of their own.  That previous requirement could cause truncation
     *# in the read side.
     */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);

        DEFER_CLEANUP(struct s2n_stuffer input = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&input, 0));
        DEFER_CLEANUP(struct s2n_stuffer output = { 0 }, s2n_stuffer_free);
        EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&output, 0));
        EXPECT_SUCCESS(s2n_connection_set_io_stuffers(&input, &output, conn));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Receive a non-alert record */
        uint8_t record_bytes[] = {
            /* record type */
            TLS_HANDSHAKE,
            /* protocol version */
            S2N_TLS12 / 10,
            S2N_TLS12 % 10,
            /* length */
            0,
            1,
            /* data */
            'x'
        };
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, record_bytes, sizeof(record_bytes)));
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* Receive the response close_notify */
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, alert_record_header, sizeof(alert_record_header)));
        EXPECT_SUCCESS(s2n_stuffer_write_bytes(&input, close_notify_alert, sizeof(close_notify_alert)));
        EXPECT_SUCCESS(s2n_shutdown(conn, &blocked));
    };

    /* Test shutdown with aggressive socket close */
    {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        struct s2n_test_io_pair io_pair = { 0 };
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        /* The client's first shutdown attempt blocks on the server's close_notify */
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_shutdown(client_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);

        /* The server's next shutdown succeeds.
         * From the server's perspective the connection is now gracefully shutdown and
         * the socket can be closed.
         */
        EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Even though the socket is now closed, we should be able to finish
         * shutting down the client connection too.
         */
        EXPECT_SUCCESS(s2n_shutdown(client_conn, &blocked));
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));
    };

    /* Functional Test: s2n_shutdown before the ServerHello message */
    for (size_t i = 0; i < s2n_array_len(modes); i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate(client_conn, &blocked), S2N_ERR_IO_BLOCKED);
        EXPECT_EQUAL(blocked, S2N_BLOCKED_ON_READ);
        EXPECT_OK(s2n_test_shutdown_server_and_client(server_conn, client_conn, modes[i]));

        /* Records not encrypted yet */
        EXPECT_EQUAL(server_conn->server, server_conn->initial);
        EXPECT_EQUAL(client_conn->client, client_conn->initial);

        /* Successfully closed */
        EXPECT_TRUE(server_conn->closed);
        EXPECT_TRUE(client_conn->closed);
    };

    /* Functional Test: s2n_shutdown after the handshake */
    for (size_t i = 0; i < s2n_array_len(modes); i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_OK(s2n_test_shutdown_server_and_client(server_conn, client_conn, modes[i]));

        /* Records secure / encrypted */
        EXPECT_EQUAL(server_conn->server, server_conn->secure);
        EXPECT_EQUAL(client_conn->client, client_conn->secure);

        /* Successfully closed */
        EXPECT_TRUE(server_conn->closed);
        EXPECT_TRUE(client_conn->closed);
    };

    /* Functional Test: s2n_shutdown with application data */
    for (size_t i = 0; i < s2n_array_len(modes); i++) {
        DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));

        DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client_conn);
        EXPECT_SUCCESS(s2n_connection_set_config(client_conn, config));

        DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
        EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));
        EXPECT_SUCCESS(s2n_connections_set_io_pair(client_conn, server_conn, &io_pair));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));

        /* Both the client and server should send application data, but not read any.
         * This leaves unread application data for both to handle.
         */
        uint8_t data[] = "hello world";
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        EXPECT_EQUAL(s2n_send(server_conn, data, sizeof(data), &blocked), sizeof(data));
        EXPECT_EQUAL(s2n_send(client_conn, data, sizeof(data), &blocked), sizeof(data));

        /* Successfully shutdown, with unread data ignored */
        EXPECT_OK(s2n_test_shutdown_server_and_client(server_conn, client_conn, modes[i]));
        EXPECT_TRUE(server_conn->closed);
        EXPECT_TRUE(client_conn->closed);

        /* Future attempts to write fail */
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(server_conn, data, sizeof(data), &blocked), S2N_ERR_CLOSED);
        EXPECT_FAILURE_WITH_ERRNO(s2n_send(client_conn, data, sizeof(data), &blocked), S2N_ERR_CLOSED);

        /* Future attempts to read indicate end of stream */
        EXPECT_EQUAL(s2n_recv(server_conn, data, sizeof(data), &blocked), 0);
        EXPECT_EQUAL(s2n_recv(client_conn, data, sizeof(data), &blocked), 0);
    };

    END_TEST();
}
