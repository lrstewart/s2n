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

#include <sys/param.h>
#include <sys/socket.h>

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"

#include "api/unstable/renegotiate.h"
#include "error/s2n_errno.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_post_handshake.h"
#include "tls/s2n_tls.h"
#include "tls/s2n_tls13_handshake.h"
#include "utils/s2n_safety.h"

/* Required to hack the memory callbacks */
#include "utils/s2n_mem.c"

#define S2N_TEST_MESSAGE_COUNT 5

bool s2n_post_handshake_is_known(uint8_t message_type);
int s2n_key_update_write(struct s2n_blob *out);

int s2n_test_error_mem_free_cb(void *ptr, uint32_t size)
{
    return S2N_FAILURE;
}

int s2n_ticket_count_cb(struct s2n_connection *conn, void *ctx, struct s2n_session_ticket *ticket)
{
    uint8_t *count = (uint8_t *) ctx;
    (*count)++;
    return S2N_SUCCESS;
}

int s2n_hello_request_cb(struct s2n_connection *conn, void *ctx, s2n_renegotiate_response *response)
{
    uint8_t *count = (uint8_t *) ctx;
    (*count)++;
    *response = S2N_RENEGOTIATE_IGNORE;
    return S2N_SUCCESS;
}

S2N_RESULT s2n_test_enable_tickets(struct s2n_config *config)
{
    RESULT_ENSURE_REF(config);

    uint8_t ticket_key_name[16] = "key name";
    uint8_t ticket_key[] = "key data";

    uint64_t current_time = 0;
    RESULT_GUARD_POSIX(config->wall_clock(config->sys_clock_ctx, &current_time));

    RESULT_GUARD_POSIX(s2n_config_set_session_tickets_onoff(config, 1));
    RESULT_GUARD_POSIX(s2n_config_add_ticket_crypto_key(config, ticket_key_name, strlen((char *)ticket_key_name),
                    ticket_key, sizeof(ticket_key), current_time/ONE_SEC_IN_NANOS));
    config->initial_tickets_to_send = 0;

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_send_records(struct s2n_connection *conn, struct s2n_stuffer *messages, uint32_t fragment_size)
{
    conn->max_outgoing_fragment_length = fragment_size;

    DEFER_CLEANUP(struct s2n_blob record_data = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&record_data, fragment_size));

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint32_t remaining = 0;
    while ((remaining = s2n_stuffer_data_available(messages)) > 0) {
        record_data.size = MIN(record_data.size, remaining);
        RESULT_GUARD_POSIX(s2n_stuffer_read(messages, &record_data));
        int r = s2n_record_write(conn, TLS_HANDSHAKE, &record_data);
        RESULT_GUARD_POSIX(r);
        RESULT_ENSURE_EQ(r, record_data.size);
        RESULT_GUARD_POSIX(s2n_flush(conn, &blocked));
    };

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_test_init_client_and_server(struct s2n_config *config,
        struct s2n_connection *sender, struct s2n_connection *receiver,
        struct s2n_test_io_stuffer_pair *io_pair)
{
    RESULT_GUARD_POSIX(s2n_connection_set_config(sender, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(sender, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(sender));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(sender, S2N_SELF_SERVICE_BLINDING));

    RESULT_GUARD_POSIX(s2n_connection_set_config(receiver, config));
    RESULT_GUARD_POSIX(s2n_connection_set_all_protocol_versions(receiver, S2N_TLS13));
    RESULT_GUARD(s2n_connection_set_secrets(receiver));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(receiver, S2N_SELF_SERVICE_BLINDING));

    if (io_pair) {
        RESULT_GUARD(s2n_io_stuffer_pair_init(io_pair));
        RESULT_GUARD(s2n_connections_set_io_stuffer_pair(sender, receiver, io_pair));
    }

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_recv(struct s2n_connection *sender, struct s2n_connection *receiver)
{
    uint8_t app_data[1] = { 0 };
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    int send_ret = s2n_send(sender, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(send_ret);
    RESULT_ENSURE_EQ(send_ret, sizeof(app_data));

    int recv_ret = s2n_recv(receiver, app_data, sizeof(app_data), &blocked);
    RESULT_GUARD_POSIX(recv_ret);
    RESULT_ENSURE_EQ(recv_ret, sizeof(app_data));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint8_t unknown_message_type = UINT8_MAX;
    EXPECT_FALSE(s2n_post_handshake_is_known(unknown_message_type));
    uint32_t test_message_sizes[] = { 0, 1, 2, 3001 };

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_OK(s2n_test_enable_tickets(config));
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

    /* Count session tickets */
    uint8_t tickets_count = 0;
    EXPECT_SUCCESS(s2n_config_set_session_ticket_cb(config, s2n_ticket_count_cb, &tickets_count));

    /* Count hello requests */
    uint8_t hello_request_count = 0;
    EXPECT_SUCCESS(s2n_config_set_renegotiate_request_cb(config, s2n_hello_request_cb, &hello_request_count));

    uint32_t fragment_sizes[] = {
        S2N_MAX_FRAGMENT_LENGTH_MIN,
        TLS_HANDSHAKE_HEADER_LENGTH,
        S2N_POST_HANDSHAKE_STATIC_IN_MAX,
        S2N_POST_HANDSHAKE_STATIC_IN_MAX + 1,
        S2N_DEFAULT_FRAGMENT_LENGTH,
        S2N_TLS_MAXIMUM_FRAGMENT_LENGTH,
    };

    uint8_t modes[] = { S2N_CLIENT, S2N_SERVER };

    /* Test with multiple different fragment sizes */
    for (size_t frag_i = 0; frag_i < s2n_array_len(fragment_sizes); frag_i++) {
        uint32_t fragment_size = fragment_sizes[frag_i];

        /* Test client and server receive small post-handshake messages (KeyUpdates) */
        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, sender, receiver, &io_pair));

            /* Write KeyUpdate records */
            DEFER_CLEANUP(struct s2n_stuffer message = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&message, 0));
            DEFER_CLEANUP(struct s2n_blob message_blob = { 0 }, s2n_free);
            EXPECT_SUCCESS(s2n_alloc(&message_blob, S2N_KEY_UPDATE_MESSAGE_SIZE));
            for (size_t j = 0; j < S2N_TEST_MESSAGE_COUNT; j++) {
                EXPECT_SUCCESS(s2n_key_update_write(&message_blob));
                EXPECT_SUCCESS(s2n_stuffer_write(&message, &message_blob));

                /* The TLS1.3 RFC says "Handshake messages MUST NOT span key changes".
                 * Because KeyUpdate messages trigger key changes, we cannot include multiple in one record.
                 * We must send individual KeyUpdate messages.
                 */
                EXPECT_OK(s2n_test_send_records(sender, &message, fragment_size));

                /* Update the traffic keys for the next records */
                EXPECT_SUCCESS(s2n_update_application_traffic_keys(sender, sender->mode, SENDING));
            }

            /*
             * We have no mechanism to count KeyUpdates, but we can assume they are processed
             * if we successfully decrypt all records. If they were not processed,
             * then we would try to use the wrong key to decrypt the next record.
             */
            EXPECT_OK(s2n_test_recv(sender, receiver));
        }

        /* Test client receives large post-handshake messages (NewSessionTickets) */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, server, client, &io_pair));

            /* Send NewSessionTicket records */
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
            for (size_t j = 0; j < S2N_TEST_MESSAGE_COUNT; j++) {
                server->tickets_to_send++;
                EXPECT_OK(s2n_tls13_server_nst_write(server, &messages));
            }
            EXPECT_OK(s2n_test_send_records(server, &messages, fragment_size));

            tickets_count = 0;
            EXPECT_OK(s2n_test_recv(server, client));
            EXPECT_EQUAL(tickets_count, S2N_TEST_MESSAGE_COUNT);
        }

        /* Test client receives empty post-handshake message (HelloRequest) */
        {
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, server, client, &io_pair));

            /* HelloRequests are ignored if secure_renegotiation isn't set */
            client->secure_renegotiation = true;

            /* Send HelloRequest records */
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
            for (size_t j = 0; j < S2N_TEST_MESSAGE_COUNT; j++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&messages, TLS_HELLO_REQUEST));
                EXPECT_SUCCESS(s2n_stuffer_write_uint24(&messages, 0));
            }
            EXPECT_OK(s2n_test_send_records(server, &messages, fragment_size));

            hello_request_count = 0;
            EXPECT_OK(s2n_test_recv(server, client));
            EXPECT_EQUAL(hello_request_count, S2N_TEST_MESSAGE_COUNT);
        }

        /* Test server rejects known, invalid post-handshake messages (NewSessionTickets) */
        {
            DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, client, server, &io_pair));

            /* Send NewSessionTicket records */
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
            for (size_t j = 0; j < S2N_TEST_MESSAGE_COUNT; j++) {
                client->tickets_to_send++;
                EXPECT_OK(s2n_tls13_server_nst_write(client, &messages));
            }
            EXPECT_OK(s2n_test_send_records(client, &messages, fragment_size));

            tickets_count = 0;
            EXPECT_ERROR_WITH_ERRNO(s2n_test_recv(client, server), S2N_ERR_BAD_MESSAGE);
            EXPECT_EQUAL(tickets_count, 0);
        }

        /* Test client and server reject known, invalid messages (ClientHellos) */
        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, sender, receiver, &io_pair));

            /* Send fake ClientHello records */
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
            for (size_t j = 0; j < s2n_array_len(test_message_sizes); j++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&messages, TLS_CLIENT_HELLO));
                EXPECT_SUCCESS(s2n_stuffer_write_uint24(&messages, test_message_sizes[j]));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&messages, test_message_sizes[j]));
            }
            EXPECT_OK(s2n_test_send_records(sender, &messages, fragment_size));

            EXPECT_ERROR_WITH_ERRNO(s2n_test_recv(sender, receiver), S2N_ERR_BAD_MESSAGE);
        }

        /* Test client and server ignore unknown messages */
        for (size_t mode_i = 0; mode_i < s2n_array_len(modes); mode_i++) {
            uint8_t mode = modes[mode_i];

            DEFER_CLEANUP(struct s2n_connection *receiver = s2n_connection_new(mode), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_connection *sender = s2n_connection_new(S2N_PEER_MODE(mode)), s2n_connection_ptr_free);
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_test_init_client_and_server(config, sender, receiver, &io_pair));

            /* Send unknown records */
            DEFER_CLEANUP(struct s2n_stuffer messages = { 0 }, s2n_stuffer_free);
            EXPECT_SUCCESS(s2n_stuffer_growable_alloc(&messages, 0));
            for (size_t j = 0; j < s2n_array_len(test_message_sizes); j++) {
                EXPECT_SUCCESS(s2n_stuffer_write_uint8(&messages, unknown_message_type));
                EXPECT_SUCCESS(s2n_stuffer_write_uint24(&messages, test_message_sizes[j]));
                EXPECT_SUCCESS(s2n_stuffer_skip_write(&messages, test_message_sizes[j]));
            }
            EXPECT_OK(s2n_test_send_records(sender, &messages, fragment_size));

            EXPECT_OK(s2n_test_recv(sender, receiver));
        }
    }

    END_TEST();
}
