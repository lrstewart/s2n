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

#include "error/s2n_errno.h"

#include "tls/s2n_connection.h"
#include "tls/s2n_key_update.h"
#include "tls/s2n_tls.h"
#include "utils/s2n_safety.h"

static bool s2n_post_handshake_message_type_is_unknown(uint8_t message_type)
{
    switch (message_type) {
        case TLS_SERVER_NEW_SESSION_TICKET:
        case TLS_HELLO_REQUEST:
        case TLS_KEY_UPDATE:
        case TLS_CLIENT_HELLO:
        case TLS_SERVER_HELLO:
        case TLS_END_OF_EARLY_DATA:
        case TLS_ENCRYPTED_EXTENSIONS:
        case TLS_CERTIFICATE:
        case TLS_SERVER_KEY:
        case TLS_CERT_REQ:
        case TLS_SERVER_HELLO_DONE:
        case TLS_CERT_VERIFY:
        case TLS_CLIENT_KEY:
        case TLS_FINISHED:
        case TLS_SERVER_CERT_STATUS:
            return false;
        default:
            return true;
    }
}

static bool s2n_post_handshake_message_type_is_invalid(s2n_mode mode, uint8_t message_type)
{
    switch (message_type) {
        case TLS_SERVER_NEW_SESSION_TICKET:
        case TLS_HELLO_REQUEST:
            return mode == S2N_CLIENT;
        case TLS_KEY_UPDATE:
            return true;
        default:
            /* Unknown messages are valid */
            return s2n_post_handshake_message_type_is_unknown(message_type);
    }
}

static S2N_RESULT s2n_post_handshake_process(struct s2n_connection *conn, struct s2n_stuffer *in, uint8_t message_type)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(in);

    switch (message_type) {
        case TLS_KEY_UPDATE:
            RESULT_GUARD_POSIX(s2n_key_update_recv(conn, in));
            break;
        case TLS_SERVER_NEW_SESSION_TICKET:
            RESULT_GUARD(s2n_tls13_server_nst_recv(conn, in));
            break;
        case TLS_HELLO_REQUEST:
            RESULT_GUARD(s2n_client_hello_request_recv(conn));
            break;
        default:
            /* We should not be processing an invalid message */
            RESULT_BAIL(S2N_ERR_BAD_MESSAGE);
    }

    return S2N_RESULT_OK;
}

/*
 * Attempt to read a full handshake message.
 * If we fail, don't modify the input buffer so that we can attempt different processing.
 */
static S2N_RESULT s2n_try_read_full_handshake_message(struct s2n_connection *conn, uint8_t *message_type, uint32_t *message_len)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(message_len);

    struct s2n_stuffer in_copy = conn->in;
    if (s2n_stuffer_data_available(&in_copy) >= TLS_HANDSHAKE_HEADER_LENGTH) {
       RESULT_GUARD(s2n_handshake_parse_header(&in_copy, message_type, message_len));
       if (s2n_stuffer_data_available(&in_copy) >= *message_len) {
           conn->in = in_copy;
           return S2N_RESULT_OK;
       }
    }
    RESULT_BAIL(S2N_ERR_IO_BLOCKED);
}

S2N_RESULT s2n_post_handshake_message_get_handling(struct s2n_connection *conn, enum s2n_message_handling *handling)
{
    if (s2n_stuffer_data_available(&conn->post_handshake.in) > 0) {
        *handling = S2N_READ_NEXT_FRAGMENT;
        return S2N_RESULT_OK;
    }

    uint8_t message_type = 0;
    uint32_t message_len = 0;
    s2n_result r = s2n_try_read_full_handshake_message(conn, &message_type, &message_len);
    if (s2n_result_is_ok(r)) {
        *handling = S2N_READ_MESSAGE_DIRECTLY;
    } else if (s2n_errno == S2N_ERR_IO_BLOCKED) {
        *handling = S2N_BUFFER_FIRST_FRAGMENT;
    } else {
        return r;
    }

    if (s2n_post_handshake_message_type_is_unknown(conn->mode, message_type)) {
        *handling = S2N_SKIP_MESSAGE;
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_post_handshake_message_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    uint8_t message_type = 0;
    uint32_t message_len = 0;

    switch(conn->post_handshake.type) {
        case S2N_POST_HS_UNKOWN_IN_TYPE:
            /* Try to read the message directly from conn->in */
            s2n_result r = s2n_read_full_handshake_message(conn, &conn->in, &message_type);
            if (s2n_result_is_error(r)) {
                conn->post_handshake.type = S2N_POST_HS_HEADER_IN;
                return s2n_post_handshake_message_recv(conn);
            }
            RESULT_GUARD(s2n_post_handshake_process(conn, &conn->post_handshake.in, message_type));
            break;
        case S2N_POST_HS_SKIP_IN:
            /* We have already allocated heap memory. Keep using it. */
            uint32_t to_skip = MAX(s2n_stuffer_data_available(conn->in), conn->post_handshake.in.remaining);
            RESULT_GUARD_POSIX(s2n_stuffer_skip_read(conn->in, to_skip));
            conn->post_handshake.in.remaining -= to_skip;
            /* Check if we've finished reading the skipped message */
            if (conn->post_handshake.in.remaining == 0) {
                conn->post_handshake.type = S2N_POST_HS_UNKOWN_IN_TYPE;
            }
            break;
        case S2N_POST_HS_DYNAMIC_IN:
            /* We have already allocated heap memory. Keep using it. */
            RESULT_GUARD(s2n_read_full_handshake_message(conn, &conn->post_handshake.in, &message_type));
            RESULT_GUARD(s2n_post_handshake_process(conn, &conn->post_handshake.in, message_type));
            RESULT_GUARD_POSIX(s2n_stuffer_wipe(&conn->post_handshake.in));
            break;
        case S2N_POST_HS_STATIC_IN:
            /* Setup a stuffer to use the connection memory */
            struct s2n_blob blob = { 0 };
            struct s2n_stuffer stuffer = { 0 };
            RESULT_GUARD_POSIX(s2n_blob_init(&blob, conn->post_handshake.in.small.bytes, sizeof(conn->post_handshake.in.bytes)));
            RESULT_GUARD_POSIX(s2n_stuffer_init(&stuffer, &blob));
            RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&stuffer, conn->post_handshake.in.small.read));
            /* Read the message into the connection memory */
            RESULT_GUARD(s2n_read_full_handshake_message(conn, &stuffer, &message_type));
            RESULT_GUARD(s2n_post_handshake_process(conn, &stuffer, message_type));
            break;
    }

    bool first_fragment = s2n_stuffer_data_available(&conn->post_handshake.in) == 0;
    bool full_message_available = false;
    if (first_fragment) {
        /* Because post-handshake messages are not necessarily common compared
         * to application data, we don't want to keep a dedicated buffer for them.
         * However, we also don't want to unnecessarily allocate large chunks of memory.
         *
         * Therefore, if the handshake message isn't fragmented, just read it from conn->in.
         * Only allocate new memory if the full message isn't available, still in that case
         * we'll need to store the fragments while we read more into conn->in.
         */
        s2n_result r = s2n_try_read_full_handshake_message(conn, &message_type, &message_len);
    }


    if (first_fragment) {
        /* Because post-handshake messages are not necessarily common compared
         * to application data, we don't want to keep a dedicated buffer for them.
         * However, we also don't want to unnecessarily allocate large chunks of memory.
         *
         * Therefore, if the handshake message isn't fragmented, just read it from conn->in.
         * Only allocate new memory if the full message isn't available, still in that case
         * we'll need to store the fragments while we read more into conn->in.
         */
        s2n_result r = s2n_try_read_full_handshake_message(conn, &message_type, &message_len);

        /* If we can't read a full message, we'll need to buffer the partial message
         * so that we can read a new record into conn->in.
         */
        if (s2n_result_is_error(r)) {
            uint32_t buffer_size = 0;
            RESULT_GUARD(s2n_post_handshake_buffer_size(message_len, &buffer_size));
            RESULT_GUARD_POSIX(s2n_stuffer_resize_if_empty(&conn->post_handshake.in, buffer_size));

            uint32_t remaining = s2n_stuffer_data_available(&conn->in);
            RESULT_GUARD_POSIX(s2n_stuffer_copy(&conn->in, &conn->post_handshake.in, remaining));

            RESULT_BAIL(S2N_ERR_IO_BLOCKED);
        }

        struct s2n_blob message_blob = { 0 };
        uint8_t *message_data = s2n_stuffer_raw_read(&conn->in, message_len);
        RESULT_ENSURE_REF(message_data);
        RESULT_GUARD_POSIX(s2n_blob_init(&message_blob, message_data, message_len));

        struct s2n_stuffer message_stuffer = { 0 };
        RESULT_GUARD_POSIX(s2n_stuffer_init(&message_stuffer, &message_blob));
        RESULT_GUARD_POSIX(s2n_stuffer_skip_write(&message_stuffer, message_len));

        RESULT_GUARD(s2n_post_handshake_process(conn, &message_stuffer, message_type));
    }

    if (!first_fragment) {
        /* We have already buffered at least one fragment of the message.
         * Continue trying to read the complete message.
         */
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_post_handshake_recv(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    while(s2n_stuffer_data_available(&conn->in)) {
        RESULT_GUARD(s2n_post_handshake_message_recv(conn));
    }
    return S2N_RESULT_OK;
}

int s2n_post_handshake_send(struct s2n_connection *conn, s2n_blocked_status *blocked)
{
    POSIX_ENSURE_REF(conn);

    POSIX_GUARD(s2n_key_update_send(conn, blocked));
    POSIX_GUARD_RESULT(s2n_tls13_server_nst_send(conn, blocked));

    return S2N_SUCCESS;
}
