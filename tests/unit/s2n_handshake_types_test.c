/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake_types.h"
#include "utils/s2n_safety.h"

static const message_type_t empty_handshake[S2N_MAX_HANDSHAKE_LENGTH];

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Invalid message number */
    EXPECT_FAILURE(s2n_handshake_message(INITIAL, S2N_MAX_HANDSHAKE_LENGTH, S2N_TLS13));

    /* Retrieve INITIAL handshake, regardless of protocol version */
    {
        uint8_t random_protocol_version = 77;
        message_type_t expected_messages[S2N_MAX_HANDSHAKE_LENGTH] = { CLIENT_HELLO, SERVER_HELLO };
        for ( int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
            EXPECT_EQUAL(s2n_handshake_message(INITIAL, i, random_protocol_version), expected_messages[i]);
        }
    }

    /* Retrieve TLS1.2-only handshake */
    {
        uint32_t handshake_type = NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY;
        message_type_t expected_messages[S2N_MAX_HANDSHAKE_LENGTH] = {
                CLIENT_HELLO,
                SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_HELLO_DONE,
                CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
                SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
                APPLICATION_DATA,
        };
        for ( int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS12), expected_messages[i]);
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS13), empty_handshake[i]);
        }
    }

    /* Retrieve TLS1.3-only handshake */
    {
        uint32_t handshake_type = NEGOTIATED | FULL_HANDSHAKE | RETRY_HANDSHAKE;
        message_type_t expected_messages[S2N_MAX_HANDSHAKE_LENGTH] = {
                CLIENT_HELLO,
                HELLO_RETRY_REQUEST, SERVER_CHANGE_CIPHER_SPEC,
                CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
                SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
                CLIENT_FINISHED,
                APPLICATION_DATA,
        };
        for ( int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS12), empty_handshake[i]);
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS13), expected_messages[i]);
        }
    }

    /* Retrieve common handshake */
    {
        uint32_t handshake_type = NEGOTIATED | FULL_HANDSHAKE;
        message_type_t expected_tls12_messages[S2N_MAX_HANDSHAKE_LENGTH] = {
                CLIENT_HELLO,
                SERVER_HELLO, SERVER_CERT, SERVER_HELLO_DONE,
                CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
                SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
                APPLICATION_DATA
        };
        message_type_t expected_tls13_messages[S2N_MAX_HANDSHAKE_LENGTH] = {
                CLIENT_HELLO,
                SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
                CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
                APPLICATION_DATA
        };
        for ( int i = 0; i < S2N_MAX_HANDSHAKE_LENGTH; i++) {
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS12), expected_tls12_messages[i]);
            EXPECT_EQUAL(s2n_handshake_message(handshake_type, i, S2N_TLS13), expected_tls13_messages[i]);
        }
    }

    END_TEST();
    return 0;
}
