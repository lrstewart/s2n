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

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_handshake_types.h"
#include "utils/s2n_safety.h"

/*
 * All possible TLS handshakes are stored in a map keyed on their type bitflags.
 * A perfect hashing function is used to keep the size of the map reasonable even
 * as we add more handshake types.
 */

/*
 * If we change the handshake tables, we'll probably need to update
 * this size. It will always be a prime, but not all primes will produce
 * a perfect hash.
 */
#define S2N_HANDSHAKES_TABLE_SIZE 37

#define S2N_SIZEOF_MESSAGES( count ) ((count) * sizeof(message_type_t))
#define MESSAGES (message_type_t[S2N_MAX_HANDSHAKE_LENGTH])

struct handshakes_entry {
    uint32_t handshake_type;
    message_type_t messages[S2N_MAX_HANDSHAKE_LENGTH];
};

static struct handshakes_entry tls12_handshakes[S2N_HANDSHAKES_TABLE_SIZE];
static struct handshakes_entry tls13_handshakes[S2N_HANDSHAKES_TABLE_SIZE];

static const message_type_t empty_handshake[S2N_MAX_HANDSHAKE_LENGTH];
static const message_type_t initial_handshake[S2N_MAX_HANDSHAKE_LENGTH] = {
        CLIENT_HELLO,
        SERVER_HELLO
};

static int s2n_init_tls12_handshakes();
static int s2n_init_tls13_handshakes();

int s2n_handshakes_init()
{
    GUARD(s2n_init_tls12_handshakes(tls12_handshakes));
    GUARD(s2n_init_tls13_handshakes(tls13_handshakes));

    return 0;
}

message_type_t s2n_handshake_message(uint32_t handshake_type, uint8_t message_number, uint8_t protocol_version)
{
    lt_check(message_number, S2N_MAX_HANDSHAKE_LENGTH);

    if (handshake_type == 0) {
        return initial_handshake[message_number];
    }

    int index = handshake_type % S2N_HANDSHAKES_TABLE_SIZE;

    struct handshakes_entry *handshakes = tls12_handshakes;
    if (protocol_version >= S2N_TLS13) {
        handshakes = tls13_handshakes;
    }

    if (handshakes[index].handshake_type == handshake_type) {
        return handshakes[index].messages[message_number];
    }

    return 0;
}

/* Used in tests */
int s2n_all_valid_handshakes(uint8_t protocol_version, uint32_t *valid_handshakes, int max_valid_handshakes)
{
    struct handshakes_entry *handshakes = tls12_handshakes;
    if (protocol_version == S2N_TLS13) {
        handshakes = tls13_handshakes;
    }

    int valid_handshakes_count = 0;
    for (int i = 0; i < S2N_HANDSHAKES_TABLE_SIZE; i++) {
        if (memcmp(handshakes[i].messages, empty_handshake, S2N_SIZEOF_MESSAGES(S2N_MAX_HANDSHAKE_LENGTH)) == 0) {
            continue;
        }

        lt_check(valid_handshakes_count, max_valid_handshakes);

        valid_handshakes[valid_handshakes_count] = handshakes[i].handshake_type;
        valid_handshakes_count++;
    }

    return valid_handshakes_count;
}

static int s2n_add_handshake(struct handshakes_entry *handshakes, uint32_t handshake_type, message_type_t *messages)
{
    uint8_t index = handshake_type % S2N_HANDSHAKES_TABLE_SIZE;

    S2N_ERROR_IF(index == 0, S2N_ERR_NOT_INITIALIZED);
    S2N_ERROR_IF(handshakes[index].handshake_type != 0, S2N_ERR_NOT_INITIALIZED);

    handshakes[index].handshake_type = handshake_type;
    memcpy_check(handshakes[index].messages, messages, S2N_SIZEOF_MESSAGES(S2N_MAX_HANDSHAKE_LENGTH));

    return 0;
}

static int s2n_tls12_handshake(uint32_t handshake_type, message_type_t *messages)
{
    return s2n_add_handshake(tls12_handshakes, handshake_type, messages);
}

static int s2n_tls13_handshake(uint32_t handshake_type, message_type_t *messages)
{
    return s2n_add_handshake(tls13_handshakes, handshake_type, messages);
}

int s2n_init_tls12_handshakes()
{
    GUARD(s2n_tls12_handshake(NEGOTIATED, MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_HELLO_DONE,
            CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | CLIENT_AUTH), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | CLIENT_AUTH | NO_CLIENT_CERT), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | CLIENT_AUTH | WITH_SESSION_TICKET), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | WITH_SESSION_TICKET), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET), MESSAGES{
           CLIENT_HELLO,
           SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_CERT_REQ, SERVER_HELLO_DONE,
           CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
           SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
           APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CERT_VERIFY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    GUARD(s2n_tls12_handshake((NEGOTIATED | FULL_HANDSHAKE | PERFECT_FORWARD_SECRECY | OCSP_STATUS | CLIENT_AUTH | NO_CLIENT_CERT | WITH_SESSION_TICKET), MESSAGES{
            CLIENT_HELLO,
            SERVER_HELLO, SERVER_CERT, SERVER_CERT_STATUS, SERVER_KEY, SERVER_CERT_REQ, SERVER_HELLO_DONE,
            CLIENT_CERT, CLIENT_KEY, CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
            SERVER_NEW_SESSION_TICKET, SERVER_CHANGE_CIPHER_SPEC, SERVER_FINISHED,
            APPLICATION_DATA
    }));

    return 0;
}

/*
 * This selection of handshakes resembles the standard set, but with changes made to support tls1.3.
 *
 * At the moment session resumption and early data are not supported.
 *
 * The CHANGE_CIPHER_SPEC messages are included only for middlebox compatibility.
 * See https://tools.ietf.org/html/rfc8446#appendix-D.4
 */
static int s2n_init_tls13_handshakes()
{
    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE), MESSAGES{
        CLIENT_HELLO,
        SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH), MESSAGES{
        CLIENT_HELLO,
        SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT), MESSAGES{
        CLIENT_HELLO,
        SERVER_HELLO, SERVER_CHANGE_CIPHER_SPEC, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_CERT, CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE | RETRY_HANDSHAKE), MESSAGES{
        CLIENT_HELLO,
        HELLO_RETRY_REQUEST, SERVER_CHANGE_CIPHER_SPEC,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
        SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | RETRY_HANDSHAKE), MESSAGES{
        CLIENT_HELLO,
        HELLO_RETRY_REQUEST, SERVER_CHANGE_CIPHER_SPEC,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
        SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_CERT, CLIENT_CERT_VERIFY, CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    GUARD(s2n_tls13_handshake((NEGOTIATED | FULL_HANDSHAKE | CLIENT_AUTH | NO_CLIENT_CERT | RETRY_HANDSHAKE), MESSAGES{
        CLIENT_HELLO,
        HELLO_RETRY_REQUEST, SERVER_CHANGE_CIPHER_SPEC,
        CLIENT_CHANGE_CIPHER_SPEC, CLIENT_HELLO,
        SERVER_HELLO, ENCRYPTED_EXTENSIONS, SERVER_CERT_REQ, SERVER_CERT, SERVER_CERT_VERIFY, SERVER_FINISHED,
        CLIENT_CERT, CLIENT_FINISHED,
        APPLICATION_DATA
    }));

    return 0;
}
