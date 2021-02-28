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

#include "tls/s2n_connection.h"
#include "tls/s2n_handshake_type.h"
#include "utils/s2n_safety.h"

S2N_RESULT s2n_handshake_type_set_flag(struct s2n_connection *conn, s2n_handshake_type_flag flag)
{
    ENSURE_REF(conn);
    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        conn->handshake.handshake_type_tls12 |= flag;
    } else {
        conn->handshake.handshake_type_tls13 |= flag;
    }
    return S2N_RESULT_OK;
}

bool s2n_handshake_type_check_flag(struct s2n_connection *conn, s2n_handshake_type_flag flag)
{
    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        return conn->handshake.handshake_type_tls12 & flag;
    }
    return conn->handshake.handshake_type_tls13 & flag;
}

S2N_RESULT s2n_handshake_type_set_tls12_flag(struct s2n_connection *conn, s2n_tls12_handshake_type_flag flag)
{
    ENSURE_REF(conn);
    ENSURE(s2n_connection_get_protocol_version(conn) < S2N_TLS13, S2N_ERR_HANDSHAKE_STATE);
    conn->handshake.handshake_type_tls12 |= flag;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_handshake_type_unset_tls12_flag(struct s2n_connection *conn, s2n_tls12_handshake_type_flag flag)
{
    ENSURE_REF(conn);
    ENSURE(s2n_connection_get_protocol_version(conn) < S2N_TLS13, S2N_ERR_HANDSHAKE_STATE);
    conn->handshake.handshake_type_tls12 &= ~(flag);
    return S2N_RESULT_OK;
}

bool s2n_handshake_type_check_tls12_flag(struct s2n_connection *conn, s2n_tls12_handshake_type_flag flag)
{
    return conn && s2n_connection_get_protocol_version(conn) < S2N_TLS13
            && (conn->handshake.handshake_type_tls12 & flag);
}

S2N_RESULT s2n_handshake_type_set_tls13_flag(struct s2n_connection *conn, s2n_tls13_handshake_type_flag flag)
{
    ENSURE_REF(conn);
    ENSURE(s2n_connection_get_protocol_version(conn) >= S2N_TLS13, S2N_ERR_HANDSHAKE_STATE);
    conn->handshake.handshake_type_tls13 |= flag;
    return S2N_RESULT_OK;
}

bool s2n_handshake_type_check_tls13_flag(struct s2n_connection *conn, s2n_tls13_handshake_type_flag flag)
{
    return conn && s2n_connection_get_protocol_version(conn) >= S2N_TLS13
            && (conn->handshake.handshake_type_tls13 & flag);
}

S2N_RESULT s2n_get_handshake_type(struct s2n_connection *conn, uint16_t *handshake_type)
{
    ENSURE_REF(handshake_type);
    *handshake_type = 0;
    if (s2n_connection_get_protocol_version(conn) < S2N_TLS13) {
        ENSURE(conn->handshake.handshake_type_tls13 == 0, S2N_ERR_HANDSHAKE_STATE);
        *handshake_type = conn->handshake.handshake_type_tls12;
    } else {
        ENSURE(conn->handshake.handshake_type_tls12 == 0, S2N_ERR_HANDSHAKE_STATE);
        *handshake_type = conn->handshake.handshake_type_tls13;
    }
    ENSURE(*handshake_type < S2N_HANDSHAKES_COUNT, S2N_ERR_HANDSHAKE_STATE);
    return S2N_RESULT_OK;
}
