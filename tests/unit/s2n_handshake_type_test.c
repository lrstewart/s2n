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

#include "tls/s2n_connection.h"

int main(int argc, char **argv)
{
    BEGIN_TEST();

    const uint16_t test_handshake_type = 100;

    /* Test s2n_get_handshake_type */
    {
        /* TLS1.2 handshake */
        {
            uint16_t actual_handshake_type = 0;

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            /* Returns valid TLS1.2 handshake type */
            conn->handshake.handshake_type_tls12 = test_handshake_type;
            EXPECT_OK(s2n_get_handshake_type(conn, &actual_handshake_type));
            EXPECT_EQUAL(actual_handshake_type, test_handshake_type);

            /* Fails if TLS1.3 handshake type also set */
            conn->handshake.handshake_type_tls13 = 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_get_handshake_type(conn, &actual_handshake_type), S2N_ERR_HANDSHAKE_STATE);
            EXPECT_EQUAL(actual_handshake_type, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* TLS1.3 handshake */
        {
            uint16_t actual_handshake_type = 0;

            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;

            /* Returns valid TLS1.3 handshake type */
            conn->handshake.handshake_type_tls13 = test_handshake_type;
            EXPECT_OK(s2n_get_handshake_type(conn, &actual_handshake_type));
            EXPECT_EQUAL(actual_handshake_type, test_handshake_type);

            /* Fails if TLS1.2 handshake type also set */
            conn->handshake.handshake_type_tls12 = 1;
            EXPECT_ERROR_WITH_ERRNO(s2n_get_handshake_type(conn, &actual_handshake_type), S2N_ERR_HANDSHAKE_STATE);
            EXPECT_EQUAL(actual_handshake_type, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    /* Test setting handshake flags */
    {
        /* s2n_handshake_type_set_flag for TLS1.2 */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_OK(s2n_handshake_type_set_flag(conn, FULL_HANDSHAKE));
            EXPECT_EQUAL(conn->handshake.handshake_type_tls12, FULL_HANDSHAKE);
            EXPECT_EQUAL(conn->handshake.handshake_type_tls13, 0);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* s2n_handshake_type_set_flag for TLS1.2 */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_OK(s2n_handshake_type_set_flag(conn, FULL_HANDSHAKE));
            EXPECT_EQUAL(conn->handshake.handshake_type_tls12, 0);
            EXPECT_EQUAL(conn->handshake.handshake_type_tls13, FULL_HANDSHAKE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* s2n_handshake_type_set_tls12_flag */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS12;

            EXPECT_OK(s2n_handshake_type_set_tls12_flag(conn, OCSP_STATUS));
            EXPECT_EQUAL(conn->handshake.handshake_type_tls12, OCSP_STATUS);
            EXPECT_EQUAL(conn->handshake.handshake_type_tls13, 0);

            conn->actual_protocol_version = S2N_TLS13;
            EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls12_flag(conn, OCSP_STATUS), S2N_ERR_HANDSHAKE_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }

        /* s2n_handshake_type_set_tls13_flag */
        {
            struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
            EXPECT_NOT_NULL(conn);
            conn->actual_protocol_version = S2N_TLS13;

            EXPECT_OK(s2n_handshake_type_set_tls13_flag(conn, MIDDLEBOX_COMPAT));
            EXPECT_EQUAL(conn->handshake.handshake_type_tls12, 0);
            EXPECT_EQUAL(conn->handshake.handshake_type_tls13, MIDDLEBOX_COMPAT);

            conn->actual_protocol_version = S2N_TLS12;
            EXPECT_ERROR_WITH_ERRNO(s2n_handshake_type_set_tls13_flag(conn, MIDDLEBOX_COMPAT), S2N_ERR_HANDSHAKE_STATE);

            EXPECT_SUCCESS(s2n_connection_free(conn));
        }
    }

    END_TEST();
}
