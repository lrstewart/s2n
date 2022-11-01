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

#pragma once

struct s2n_connection;

enum s2n_post_hs_in_type {
    S2N_POST_HS_UNKOWN_IN_TYPE = 0,
    S2N_POST_HS_HEADER_IN,
    S2N_POST_HS_SKIP_IN,
    S2N_POST_HS_DYNAMIC_IN,
    S2N_POST_HS_STATIC_IN,
};

struct s2n_post_hs_small_msg {
    uint8_t read;
    uint8_t bytes[S2N_KEY_UPDATE_MESSAGE_SIZE];
};

struct s2n_post_handshake {
    enum s2n_post_hs_in_type type;
    union {
        struct s2n_stuffer stuffer;
        struct s2n_post_hs_small_msg small;
        uint32_t remaining;
    } in;
};

S2N_RESULT s2n_post_handshake_recv(struct s2n_connection *conn);
int s2n_post_handshake_send(struct s2n_connection *conn, s2n_blocked_status *blocked);
