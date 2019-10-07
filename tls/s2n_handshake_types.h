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

#pragma once

#include "api/s2n.h"

#include "tls/s2n_handshake.h"
#include "tls/s2n_connection.h"

/* Maximum number of messages in a handshake */
#define S2N_MAX_HANDSHAKE_LENGTH    16

typedef enum {
    INITIAL                     = 0x00,
    NEGOTIATED                  = 0x01,
    FULL_HANDSHAKE              = 0x02,
    PERFECT_FORWARD_SECRECY     = 0x04,
    OCSP_STATUS                 = 0x08,
    CLIENT_AUTH                 = 0x10,
    WITH_SESSION_TICKET         = 0x20,
    NO_CLIENT_CERT              = 0x40,
    RETRY_HANDSHAKE             = 0x80,
} s2n_handshake_flag_types;

#define IS_NEGOTIATED( type )                   ( (type) & NEGOTIATED )
#define IS_FULL_HANDSHAKE( type )               ( (type) & FULL_HANDSHAKE )
#define IS_RESUMPTION_HANDSHAKE( type )         ( !IS_FULL_HANDSHAKE( (type) ) && IS_NEGOTIATED ( (type) ) )
#define IS_OCSP_STAPLED( type )                 ( (type) & OCSP_STATUS )
#define IS_ISSUING_NEW_SESSION_TICKET( type )   ( (type) & WITH_SESSION_TICKET )

int s2n_handshakes_init();
message_type_t s2n_handshake_message(uint32_t handshake_type, uint8_t message_number, uint8_t protocol_version);
