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

#include <s2n.h>

/**
 * @file fingerprint.h
 *
 * The following APIs enable applications to calculate fingerprints to
 * identify ClientHellos.
 *
 * The fingerprinting APIs are currently considered unstable. They will be finalized
 * and marked as stable after an initial customer integration and feedback.
 */

typedef enum {
    /* See https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967 */
    S2N_FINGERPRINT_JA3,
    /* See https://github.com/FoxIO-LLC/ja4/tree/main */
    S2N_FINGERPRINT_JA4,
} s2n_fingerprint_type;

struct s2n_fingerprint;

S2N_API struct s2n_fingerprint *s2n_fingerprint_new(s2n_fingerprint_type type);
S2N_API int s2n_fingerprint_wipe(struct s2n_fingerprint *fingerprint);
S2N_API int s2n_fingerprint_free(struct s2n_fingerprint **fingerprint);

S2N_API int s2n_fingerprint_set_client_hello(struct s2n_fingerprint *fingerprint, struct s2n_client_hello *ch);
S2N_API int s2n_fingerprint_set_working_buffer(struct s2n_fingerprint *fingerprint,
        uint8_t *mem, size_t mem_size);

S2N_API int s2n_fingerprint_get_hash_size(struct s2n_fingerprint *fingerprint, uint32_t *size);
S2N_API int s2n_fingerprint_get_hash(struct s2n_fingerprint *fingerprint,
        uint32_t max_output_size, uint8_t *output, uint32_t *output_size);

/**
 * Calculates a fingerprint hash for a given ClientHello.
 *
 * Currently the only type supported is S2N_FINGERPRINT_JA3, which uses MD5 and
 * requires at least 16 bytes of memory.
 *
 * @param ch The ClientHello to fingerprint.
 * @param type The algorithm to use for the fingerprint. Currently only JA3 is supported.
 * @param max_hash_size The maximum size of data that may be written to `hash`.
 * If too small for the requested hash, an S2N_ERR_T_USAGE error will occur.
 * @param hash The location that the requested hash will be written to.
 * @param hash_size The actual size of the data written to `hash`.
 * @param str_size The actual size of the full string associated with this hash.
 * This size can be used to ensure that sufficient memory is provided for the
 * output of `s2n_client_hello_get_fingerprint_string`.
 * @returns S2N_SUCCESS on success, S2N_FAILURE on failure.
 */
S2N_API int s2n_client_hello_get_fingerprint_hash(struct s2n_client_hello *ch,
        s2n_fingerprint_type type, uint32_t max_hash_size,
        uint8_t *hash, uint32_t *hash_size, uint32_t *str_size);
