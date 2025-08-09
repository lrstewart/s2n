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

#include "tls/s2n_security_policy_builder.h"

#include "tls/s2n_security_policies.h"

#define S2N_BASE_POLICIES_COUNT 3
#define S2N_MAX_POLICY_VERSIONS 10

S2N_INLINE_SECURITY_POLICY_V1(
    base_policy_strict,
    S2N_TLS13,
    S2N_CIPHER_PREF_LIST(
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    ),
    S2N_SIG_PREF_LIST(
        &s2n_mldsa44,
        &s2n_mldsa65,
        &s2n_mldsa87,
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_rsa_pss_pss_sha256,
        &s2n_rsa_pss_pss_sha384,
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,
    ),
    S2N_CURVE_PREF_LIST(
        &s2n_ecc_curve_secp256r1,
        &s2n_ecc_curve_secp384r1,
        &s2n_ecc_curve_secp521r1,
    ),
    S2N_KEM_PREF_LIST(
        &s2n_secp256r1_mlkem_768,
        &s2n_secp384r1_mlkem_1024,
        &s2n_x25519_mlkem_768,
    )
);

S2N_INLINE_SECURITY_POLICY_V1(
    base_policy_compat,
    S2N_TLS12,
    S2N_CIPHER_PREF_LIST(
        &s2n_tls13_aes_128_gcm_sha256,
        &s2n_tls13_aes_256_gcm_sha384,
        &s2n_tls13_chacha20_poly1305_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    ),
    S2N_SIG_PREF_LIST(
        &s2n_mldsa44,
        &s2n_mldsa65,
        &s2n_mldsa87,
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_rsa_pss_pss_sha256,
        &s2n_rsa_pss_pss_sha384,
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
    ),
    S2N_CURVE_PREF_LIST(
        &s2n_ecc_curve_secp256r1,
        &s2n_ecc_curve_secp384r1,
        &s2n_ecc_curve_secp521r1,
        &s2n_ecc_curve_x25519,
    ),
    S2N_KEM_PREF_LIST(
        &s2n_secp256r1_mlkem_768,
        &s2n_secp384r1_mlkem_1024,
        &s2n_x25519_mlkem_768,
    )
);

S2N_INLINE_SECURITY_POLICY_V1(
    base_policy_legacy,
    S2N_TLS10,
    S2N_CIPHER_PREF_LIST(
        &s2n_tls13_aes_128_gcm_sha256,
        &s2n_tls13_aes_256_gcm_sha384,
        &s2n_tls13_chacha20_poly1305_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
        &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
        &s2n_ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        &s2n_ecdhe_rsa_with_chacha20_poly1305_sha256,
        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,

        &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
        &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
        &s2n_rsa_with_aes_128_gcm_sha256,
        &s2n_rsa_with_aes_256_gcm_sha384,
        &s2n_rsa_with_aes_128_cbc_sha256,
        &s2n_rsa_with_aes_256_cbc_sha256,
        &s2n_rsa_with_aes_128_cbc_sha,
        &s2n_rsa_with_aes_256_cbc_sha,
    ),
    S2N_SIG_PREF_LIST(
        &s2n_mldsa44,
        &s2n_mldsa65,
        &s2n_mldsa87,
        &s2n_ecdsa_sha256,
        &s2n_ecdsa_sha384,
        &s2n_ecdsa_sha512,
        &s2n_rsa_pss_pss_sha256,
        &s2n_rsa_pss_pss_sha384,
        &s2n_rsa_pss_rsae_sha256,
        &s2n_rsa_pss_rsae_sha384,
        &s2n_rsa_pss_rsae_sha512,
        &s2n_rsa_pkcs1_sha256,
        &s2n_rsa_pkcs1_sha384,
        &s2n_rsa_pkcs1_sha512,
        &s2n_ecdsa_sha224,
        &s2n_rsa_pkcs1_sha224,
        &s2n_ecdsa_sha1,
        &s2n_rsa_pkcs1_sha1,
        &s2n_rsa_pkcs1_md5_sha1,
    ),
    S2N_CURVE_PREF_LIST(
        &s2n_ecc_curve_secp256r1,
        &s2n_ecc_curve_secp384r1,
        &s2n_ecc_curve_secp521r1,
        &s2n_ecc_curve_x25519
    ),
    S2N_KEM_PREF_LIST(
        &s2n_secp256r1_mlkem_768,
        &s2n_secp384r1_mlkem_1024,
        &s2n_x25519_mlkem_768,
    )
);

const struct s2n_security_policy *base_policies[S2N_BASE_POLICIES_COUNT][S2N_MAX_POLICY_VERSIONS] = {
    [S2N_POLICY_STRICT] = {
        [S2N_STRICT_2025_1] = &base_policy_strict,
    },
    [S2N_POLICY_COMPATIBLE] = {
        [S2N_COMPAT_2024_1] = &security_policy_20240417,
        [S2N_COMPAT_2024_2] = &security_policy_20240503,
        [S2N_COMPAT_2025_1] = &base_policy_compat,
    },
    [S2N_POLICY_LEGACY] = {
        [S2N_LEGACY_2025_1] = &base_policy_legacy,
    },
};

const struct s2n_security_policy* s2n_security_policy_get(s2n_base_policy policy, uint64_t version)
{
    PTR_ENSURE(policy < S2N_BASE_POLICIES_COUNT, S2N_ERR_INVALID_ARGUMENT);
    PTR_ENSURE(version < S2N_MAX_POLICY_VERSIONS, S2N_ERR_INVALID_SECURITY_POLICY);

    const struct s2n_security_policy *match = base_policies[policy][version];
    PTR_ENSURE(match, S2N_ERR_INVALID_SECURITY_POLICY);

    return match;
}
