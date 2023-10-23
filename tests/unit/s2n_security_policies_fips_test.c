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
#include "testlib/s2n_testlib.h"

#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"

const uint8_t min_version = S2N_TLS11;

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf */
const struct s2n_cipher_suite *fips_cipher_suites[] = {
    &s2n_dhe_rsa_with_aes_128_cbc_sha,
    &s2n_dhe_rsa_with_aes_256_cbc_sha,
    &s2n_dhe_rsa_with_aes_128_cbc_sha256,
    &s2n_dhe_rsa_with_aes_256_cbc_sha256,
    &s2n_dhe_rsa_with_aes_128_gcm_sha256,
    &s2n_dhe_rsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha,
    &s2n_ecdhe_ecdsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_rsa_with_aes_128_cbc_sha256,
    &s2n_ecdhe_rsa_with_aes_256_cbc_sha384,
    &s2n_ecdhe_ecdsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_ecdsa_with_aes_256_gcm_sha384,
    &s2n_ecdhe_rsa_with_aes_128_gcm_sha256,
    &s2n_ecdhe_rsa_with_aes_256_gcm_sha384,
    &s2n_tls13_aes_128_gcm_sha256,
    &s2n_tls13_aes_256_gcm_sha384,
};
static S2N_RESULT s2n_assert_cipher_fips_compliant(const struct s2n_cipher_suite *cipher)
{
    for (size_t i = 0; i < s2n_array_len(fips_cipher_suites); i++) {
        if (fips_cipher_suites[i] == cipher) {
            return S2N_RESULT_OK;
        }
    }
    RESULT_BAIL(S2N_ERR_TEST_ASSERTION);
}

/* FIPS requires at least 112 bits of security.
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf */
const s2n_hash_algorithm fips_hash_algs[] = {
    //S2N_HASH_SHA1,
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
};
static S2N_RESULT s2n_assert_sig_scheme_fips_compliant(const struct s2n_signature_scheme *sig_alg)
{
    for (size_t i = 0; i < s2n_array_len(fips_hash_algs); i++) {
        if (fips_hash_algs[i] == sig_alg->hash_alg) {
            return S2N_RESULT_OK;
        }
    }
    RESULT_BAIL(S2N_ERR_TEST_ASSERTION);
}

/* https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf */
const struct s2n_ecc_named_curve *fips_curves[] = {
        &s2n_ecc_curve_secp256r1,
        &s2n_ecc_curve_secp384r1,
        &s2n_ecc_curve_secp521r1,
};
static S2N_RESULT s2n_assert_curve_fips_compliant(const struct s2n_ecc_named_curve *const curve)
{
    for (size_t i = 0; i < s2n_array_len(fips_curves); i++) {
        if (fips_curves[i] == curve) {
            return S2N_RESULT_OK;
        }
    }
    RESULT_BAIL(S2N_ERR_TEST_ASSERTION);
}

static S2N_RESULT s2n_assert_negotiation(struct s2n_connection *server, struct s2n_connection *client)
{
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(client, S2N_SELF_SERVICE_BLINDING));
    RESULT_GUARD_POSIX(s2n_connection_set_blinding(server, S2N_SELF_SERVICE_BLINDING));

    DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
    RESULT_GUARD(s2n_io_stuffer_pair_init(&io_pair));
    RESULT_GUARD(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server, client));
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_assert_negotiation_fips_compliant(
        struct s2n_config *server_config, struct s2n_config *client_config,
        const struct s2n_security_policy *server_policy, const struct s2n_security_policy *client_policy)
{
    DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client, client_config));

    DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server, server_config));

    client->security_policy_override = client_policy;
    server->security_policy_override = &security_policy_test_all;
    RESULT_GUARD(s2n_assert_negotiation(server, client));

    RESULT_GUARD_POSIX(s2n_connection_wipe(server));
    RESULT_GUARD_POSIX(s2n_connection_wipe(client));

    client->security_policy_override = client_policy;
    server->security_policy_override = server_policy;
    s2n_result result = s2n_assert_negotiation(server, client);
    if (s2n_result_is_error(result)) {
        return S2N_RESULT_OK;
    }

    RESULT_GUARD(s2n_assert_cipher_fips_compliant(server->secure->cipher_suite));
    RESULT_GUARD(s2n_assert_sig_scheme_fips_compliant(server->handshake_params.server_cert_sig_scheme));
    RESULT_GUARD(s2n_assert_curve_fips_compliant(server->kex_params.server_ecc_evp_params.negotiated_curve));

    /* Version must be >= TLS1.1
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf */
    RESULT_ENSURE(server->actual_protocol_version >= S2N_TLS11, S2N_ERR_TEST_ASSERTION);

    return S2N_RESULT_OK;
}

int main()
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *pss_chain_and_key = NULL,
            s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&pss_chain_and_key,
            S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));

    char dh_params[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dh_params, sizeof(dh_params)));

    DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, rsa_chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, pss_chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(server_config, ecdsa_chain_and_key));
    EXPECT_SUCCESS(s2n_config_add_dhparams(server_config, dh_params));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

    const struct s2n_cipher_preferences *cipher_pref_all = security_policy_test_all.cipher_preferences;
    const struct s2n_signature_preferences *sig_pref_all = security_policy_test_all.signature_preferences;
    const struct s2n_ecc_preferences *ecc_pref_all = security_policy_test_all.ecc_preferences;

    /* Collect all fips policies. For now, assume based on the name.
     * We can add a flag later if desired.
     */
    const struct s2n_security_policy *fips_policies[100] = { 0 };
    size_t fips_policies_count = 0;
    for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
        if (security_policy_selection[i].security_policy == NULL) {
            continue;
        }
        bool is_fips = strstr(security_policy_selection[i].version, "fips")
                || strstr(security_policy_selection[i].version, "FIPS")
                || security_policy_selection[i].security_policy->fips_compliant;
        if (is_fips) {
            EXPECT_TRUE(fips_policies_count < s2n_array_len(fips_policies));
            fips_policies[fips_policies_count] = security_policy_selection[i].security_policy;
            fips_policies_count++;
        }
    }

    /* First, make generic assertions about policies that should be fips */
    for (size_t i = 0; i < fips_policies_count; i++) {
        const struct s2n_security_policy *policy = fips_policies[i];

        const struct s2n_cipher_preferences *cipher_prefs = policy->cipher_preferences;
        for (size_t j = 0; j < cipher_prefs->count; j++) {
            EXPECT_OK(s2n_assert_cipher_fips_compliant(cipher_prefs->suites[j]));
        }

        const struct s2n_signature_preferences *sig_prefs = policy->signature_preferences;
        for (size_t j = 0; j < sig_prefs->count; j++) {
            EXPECT_OK(s2n_assert_sig_scheme_fips_compliant(sig_prefs->signature_schemes[j]));
        }

        const struct s2n_ecc_preferences *ecc_prefs = policy->ecc_preferences;
        for (size_t j = 0; j < ecc_prefs->count; j++) {
            EXPECT_OK(s2n_assert_curve_fips_compliant(ecc_prefs->ecc_curves[j]));
        }

        EXPECT_TRUE(policy->minimum_protocol_version >= S2N_TLS11);
    }

    /* Next, check that those assertions hold up in a self-talk test */
    for (size_t i = 0; i < fips_policies_count; i++) {
        const struct s2n_security_policy *fips_policy = fips_policies[i];

        /* Test all ciphers */
        for (size_t j = 0; j < cipher_pref_all->count; j++) {
            struct s2n_cipher_suite *cipher = cipher_pref_all->suites[j];
            if (!cipher->available) {
                continue;
            }
            struct s2n_cipher_preferences cipher_prefs = {
                .suites = &cipher,
                .count = 1,
            };
            struct s2n_security_policy test_policy = security_policy_test_all;
            test_policy.cipher_preferences = &cipher_prefs;

            EXPECT_OK(s2n_assert_negotiation_fips_compliant(
                    server_config, client_config,
                    fips_policy, &test_policy));
        }

        /* Test all signature algorithms */
        for (size_t j = 0; j < sig_pref_all->count; j++) {
            const struct s2n_signature_scheme *sig_scheme = sig_pref_all->signature_schemes[j];
            struct s2n_signature_preferences sig_prefs = {
                .signature_schemes = &sig_scheme,
                .count = 1,
            };
            struct s2n_security_policy test_policy = security_policy_test_all;
            test_policy.signature_preferences = &sig_prefs;
            if (sig_scheme->maximum_protocol_version < S2N_TLS13) {
                test_policy.cipher_preferences = security_policy_test_all_tls12.cipher_preferences;
            }

            EXPECT_OK(s2n_assert_negotiation_fips_compliant(
                    server_config, client_config,
                    fips_policy, &test_policy));
        }

        /* Test all curves */
        for (size_t j = 0; j < ecc_pref_all->count; j++) {
            struct s2n_ecc_preferences ecc_prefs = {
                .ecc_curves = &ecc_pref_all->ecc_curves[j],
                .count = 1,
            };
            struct s2n_security_policy test_policy = security_policy_test_all_ecdsa;
            test_policy.ecc_preferences = &ecc_prefs;

            EXPECT_OK(s2n_assert_negotiation_fips_compliant(
                    server_config, client_config,
                    fips_policy, &test_policy));
        }

        /* Test all protocols */
        for (size_t j = S2N_TLS10; j <= S2N_TLS13; j++) {
            s2n_highest_protocol_version = j;
            EXPECT_OK(s2n_assert_negotiation_fips_compliant(
                    server_config, client_config,
                    fips_policy, &security_policy_test_all));
        }
    }

    END_TEST();
}
