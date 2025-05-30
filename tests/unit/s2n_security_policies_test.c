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

#include "tls/s2n_security_policies.h"

#include "crypto/s2n_pq.h"
#include "crypto/s2n_rsa_pss.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_kem.h"
#include "tls/s2n_signature_algorithms.h"
#include "tls/s2n_tls.h"

struct s2n_supported_cert {
    struct s2n_cert_chain_and_key *cert;
    size_t start_index;
};

static S2N_RESULT s2n_test_security_policies_compatible(const struct s2n_security_policy *policy,
        const char *default_policy, struct s2n_cert_chain_and_key *cert_chain)
{
    DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(),
            s2n_config_ptr_free);
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(server_config, cert_chain));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(),
            s2n_config_ptr_free);
    RESULT_GUARD_POSIX(s2n_config_set_unsafe_for_testing(client_config));

    DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server, server_config));
    RESULT_GUARD_POSIX(s2n_connection_set_cipher_preferences(server, default_policy));

    DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client, client_config));
    client->security_policy_override = policy;

    DEFER_CLEANUP(struct s2n_test_io_pair test_io_pair = { 0 },
            s2n_io_pair_close);
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&test_io_pair));
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(client, server, &test_io_pair));
    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server, client));

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_test_default_backwards_compatible(const char *default_version,
        const struct s2n_security_policy **versioned_policies, size_t versioned_policies_count,
        const struct s2n_supported_cert *supported_certs, size_t supported_certs_count)
{
    RESULT_ENSURE_REF(default_version);
    RESULT_ENSURE_REF(versioned_policies);
    RESULT_ENSURE_REF(supported_certs);

    /* The list of versioned policies MUST be kept up to date so that
     * we continue testing against all past defaults.
     */
    const struct s2n_security_policy *current = NULL;
    RESULT_GUARD_POSIX(s2n_find_security_policy_from_version(default_version, &current));
    if (versioned_policies[versioned_policies_count - 1] != current) {
        fprintf(stdout, "Missing latest version of '%s'\n", default_version);
        FAIL_MSG("New default policy MUST be added to versioning test");
    }

    for (size_t policy_i = 0; policy_i < versioned_policies_count; policy_i++) {
        for (size_t cert_i = 0; cert_i < supported_certs_count; cert_i++) {
            if (policy_i < supported_certs[cert_i].start_index) {
                continue;
            }
            RESULT_GUARD(s2n_test_security_policies_compatible(
                    versioned_policies[policy_i],
                    default_version,
                    supported_certs[cert_i].cert));
        }
    }

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();
    EXPECT_SUCCESS(s2n_disable_tls13_in_test());

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain_and_key,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&ecdsa_chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_sha384_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&ecdsa_sha384_chain_and_key, "ec", "ecdsa", "p384", "sha384"));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *ecdsa_sha256_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_permutation_load_server_chain(&ecdsa_sha256_chain_and_key, "ec", "ecdsa", "p256", "sha256"));

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_pss_chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    if (s2n_is_rsa_pss_certs_supported()) {
        EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_pss_chain_and_key,
                S2N_RSA_PSS_2048_SHA256_LEAF_CERT, S2N_RSA_PSS_2048_SHA256_LEAF_KEY));
    }

    /* Perform basic checks on all Security Policies. */
    for (size_t policy_index = 0; security_policy_selection[policy_index].version != NULL; policy_index++) {
        const struct s2n_security_policy *security_policy = security_policy_selection[policy_index].security_policy;

        /* TLS 1.3 + PQ checks */
        if (security_policy->kem_preferences->tls13_kem_group_count > 0) {
            /* Ensure that no TLS 1.3 KEM group preference lists go over max supported limit */
            EXPECT_TRUE(security_policy->kem_preferences->tls13_kem_group_count <= S2N_KEM_GROUPS_COUNT);

            /* Ensure all TLS 1.3 KEM groups in all policies are in the global list of all supported KEM groups */
            for (size_t i = 0; i < security_policy->kem_preferences->tls13_kem_group_count; i++) {
                const struct s2n_kem_group *kem_group = security_policy->kem_preferences->tls13_kem_groups[i];

                bool kem_group_is_supported = false;
                for (size_t j = 0; j < kem_preferences_all.tls13_kem_group_count; j++) {
                    if (kem_group->iana_id == kem_preferences_all.tls13_kem_groups[j]->iana_id) {
                        kem_group_is_supported = true;
                        break;
                    }
                }
                EXPECT_TRUE(kem_group_is_supported);
            }
        }

        /* TLS 1.3 Cipher suites have TLS 1.3 Signature Algorithms Test */
        bool has_tls_13_cipher = false;
        for (size_t i = 0; i < security_policy->cipher_preferences->count; i++) {
            if (security_policy->cipher_preferences->suites[i]->minimum_required_tls_version == S2N_TLS13) {
                has_tls_13_cipher = true;
                break;
            }
        }

        if (has_tls_13_cipher) {
            bool has_tls_13_sig_alg = false;
            bool has_rsa_pss = false;

            for (size_t i = 0; i < security_policy->signature_preferences->count; i++) {
                int min = security_policy->signature_preferences->signature_schemes[i]->minimum_protocol_version;
                int max = security_policy->signature_preferences->signature_schemes[i]->maximum_protocol_version;
                if (max == S2N_UNKNOWN_PROTOCOL_VERSION) {
                    max = S2N_TLS13;
                }
                s2n_signature_algorithm sig_alg = security_policy->signature_preferences->signature_schemes[i]->sig_alg;

                if (min <= S2N_TLS13 && max >= S2N_TLS13) {
                    has_tls_13_sig_alg = true;
                }

                if (sig_alg == S2N_SIGNATURE_RSA_PSS_PSS || sig_alg == S2N_SIGNATURE_RSA_PSS_RSAE) {
                    has_rsa_pss = true;
                }
            }

            EXPECT_TRUE(has_tls_13_sig_alg);
            EXPECT_TRUE(has_rsa_pss);
        }
    }

    const struct s2n_security_policy *security_policy = NULL;

    /* Test Deprecated Security Policies */
    {
        /* Ensure that every policy in the deprecated list has been removed from the supported policies list */
        for (size_t i = 0; i < deprecated_security_policies_len; i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version(deprecated_security_policies[i], &security_policy), S2N_ERR_DEPRECATED_SECURITY_POLICY);
        }

        /* Spot check a few deprecated security policies to ensure S2N_ERR_DEPRECATED_SECURITY_POLICY is returned as expected. */
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2019-11", &security_policy), S2N_ERR_DEPRECATED_SECURITY_POLICY);
        EXPECT_FAILURE_WITH_ERRNO(s2n_find_security_policy_from_version("PQ-SIKE-TEST-TLS-1-0-2020-02", &security_policy), S2N_ERR_DEPRECATED_SECURITY_POLICY);
    }

    /* Test common known good cipher suites for expected configuration */
    {
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);
        EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kems);
        EXPECT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);

        /* The "all" security policy contains both TLS 1.2 KEM extension and TLS 1.3 KEM SupportedGroup entries*/
        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("test_all", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_EQUAL(security_policy->kem_preferences->tls13_kem_groups, ALL_SUPPORTED_KEM_GROUPS);
        /* All supported kem groups should be in the preference list, but not all of them may be available. */
        EXPECT_EQUAL(S2N_KEM_GROUPS_COUNT, security_policy->kem_preferences->tls13_kem_group_count);
        uint32_t available_groups = 0;
        EXPECT_OK(s2n_kem_preferences_groups_available(security_policy->kem_preferences, &available_groups));
        if (s2n_libcrypto_supports_evp_kem() && s2n_is_evp_apis_supported()) {
            if (s2n_libcrypto_supports_mlkem()) {
                EXPECT_EQUAL(S2N_KEM_GROUPS_COUNT, available_groups);
            } else {
                EXPECT_EQUAL(6, available_groups);
            }
        } else if (s2n_libcrypto_supports_evp_kem() && !s2n_is_evp_apis_supported()) {
            if (s2n_libcrypto_supports_mlkem()) {
                EXPECT_EQUAL(5, available_groups);
            } else {
                EXPECT_EQUAL(4, available_groups);
            }
        } else {
            EXPECT_EQUAL(0, available_groups);
        }

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("KMS-TLS-1-0-2018-10", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("PQ-TLS-1-3-2023-06-01", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_pq_tls_1_3_2023_06);
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_NOT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(security_policy->kem_preferences->tls13_kem_groups, pq_kem_groups_r3_2023_06);
        /* All supported kem groups should be in the preference list, but not all of them may be available. */
        EXPECT_EQUAL(6, security_policy->kem_preferences->tls13_kem_group_count);
        EXPECT_OK(s2n_kem_preferences_groups_available(security_policy->kem_preferences, &available_groups));
        if (s2n_libcrypto_supports_evp_kem() && s2n_is_evp_apis_supported()) {
            EXPECT_EQUAL(6, available_groups);
        } else if (s2n_libcrypto_supports_evp_kem() && !s2n_is_evp_apis_supported()) {
            EXPECT_EQUAL(4, available_groups);
        } else {
            EXPECT_EQUAL(0, available_groups);
        }

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("20141001", &security_policy));
        EXPECT_FALSE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);

        security_policy = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("20201021", &security_policy));
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_EQUAL(0, security_policy->kem_preferences->kem_count);
        EXPECT_NULL(security_policy->kem_preferences->kems);
        EXPECT_NULL(security_policy->kem_preferences->tls13_kem_groups);
        EXPECT_EQUAL(0, security_policy->kem_preferences->tls13_kem_group_count);
    }

    {
        char tls12_only_security_policy_strings[][255] = {
            "default",
            "default_fips",
            "ELBSecurityPolicy-TLS-1-0-2015-04",
            "ELBSecurityPolicy-TLS-1-0-2015-05",
            "ELBSecurityPolicy-2016-08",
            "ELBSecurityPolicy-TLS-1-1-2017-01",
            "ELBSecurityPolicy-TLS-1-2-2017-01",
            "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
            "ELBSecurityPolicy-FS-2018-06",
            "ELBSecurityPolicy-FS-1-2-2019-08",
            "ELBSecurityPolicy-FS-1-1-2019-08",
            "ELBSecurityPolicy-FS-1-2-Res-2019-08",
            "CloudFront-Upstream",
            "CloudFront-Upstream-TLS-1-0",
            "CloudFront-Upstream-TLS-1-1",
            "CloudFront-Upstream-TLS-1-2",
            /* CloudFront legacy viewer facing policies (max TLS 1.2)  */
            "CloudFront-SSL-v-3-Legacy",
            "CloudFront-TLS-1-0-2014-Legacy",
            "CloudFront-TLS-1-0-2016-Legacy",
            "CloudFront-TLS-1-1-2016-Legacy",
            "CloudFront-TLS-1-2-2018-Legacy",
            "CloudFront-TLS-1-2-2019-Legacy",
            "KMS-TLS-1-0-2018-10",
            "KMS-FIPS-TLS-1-2-2018-10",
            "20140601",
            "20141001",
            "20150202",
            "20150214",
            "20150306",
            "20160411",
            "20160804",
            "20160824",
            "20170210",
            "20170328",
            "20190214",
            "20170405",
            "20170718",
            "20190120",
            "20190121",
            "20190122",
            "20201021",
            "20240331",
            "test_all_ecdsa",
            "test_ecdsa_priority",
            "test_all_tls12",
        };

        for (size_t i = 0; i < s2n_array_len(tls12_only_security_policy_strings); i++) {
            security_policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(tls12_only_security_policy_strings[i], &security_policy));
            EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));
        }

        char tls13_security_policy_strings[][255] = {
            "default_tls13",
            "test_all",
            "test_all_tls13",
            "20190801",
            "20190802",
            "KMS-TLS-1-2-2023-06",
            "20230317",
            /* CloudFront viewer facing */
            "CloudFront-SSL-v-3",
            "CloudFront-TLS-1-0-2014",
            "CloudFront-TLS-1-0-2016",
            "CloudFront-TLS-1-1-2016",
            "CloudFront-TLS-1-2-2017",
            "CloudFront-TLS-1-2-2018",
            "CloudFront-TLS-1-2-2019",
            "CloudFront-TLS-1-2-2021",
            "CloudFront-TLS-1-2-2021-ChaCha20-Boosted",
            /* AWS Common Runtime SDK */
            "AWS-CRT-SDK-SSLv3.0",
            "AWS-CRT-SDK-TLSv1.0",
            "AWS-CRT-SDK-TLSv1.1",
            "AWS-CRT-SDK-TLSv1.2",
            "AWS-CRT-SDK-TLSv1.3",
            "AWS-CRT-SDK-SSLv3.0-2023",
            "AWS-CRT-SDK-TLSv1.0-2023",
            "AWS-CRT-SDK-TLSv1.1-2023",
            "AWS-CRT-SDK-TLSv1.2-2023",
            "AWS-CRT-SDK-TLSv1.3-2023",
            /* PQ TLS */
            "PQ-TLS-1-2-2023-04-07",
            "PQ-TLS-1-2-2023-04-08",
            "PQ-TLS-1-2-2023-04-09",
            "PQ-TLS-1-2-2023-04-10",
            "PQ-TLS-1-3-2023-06-01",
            "PQ-TLS-1-2-2023-10-07",
            "PQ-TLS-1-2-2023-10-08",
            "PQ-TLS-1-2-2023-10-09",
            "PQ-TLS-1-2-2023-10-10",
        };
        for (size_t i = 0; i < s2n_array_len(tls13_security_policy_strings); i++) {
            security_policy = NULL;
            EXPECT_SUCCESS(s2n_find_security_policy_from_version(tls13_security_policy_strings[i], &security_policy));
            EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));
        }
    }

    /* Test that null fails */
    {
        security_policy = NULL;
        EXPECT_FALSE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_security_policy_supports_tls13(security_policy));
    }

    /* Test that security policies have valid chacha20 boosting configurations when chacha20 is available */
    if (s2n_chacha20_poly1305.is_available()) {
        for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
            const struct s2n_security_policy *sec_policy = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(sec_policy);
            const struct s2n_cipher_preferences *cipher_preference = sec_policy->cipher_preferences;
            EXPECT_NOT_NULL(cipher_preference);

            /* No need to check cipher preferences with chacha20 boosting disabled */
            if (!cipher_preference->allow_chacha20_boosting) {
                continue;
            }

            bool cipher_preferences_has_chacha20_cipher_suite = false;

            /* Iterate over cipher preferences and try to find a chacha20 ciphersuite */
            for (size_t j = 0; j < cipher_preference->count; j++) {
                struct s2n_cipher_suite *cipher = cipher_preference->suites[j];
                EXPECT_NOT_NULL(cipher);

                if (s2n_cipher_suite_uses_chacha20_alg(cipher)) {
                    cipher_preferences_has_chacha20_cipher_suite = true;
                    break;
                }
            }

            /* If chacha20 boosting support is enabled, then the cipher preference must have at least one chacha20 cipher suite */
            EXPECT_TRUE(cipher_preferences_has_chacha20_cipher_suite);
        }
    }

    /* Test a security policy not on the official list */
    {
        struct s2n_cipher_suite *fake_suites[] = {
            &s2n_tls13_chacha20_poly1305_sha256,
        };

        const struct s2n_cipher_preferences fake_cipher_preference = {
            .count = s2n_array_len(fake_suites),
            .suites = fake_suites,
        };

        const struct s2n_kem_preferences fake_kem_preference = {
            .kem_count = 1,
            .kems = NULL,
        };

        const struct s2n_security_policy fake_security_policy = {
            .minimum_protocol_version = S2N_TLS10,
            .cipher_preferences = &fake_cipher_preference,
            .kem_preferences = &fake_kem_preference,
        };

        security_policy = &fake_security_policy;
        EXPECT_TRUE(s2n_ecc_is_extension_required(security_policy));
        EXPECT_FALSE(s2n_pq_kem_is_extension_required(security_policy));
        EXPECT_TRUE(s2n_security_policy_supports_tls13(security_policy));
    }
    {
        struct s2n_config *config = s2n_config_new();

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20170210);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20190801"));
        EXPECT_EQUAL(config->security_policy, &security_policy_20190801);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "null"));
        EXPECT_EQUAL(config->security_policy, &security_policy_null);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_null);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_null);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_null);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all"));
        EXPECT_EQUAL(config->security_policy, &security_policy_test_all);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_test_all);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_all);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_all);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_test_all);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "test_all_tls12"));
        EXPECT_EQUAL(config->security_policy, &security_policy_test_all_tls12);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_test_all_tls12);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_pq_tls_1_0_2021_05);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20201021);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20201021);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-SSLv3.0"));
        EXPECT_EQUAL(config->security_policy, &security_policy_aws_crt_sdk_ssl_v3);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_aws_crt_sdk_ssl_v3);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-TLSv1.0"));
        EXPECT_EQUAL(config->security_policy, &security_policy_aws_crt_sdk_tls_10);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_aws_crt_sdk_default);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-TLSv1.1"));
        EXPECT_EQUAL(config->security_policy, &security_policy_aws_crt_sdk_tls_11);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_aws_crt_sdk_default);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-TLSv1.2"));
        EXPECT_EQUAL(config->security_policy, &security_policy_aws_crt_sdk_tls_12);
        EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_aws_crt_sdk_default);
        EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        if (s2n_is_tls13_fully_supported()) {
            EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-TLSv1.3"));
            EXPECT_EQUAL(config->security_policy, &security_policy_aws_crt_sdk_tls_13);
            EXPECT_EQUAL(config->security_policy->cipher_preferences, &cipher_preferences_aws_crt_sdk_tls_13);
            EXPECT_EQUAL(config->security_policy->kem_preferences, &kem_preferences_null);
            EXPECT_EQUAL(config->security_policy->signature_preferences, &s2n_signature_preferences_20200207);
            EXPECT_EQUAL(config->security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);
        } else {
            EXPECT_FAILURE(s2n_config_set_cipher_preferences(config, "AWS-CRT-SDK-TLSv1.3"));
        }

        EXPECT_FAILURE(s2n_config_set_cipher_preferences(config, NULL));

        EXPECT_FAILURE_WITH_ERRNO(s2n_config_set_cipher_preferences(config, "notathing"),
                S2N_ERR_INVALID_SECURITY_POLICY);

        s2n_config_free(config);
    }
    {
        struct s2n_config *config = s2n_config_new();

        struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
        s2n_connection_set_config(conn, config);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20170210"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20170210);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20170210);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20140601);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20140601);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "20190801"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_20190801);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_20190801);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_null);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20200207);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20200310);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_test_all);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_test_all);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_all);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_all);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_test_all);

        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "test_all_tls12"));
        EXPECT_SUCCESS(s2n_connection_get_security_policy(conn, &security_policy));
        EXPECT_EQUAL(security_policy, &security_policy_test_all_tls12);
        EXPECT_EQUAL(security_policy->cipher_preferences, &cipher_preferences_test_all_tls12);
        EXPECT_EQUAL(security_policy->kem_preferences, &kem_preferences_pq_tls_1_0_2021_05);
        EXPECT_EQUAL(security_policy->signature_preferences, &s2n_signature_preferences_20201021);
        EXPECT_EQUAL(security_policy->ecc_preferences, &s2n_ecc_preferences_20201021);

        EXPECT_FAILURE_WITH_ERRNO(s2n_connection_set_cipher_preferences(conn, "notathing"),
                S2N_ERR_INVALID_SECURITY_POLICY);

        s2n_config_free(config);
        s2n_connection_free(conn);
    }

    /* All signature preferences are valid */
    {
        for (int i = 0; security_policy_selection[i].version != NULL; i++) {
            security_policy = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(security_policy);
            EXPECT_NOT_NULL(security_policy->signature_preferences);

            for (int j = 0; j < security_policy->signature_preferences->count; j++) {
                const struct s2n_signature_scheme *scheme = security_policy->signature_preferences->signature_schemes[j];

                EXPECT_NOT_NULL(scheme);

                uint8_t max_version = scheme->maximum_protocol_version;
                uint8_t min_version = scheme->minimum_protocol_version;

                EXPECT_TRUE(max_version == S2N_UNKNOWN_PROTOCOL_VERSION || min_version <= max_version);

                /* If scheme will be used for tls1.3 */
                if (max_version == S2N_UNKNOWN_PROTOCOL_VERSION || max_version >= S2N_TLS13) {
                    EXPECT_NOT_EQUAL(scheme->hash_alg, S2N_HASH_SHA1);
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA);
                    if (scheme->sig_alg == S2N_SIGNATURE_ECDSA) {
                        EXPECT_NOT_NULL(scheme->signature_curve);
                    }
                }

                /* If scheme will be used for legacy versions */
                if (min_version < S2N_TLS12) {
                    EXPECT_NOT_EQUAL(scheme->sig_alg, S2N_SIGNATURE_RSA_PSS_PSS);
                }
            }
        }
    }

    /* Failure case when s2n_ecc_preference lists contains a curve not present in s2n_all_supported_curves_list */
    {
        const struct s2n_ecc_named_curve test_curve = {
            .iana_id = 12345,
            .libcrypto_nid = 0,
            .name = "test_curve",
            .share_size = 0
        };

        const struct s2n_ecc_named_curve *const s2n_ecc_pref_list_test[] = {
            &test_curve,
        };

        const struct s2n_ecc_preferences s2n_ecc_preferences_new_list = {
            .count = s2n_array_len(s2n_ecc_pref_list_test),
            .ecc_curves = s2n_ecc_pref_list_test,
        };

        EXPECT_FAILURE(s2n_check_ecc_preferences_curves_list(&s2n_ecc_preferences_new_list));
    }

    /* Positive and negative cases for s2n_validate_kem_preferences() */
    {
        EXPECT_FAILURE_WITH_ERRNO(s2n_validate_kem_preferences(NULL, 0), S2N_ERR_NULL);
        EXPECT_FAILURE_WITH_ERRNO(s2n_validate_kem_preferences(&kem_preferences_null, 1), S2N_ERR_INVALID_SECURITY_POLICY);
        EXPECT_SUCCESS(s2n_validate_kem_preferences(&kem_preferences_null, 0));

        const struct s2n_kem_preferences invalid_kem_prefs[] = {
            {
                    .kem_count = 1,
                    .kems = NULL,
                    .tls13_kem_group_count = 0,
                    .tls13_kem_groups = NULL,
            },
            {
                    .kem_count = 0,
                    .kems = NULL,
                    .tls13_kem_group_count = 1,
                    .tls13_kem_groups = NULL,
            },
            {
                    .kem_count = 0,
                    .kems = pq_kems_r3_2021_05,
                    .tls13_kem_group_count = 0,
                    .tls13_kem_groups = NULL,
            },
            {
                    .kem_count = 0,
                    .kems = NULL,
                    .tls13_kem_group_count = 0,
                    .tls13_kem_groups = kem_preferences_all.tls13_kem_groups,
            },
        };

        for (size_t i = 0; i < s2n_array_len(invalid_kem_prefs); i++) {
            EXPECT_FAILURE_WITH_ERRNO(s2n_validate_kem_preferences(&invalid_kem_prefs[i], 1), S2N_ERR_INVALID_SECURITY_POLICY);
        }

        EXPECT_SUCCESS(s2n_validate_kem_preferences(&kem_preferences_pq_tls_1_0_2021_05, 0));
    }

    /* Checks that NUM_RSA_PSS_SCHEMES accurately represents the number of rsa_pss signature schemes usable in a
     * certificate_signature_preferences list */
    {
        for (size_t i = 0; security_policy_selection[i].version != NULL; i++) {
            security_policy = security_policy_selection[i].security_policy;
            EXPECT_NOT_NULL(security_policy);

            if (security_policy->certificate_signature_preferences != NULL) {
                size_t num_rsa_pss = 0;
                for (size_t j = 0; j < security_policy->certificate_signature_preferences->count; j++) {
                    if (security_policy->certificate_signature_preferences->signature_schemes[j]->libcrypto_nid == NID_rsassaPss) {
                        num_rsa_pss += 1;
                    }
                }
                EXPECT_TRUE(num_rsa_pss <= NUM_RSA_PSS_SCHEMES);
            }
        }
    }

    /* s2n_validate_certificate_signature_preferences will succeed if there are no rsa_pss schemes in the preference list */
    {
        const struct s2n_signature_scheme *const test_sig_scheme_pref_list[] = {
            &s2n_rsa_pkcs1_sha256,
        };

        const struct s2n_signature_preferences test_certificate_signature_preferences = {
            .count = s2n_array_len(test_sig_scheme_pref_list),
            .signature_schemes = test_sig_scheme_pref_list,
        };

        EXPECT_OK(s2n_validate_certificate_signature_preferences(&test_certificate_signature_preferences));
    }

    /* s2n_validate_certificate_signature_preferences will succeed if all rsa_pss schemes are included in the preference list */
    {
        const struct s2n_signature_scheme *const test_sig_scheme_pref_list[] = {
            &s2n_rsa_pss_pss_sha256,
            &s2n_rsa_pss_pss_sha384,
            &s2n_rsa_pss_pss_sha512,
            &s2n_rsa_pss_rsae_sha256,
            &s2n_rsa_pss_rsae_sha384,
            &s2n_rsa_pss_rsae_sha512,
        };

        const struct s2n_signature_preferences test_certificate_signature_preferences = {
            .count = s2n_array_len(test_sig_scheme_pref_list),
            .signature_schemes = test_sig_scheme_pref_list,
        };

        EXPECT_OK(s2n_validate_certificate_signature_preferences(&test_certificate_signature_preferences));
    }

    /* s2n_validate_certificate_signature_preferences will fail if not all rsa_pss schemes are included in the preference list */
    {
        const struct s2n_signature_scheme *const test_sig_scheme_pref_list[] = {
            &s2n_rsa_pss_pss_sha256,
            &s2n_rsa_pss_pss_sha384,
        };

        const struct s2n_signature_preferences test_certificate_signature_preferences = {
            .count = s2n_array_len(test_sig_scheme_pref_list),
            .signature_schemes = test_sig_scheme_pref_list,
        };

        EXPECT_ERROR_WITH_ERRNO(s2n_validate_certificate_signature_preferences(&test_certificate_signature_preferences), S2N_ERR_INVALID_SECURITY_POLICY);
    }

    EXPECT_SUCCESS(s2n_reset_tls13_in_test());

    /* Test that security policies are compatible with other policies */
    {
        /* 20230317 */
        {
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default_tls13", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default_fips", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "20230317", rsa_chain_and_key));

            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default_tls13", ecdsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default_fips", ecdsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "20230317", ecdsa_chain_and_key));

            if (s2n_is_rsa_pss_certs_supported()) {
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "default_tls13", rsa_pss_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317, "20230317", rsa_pss_chain_and_key));
            }

            if (s2n_is_tls13_fully_supported()) {
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317,
                        "test_all_tls13", rsa_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317,
                        "test_all_tls13", rsa_pss_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20230317,
                        "test_all_tls13", ecdsa_chain_and_key));
            }
        };

        /* 20240331 */
        {
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "default", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "default_tls13", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "default_fips", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "20230317", rsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "20240331", rsa_chain_and_key));

            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "default_tls13", ecdsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "default_fips", ecdsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "20230317", ecdsa_chain_and_key));
            EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240331,
                    "20240331", ecdsa_chain_and_key));

            /* Can't negotiate TLS1.3 */
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_test_security_policies_compatible(&security_policy_20240331,
                            "test_all_tls13", rsa_chain_and_key),
                    S2N_ERR_CIPHER_NOT_SUPPORTED);
            EXPECT_ERROR_WITH_ERRNO(
                    s2n_test_security_policies_compatible(&security_policy_20240331,
                            "test_all_tls13", ecdsa_chain_and_key),
                    S2N_ERR_CIPHER_NOT_SUPPORTED);
        };

        /* We know of customers that expect to move between the policies in
         * this section without multi-phased rollouts, so avoid inadvertant
         * breakage by verifying compatibility.
         */
        if (s2n_is_tls13_fully_supported()) {
            /* 20250211 */
            {
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "default_tls13", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "default_fips", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "20250211", ecdsa_sha384_chain_and_key));

                /* default_tls13 is currently 20240503 */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240503, "rfc9151", ecdsa_sha384_chain_and_key));
                /* default_fips is currently 20240502 */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240502, "rfc9151", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20250211, "rfc9151", ecdsa_sha384_chain_and_key));

                /* default_tls13 > 20250211
                */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240503, "20250211", ecdsa_chain_and_key));

                /* note this ended up requiring a sha384 key, fixed in 20250414. */
                EXPECT_ERROR_WITH_ERRNO(s2n_test_security_policies_compatible(&security_policy_20240503, "20250211", ecdsa_sha256_chain_and_key),
                        S2N_ERR_NO_VALID_SIGNATURE_SCHEME);
            };

            /* 20250414 */
            {
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "default_tls13", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "default_fips", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_rfc9151, "20250414", ecdsa_sha384_chain_and_key));

                /* default_tls13 is currently 20240503 */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240503, "rfc9151", ecdsa_sha384_chain_and_key));
                /* default_fips is currently 20240502 */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240502, "rfc9151", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20250414, "rfc9151", ecdsa_sha384_chain_and_key));

                /* default_tls13 > 20250414 (with either p-256 or p-384 cert) */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240503, "20250414", ecdsa_sha384_chain_and_key));
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20240503, "20250414", ecdsa_sha256_chain_and_key));

                /* 20250211 > 20250414 (with p-384 cert only) */
                EXPECT_OK(s2n_test_security_policies_compatible(&security_policy_20250211, "20250414", ecdsa_sha384_chain_and_key));
            };
        };
    };

    /* Sanity check that changes to default security policies are not completely
     * backwards incompatible.
     *
     * If we get into a situation where the current default has NO options in
     * common with a past version of the default, then updating s2n-tls becomes
     * very dangerous. Fleets with a mix of the old default and the new default
     * may be unable to communicate.
     *
     * This check only performs one basic handshake, so isn't exhaustive.
     */
    {
        /* "default" */
        {
            const struct s2n_security_policy *versioned_policies[] = {
                &security_policy_20170210,
                &security_policy_20240501,
            };

            const struct s2n_supported_cert supported_certs[] = {
                { .cert = rsa_chain_and_key },
                { .cert = ecdsa_chain_and_key, .start_index = 1 },
            };

            EXPECT_OK(s2n_test_default_backwards_compatible("default",
                    versioned_policies, s2n_array_len(versioned_policies),
                    supported_certs, s2n_array_len(supported_certs)));
        };

        /* "default_tls13" */
        if (s2n_is_rsa_pss_certs_supported()) {
            const struct s2n_security_policy *versioned_policies[] = {
                &security_policy_20240417,
                &security_policy_20240503,
            };

            const struct s2n_supported_cert supported_certs[] = {
                { .cert = rsa_chain_and_key },
                { .cert = ecdsa_chain_and_key },
                { .cert = rsa_pss_chain_and_key },
            };

            EXPECT_OK(s2n_test_default_backwards_compatible("default_tls13",
                    versioned_policies, s2n_array_len(versioned_policies),
                    supported_certs, s2n_array_len(supported_certs)));
        };

        /* "default_fips" */
        {
            const struct s2n_security_policy *versioned_policies[] = {
                &security_policy_20240416,
                &security_policy_20240502,
            };

            const struct s2n_supported_cert supported_certs[] = {
                { .cert = rsa_chain_and_key },
                { .cert = ecdsa_chain_and_key },
            };

            EXPECT_OK(s2n_test_default_backwards_compatible("default_fips",
                    versioned_policies, s2n_array_len(versioned_policies),
                    supported_certs, s2n_array_len(supported_certs)));
        };
    };

    /* Test that default_pq always matches default_tls13 */
    {
        const struct s2n_security_policy *default_pq = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_pq", &default_pq));
        EXPECT_NOT_EQUAL(default_pq->kem_preferences, &kem_preferences_null);

        const struct s2n_security_policy *default_tls13 = NULL;
        EXPECT_SUCCESS(s2n_find_security_policy_from_version("default_tls13", &default_tls13));
        EXPECT_EQUAL(default_tls13->kem_preferences, &kem_preferences_null);

        /* Except for PQ algorithms, the two policies should match */

        /* Most fields can be compared directly. We just ignore kem_preferences. */
        EXPECT_EQUAL(default_pq->minimum_protocol_version, default_tls13->minimum_protocol_version);
        EXPECT_EQUAL(default_pq->cipher_preferences, default_tls13->cipher_preferences);
        EXPECT_EQUAL(default_pq->ecc_preferences, default_tls13->ecc_preferences);
        EXPECT_EQUAL(default_pq->certificate_key_preferences, default_tls13->certificate_key_preferences);
        EXPECT_EQUAL(default_pq->certificate_preferences_apply_locally,
                default_tls13->certificate_preferences_apply_locally);

        /* The signature preferences match,
         * EXCEPT for the added PQ algorithms, which should come first.
         */
        {
            const struct s2n_signature_preferences *pq_sig_prefs = default_pq->signature_preferences;
            const struct s2n_signature_preferences *tls13_sig_prefs = default_tls13->signature_preferences;

            /* Count how many PQ sig schemes */
            size_t pq_count = 0;
            while (pq_count < pq_sig_prefs->count) {
                if (pq_sig_prefs->signature_schemes[pq_count]->sig_alg
                        == S2N_SIGNATURE_MLDSA) {
                    pq_count++;
                } else {
                    break;
                }
            }
            EXPECT_TRUE(pq_count > 0);

            /* Compare the two preference lists, minus the PQ sig schemes */
            EXPECT_EQUAL(pq_sig_prefs->count - pq_count, tls13_sig_prefs->count);
            for (size_t i = 0; i < default_tls13->signature_preferences->count; i++) {
                EXPECT_EQUAL(pq_sig_prefs->signature_schemes[i + pq_count],
                        tls13_sig_prefs->signature_schemes[i]);
            }
        }

        /* The certificate signature preferences match,
         * EXCEPT for the added PQ algorithms, which should come first.
         */
        {
            const struct s2n_signature_preferences *pq_sig_prefs = default_pq->certificate_signature_preferences;
            const struct s2n_signature_preferences *tls13_sig_prefs = default_tls13->certificate_signature_preferences;

            /* Count how many PQ sig schemes */
            size_t pq_count = 0;
            while (pq_count < pq_sig_prefs->count) {
                if (pq_sig_prefs->signature_schemes[pq_count]->sig_alg
                        == S2N_SIGNATURE_MLDSA) {
                    pq_count++;
                } else {
                    break;
                }
            }
            EXPECT_TRUE(pq_count > 0);

            /* Compare the two preference lists, minus the PQ sig schemes */
            EXPECT_EQUAL(pq_sig_prefs->count - pq_count, tls13_sig_prefs->count);
            for (size_t i = 0; i < default_tls13->signature_preferences->count; i++) {
                EXPECT_EQUAL(pq_sig_prefs->signature_schemes[i + pq_count],
                        tls13_sig_prefs->signature_schemes[i]);
            }
        }
    };

    END_TEST();
}
