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

#include <sys/param.h>

#include "api/s2n.h"
#include "utils/s2n_blob.h"
#include "utils/s2n_result.h"
#include "utils/s2n_safety.h"

#define S2N_POLICY_MIN_TLS_VERSION   S2N_SSLv3
#define S2N_POLICY_MAX_TLS_VERSION   S2N_TSL13
#define S2N_POLICY_TLS_VERSION_COUNT (S2N_POLICY_MAX_TLS_VERSION - S2N_POLICY_MIN_TLS_VERSION)

#define S2N_CIPHER_SUITES_COUNT 100

typedef enum {
    S2N_SECURITY_PERFECT_FORWARD_SECRECY = 0,
    S2N_SECURITY_FIPS,
    S2N_SECURITY_RFC9151,
    S2N_SECURITY_RULE_COUNT
} s2n_security_rule;

typedef enum {
    S2N_POLICY_KEY_EXCHANGE = 0,
    S2N_POLICY_AUTHENTICATION,
    S2N_POLICY_CIPHER,
    S2N_POLICY_CIPHER_MODE,
    S2N_POLICY_SIGNATURE_PADDING,
    S2N_POLICY_SIGNATURE_HASH,
    S2N_POLICY_ECC_CURVE,
    S2N_POLICY_OPTION_TYPE_COUNT
} s2n_policy_option_type;

typedef enum {
    S2N_POLICY_OPTION_NONE = 0,

    S2N_POLICY_VERSION_TLS10,
    S2N_POLICY_VERSION_TLS11,
    S2N_POLICY_VERSION_TLS12,
    S2N_POLICY_VERSION_TLS13,

    S2N_POLICY_KEX_RSA,
    S2N_POLICY_KEX_ECDHE,

    S2N_POLICY_AUTH_RSA,
    S2N_POLICY_AUTH_ECDSA,
    S2N_POLICY_AUTH_RSA_PSS,

    S2N_POLICY_CIPHER_AES128,
    S2N_POLICY_CIPHER_AES256,
    S2N_POLICY_CIPHER_CHACHA20_POLY1305,

    S2N_POLICY_CIPHER_MODE_CBC_SHA,
    S2N_POLICY_CIPHER_MODE_CBC_SHA256,
    S2N_POLICY_CIPHER_MODE_GCM,

    S2N_POLICY_SIG_PADDING_PCKS11,
    S2N_POLICY_SIG_PADDING_PSS,

    S2N_POLICY_SIG_HASH_SHA1,
    S2N_POLICY_SIG_HASH_SHA224,
    S2N_POLICY_SIG_HASH_SHA256,
    S2N_POLICY_SIG_HASH_SHA384,
    S2N_POLICY_SIG_HASH_SHA512,

    S2N_POLICY_CURVE_X25519,
    S2N_POLICY_CURVE_SECP256R1,
    S2N_POLICY_CURVE_SECP384R1,
    S2N_POLICY_CURVE_SECP512R1,

    S2N_POLICY_OPTION_COUNT
} s2n_policy_option;

typedef enum {
    S2N_REQ_IGNORE = 0,
    S2N_REQ_ALLOW,
    S2N_REQ_REQUIRE,
    S2N_REQ_FORBID,
} s2n_policy_action;

struct s2n_policy_entry {
    s2n_policy_option option;
    s2n_policy_option_type type;
    s2n_policy_action req;
};

struct s2n_security_policy_builder {
    struct s2n_policy_entry versions[S2N_POLICY_OPTION_COUNT];
    struct s2n_policy_entry ciphers[S2N_POLICY_OPTION_COUNT];
    struct s2n_policy_entry signatures[S2N_POLICY_OPTION_COUNT];
    struct s2n_policy_entry curves[S2N_POLICY_OPTION_COUNT];

    bool rules[S2N_SECURITY_RULE_COUNT];
};

typedef struct s2n_security_policy_builder s2n_policy_builder;

const s2n_policy_builder builder_v0 = {
    .minimum_version = S2N_TLS12,
    .maximum_version = S2N_TLS13,
    .versions = {
            { .option = S2N_TLS13, .req = S2N_REQ_ALLOW },
            { .option = S2N_TLS12, .req = S2N_REQ_ALLOW },
            { .option = S2N_TLS11, .req = S2N_REQ_IGNORE },
            { .option = S2N_TLS10, .req = S2N_REQ_IGNORE },
            { .option = S2N_SSLv3, .req = S2N_REQ_IGNORE },
    },
    .ciphers = {
            { .type = S2N_POLICY_KEY_EXCHANGE, .option = S2N_POLICY_KEX_ECDHE, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_CIPHER_MODE, .option = S2N_POLICY_CIPHER_MODE_GCM, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_CIPHER, .option = S2N_POLICY_CIPHER_AES128, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_ECDSA, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_RSA_PSS, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_RSA, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_CIPHER, .option = S2N_POLICY_CIPHER_AES256, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_CIPHER, .option = S2N_POLICY_CIPHER_CHACHA20_POLY1305, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_CIPHER_MODE, .option = S2N_POLICY_CIPHER_MODE_CBC_SHA256, .req = S2N_REQ_IGNORE },
            { .type = S2N_POLICY_CIPHER_MODE, .option = S2N_POLICY_CIPHER_MODE_CBC_SHA, .req = S2N_REQ_IGNORE },
            { .type = S2N_POLICY_KEY_EXCHANGE, .option = S2N_POLICY_KEX_RSA, .req = S2N_REQ_IGNORE },
    },
    .signatures = {
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_ECDSA, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_RSA_PSS, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_AUTHENTICATION, .option = S2N_POLICY_AUTH_RSA, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_PADDING, .option = S2N_POLICY_SIG_PADDING_PSS, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_PADDING, .option = S2N_POLICY_SIG_PADDING_PCKS11, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_HASH, .option = S2N_POLICY_SIG_HASH_SHA256, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_HASH, .option = S2N_POLICY_SIG_HASH_SHA384, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_HASH, .option = S2N_POLICY_SIG_HASH_SHA512, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_HASH, .option = S2N_POLICY_SIG_HASH_SHA224, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_SIGNATURE_HASH, .option = S2N_POLICY_SIG_HASH_SHA1, .req = S2N_REQ_IGNORE },
    },
    .curves = {
            { .type = S2N_POLICY_ECC_CURVE, .option = S2N_POLICY_CURVE_X25519, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_ECC_CURVE, .option = S2N_POLICY_CURVE_SECP256R1, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_ECC_CURVE, .option = S2N_POLICY_CURVE_SECP384R1, .req = S2N_REQ_ALLOW },
            { .type = S2N_POLICY_ECC_CURVE, .option = S2N_POLICY_CURVE_SECP512R1, .req = S2N_REQ_ALLOW },
    },
};

static bool s2n_policy_action_is_ok(s2n_policy_action action)
{
    return (action == S2N_REQ_ALLOW) || (action == S2N_REQ_REQUIRE);
}

static S2N_RESULT s2n_criteria_get_match(s2n_policy_option criteria[S2N_POLICY_OPTION_TYPE_COUNT],
        uint8_t version, struct s2n_cipher_suite **cipher_suite)
{
    for (size_t i = 0; i < S2N_POLICY_OPTION_TYPE_COUNT; i++) {
        if (criteria[i] == S2N_POLICY_OPTION_NONE) {
            return S2N_RESULT_OK;
        }
    }

    for (size_t i = 0; i < cipher_preferences_test_all.count; i++) {
        struct s2n_cipher_suite *candidate = cipher_preferences_test_all.suites[i];

        if ((version >= S2N_TLS13) != (candidate->minimum_required_tls_version >= S2N_TLS13)) {
            continue;
        }

        struct s2n_kex *kex = NULL;
        switch (criteria[S2N_POLICY_KEY_EXCHANGE]) {
            case S2N_POLICY_KEX_ECDHE:
                kex = &s2n_ecdhe;
                break;
            case S2N_POLICY_KEX_RSA:
                kex = &s2n_rsa;
                break;
        }
        if (candidate->key_exchange_alg && kex != candidate->key_exchange_alg) {
            continue;
        }

        s2n_authentication_method auth = S2N_AUTHENTICATION_METHOD_SENTINEL;
        switch (criteria[S2N_POLICY_AUTHENTICATION]) {
            case S2N_POLICY_AUTH_ECDSA:
                auth = S2N_AUTHENTICATION_ECDSA;
                break;
            case S2N_POLICY_AUTH_RSA:
                auth = S2N_AUTHENTICATION_RSA;
                break;
        }
        if (candidate->auth_method != S2N_AUTHENTICATION_METHOD_SENTINEL
                && auth != candidate->auth_method) {
            continue;
        }

        s2n_policy_option cipher = S2N_POLICY_OPTION_NONE;
        switch (candidate->record_alg->cipher) {
            case s2n_aes128:
            case s2n_aes128_gcm:
            case s2n_aes128_sha:
            case s2n_aes128_sha256:
            case s2n_tls13_aes128_gcm:
                cipher = S2N_POLICY_CIPHER_AES128;
                break;
            case s2n_aes256:
            case s2n_aes256_gcm:
            case s2n_aes256_sha:
            case s2n_aes256_sha256:
            case s2n_tls13_aes256_gcm:
                cipher = S2N_POLICY_CIPHER_AES256;
                break;
            case s2n_chacha20_poly1305:
                cipher = S2N_POLICY_CIPHER_CHACHA20_POLY1305;
                break;
        }
        if (criteria[S2N_POLICY_CIPHER] != cipher) {
            continue;
        }

        s2n_policy_option mode = S2N_POLICY_OPTION_NONE;
        switch (candidate->record_alg->cipher) {
            case s2n_aes128_sha:
            case s2n_aes256_sha:
                mode = S2N_POLICY_CIPHER_MODE_CBC_SHA;
                break;
            case s2n_aes128_sha256:
            case s2n_aes256_sha256:
                mode = S2N_POLICY_CIPHER_MODE_CBC_SHA256;
                break;
            case s2n_aes128:
            case s2n_aes256:
                if (candidate->record_alg->hmac_alg == S2N_HMAC_SHA256) {
                    mode = S2N_POLICY_CIPHER_MODE_CBC_SHA256;
                } else {
                    mode = S2N_POLICY_CIPHER_MODE_CBC_SHA;
                }
                break;
            case s2n_aes128_gcm:
            case s2n_aes256_gcm:
            case s2n_tls13_aes128_gcm:
            case s2n_tls13_aes256_gcm:
                mode = S2N_POLICY_CIPHER_MODE_GCM;
                break;
        }
        if (mode != S2N_POLICY_OPTION_NONE && criteria[S2N_POLICY_CIPHER_MODE] != mode) {
            continue;
        }

        *cipher_suite = candidate;
        return S2N_RESULT_OK;
    }

    *cipher_suite = NULL;
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_cipher_preferences_build(s2n_policy_builder *builder,
        struct s2n_cipher_preferences **result)
{
    DEFER_CLEANUP(struct s2n_cipher_preferences *prefs = *result, s2n_cipher_preferences_free);

    struct s2n_blob pref_mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&pref_mem, sizeof(struct s2n_cipher_preferences)));
    *result = (struct s2n_cipher_preferences *) (void *) pref_mem->data;

    struct s2n_cipher_suite *ciphers[S2N_CIPHER_SUITES_COUNT] = { 0 };
    size_t ciphers_count = 0;

    for (size_t i = 0; i < S2N_POLICY_OPTION_COUNT; i++) {
        if (s2n_policy_action_is_ok(builder->ciphers[i].req)) {
            continue;
        }

        s2n_policy_option option = builder->ciphers[i].option;
        if (option == S2N_POLICY_OPTION_NONE) {
            break;
        }

        s2n_policy_option_type type = builder->ciphers[i].type;
        s2n_policy_option criteria[S2N_POLICY_OPTION_TYPE_COUNT] = { [type] = option };

        for (size_t j = 0; j < i; j++) {
            if (s2n_policy_action_is_ok(builder->ciphers[i].req)) {
                continue;
            }

            if (type == builder->ciphers[j].type) {
                continue;
            }

            criteria[builder->ciphers[j].type] = builder->ciphers[j].option;
            RESULT_GUARD(s2n_criteria_get_match(criteria, &ciphers[ciphers_count]));
            if (&ciphers[ciphers_count]) {
                ciphers_count++;
            }
        }
    }

    return S2N_RESULT_OK;
}

S2N_RESULT s2n_signature_preferences_build(s2n_policy_builder *builder,
        struct s2n_cipher_preferences **result)
{
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_ecc_preferences_build(s2n_policy_builder *builder,
        struct s2n_ecc_preferences **result)
{
    return S2N_RESULT_OK;
}

S2N_RESULT s2n_security_policy_build_impl(s2n_policy_builder *builder,
        struct s2n_security_policy **result)
{
    struct s2n_blob policy_mem = { 0 };
    RESULT_GUARD_POSIX(s2n_alloc(&policy_mem, sizeof(struct s2n_security_policy)));
    DEFER_CLEANUP(struct s2n_security_policy *policy = (struct s2n_security_policy *) (void *) policy_mem->data,
            s2n_security_policy_free);

    struct s2n_cipher_preferences *cipher_prefs = NULL;
    RESULT_GUARD(s2n_cipher_preferences_build(builder, &cipher_prefs));
    policy->cipher_preferences = cipher_prefs;

    struct s2n_signature_preferences *sig_prefs = NULL;
    RESULT_GAURD(s2n_signature_preferences_build(builder, &sig_prefs));
    policy->signature_preferences = sig_prefs;

    struct s2n_ecc_preferences *ecc_prefs = NULL;
    RESULT_GAURD(s2n_ecc_preferences_build(builder, &sig_prefs));
    policy->ecc_preferences = ecc_prefs;

    return S2N_RESULT_OK;
}

struct s2n_policy_builder *s2n_security_policy_builder_new(const char *version)
{
    return NULL;
}

S2N_CLEANUP_RESULT s2n_security_policy_free(struct s2n_security_policy **policy)
{
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_cipher_preferences_free(struct s2n_cipher_preferences **policy)
{
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_signature_preferences_free(struct s2n_cipher_preferences **policy)
{
    return S2N_RESULT_OK;
}

S2N_CLEANUP_RESULT s2n_ecc_preferences_free(struct s2n_cipher_preferences **policy)
{
    return S2N_RESULT_OK;
}

int s2n_security_policy_enable_rule(s2n_policy_builder *builder, s2n_security_rule rule)
{
    POSIX_ENSURE_REF(builder);
    POSIX_ENSURE(rule >= 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(rule < S2N_SECURITY_RULE_COUNT, S2N_ERR_INVALID_ARGUMENT);
    builder->rules[rule] = true;
    return S2N_SUCCESS;
}

int s2n_security_policy_disable_rule(s2n_policy_builder *builder, s2n_security_rule rule)
{
    POSIX_ENSURE_REF(builder);
    POSIX_ENSURE(rule >= 0, S2N_ERR_INVALID_ARGUMENT);
    POSIX_ENSURE(rule < S2N_SECURITY_RULE_COUNT, S2N_ERR_INVALID_ARGUMENT);
    builder->rules[rule] = false;
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_policy_entry_require(struct s2n_policy_entry *entry)
{
    POSIX_ENSURE(entry->req != S2N_REQ_FORBID, S2N_ERR_INVALID_ARGUMENT);
    entry->req = S2N_REQ_REQUIRE;
    return S2N_RESULT_OK;
}

int s2n_security_policy_require(s2n_policy_builder *builder, s2n_policy_option option)
{
    POSIX_ENSURE_REF(builder);
    for (size_t i = 0; i < S2N_POLICY_OPTION_COUNT; i++) {
        if (builder->versions[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_require(&builder->ciphers[i]));
        }
        if (builder->ciphers[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_require(&builder->ciphers[i]));
        }
        if (builder->signatures[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_require(&builder->signatures[i]));
        }
        if (builder->curves[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_require(&builder->curves[i]));
        }
    }
    return S2N_SUCCESS;
}

static S2N_RESULT s2n_policy_entry_forbid(struct s2n_policy_entry *entry)
{
    POSIX_ENSURE(entry->req != S2N_REQ_REQUIRE, S2N_ERR_INVALID_ARGUMENT);
    entry->req = S2N_REQ_FORBID;
    return S2N_RESULT_OK;
}

int s2n_security_policy_forbid(s2n_policy_builder *builder, s2n_policy_option option)
{
    POSIX_ENSURE_REF(builder);
    for (size_t i = 0; i < S2N_POLICY_OPTION_COUNT; i++) {
        if (builder->versions[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_forbid(&builder->ciphers[i]));
        }
        if (builder->ciphers[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_forbid(&builder->ciphers[i]));
        }
        if (builder->signatures[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_forbid(&builder->signatures[i]));
        }
        if (builder->curves[i].option == option) {
            POSIX_GUARD_RESULT(s2n_policy_entry_forbid(&builder->curves[i]));
        }
    }
    return S2N_SUCCESS;
}

struct s2n_security_policy *s2n_security_policy_build(s2n_policy_builder *builder)
{
    struct s2n_security_policy *policy = NULL;
    PTR_GUARD_RESULT(s2n_security_policy_build_impl(builder, &policy));
    return policy;
}
