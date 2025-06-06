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

#include "crypto/s2n_libcrypto.h"

#include "s2n_test.h"
#include "utils/s2n_random.h"

int main(int argc, char** argv)
{
    BEGIN_TEST();

    const char* env_libcrypto = getenv("S2N_LIBCRYPTO");
    if (env_libcrypto == NULL) {
        END_TEST();
    }

    /* Confirm "S2N_LIBCRYPTO" env variable matches the linked libcrypto. */
    if (strstr(env_libcrypto, "awslc") != NULL) {
        EXPECT_TRUE(s2n_libcrypto_is_awslc());
        EXPECT_FALSE(s2n_libcrypto_is_boringssl());
        EXPECT_FALSE(s2n_libcrypto_is_libressl());
        EXPECT_FALSE(s2n_libcrypto_is_openssl());
    } else if (strcmp(env_libcrypto, "boringssl") == 0) {
        EXPECT_FALSE(s2n_libcrypto_is_awslc());
        EXPECT_TRUE(s2n_libcrypto_is_boringssl());
        EXPECT_FALSE(s2n_libcrypto_is_libressl());
        EXPECT_FALSE(s2n_libcrypto_is_openssl());
    } else if (strcmp(env_libcrypto, "libressl") == 0) {
        EXPECT_FALSE(s2n_libcrypto_is_awslc());
        EXPECT_FALSE(s2n_libcrypto_is_boringssl());
        EXPECT_TRUE(s2n_libcrypto_is_libressl());
        EXPECT_FALSE(s2n_libcrypto_is_openssl());
    } else if (strstr(env_libcrypto, "openssl") != NULL) {
        EXPECT_FALSE(s2n_libcrypto_is_awslc());
        EXPECT_FALSE(s2n_libcrypto_is_boringssl());
        EXPECT_FALSE(s2n_libcrypto_is_libressl());
        EXPECT_TRUE(s2n_libcrypto_is_openssl());
    } else if (strcmp(env_libcrypto, "default") == 0) {
        /* running with the default libcrypto on path */
    } else {
        FAIL_MSG("Testing with an unexpected libcrypto.");
    }

    /* Ensure that custom rand is not enabled for OpenSSL 1.0.2 Fips to match
     * historical behavior 
     */
    if (strcmp("openssl-1.0.2-fips", env_libcrypto) == 0) {
        EXPECT_FALSE(s2n_supports_custom_rand());
    }

    /* We expect openssl-3.0 to support providers */
    if (strstr(env_libcrypto, "openssl") && strstr(env_libcrypto, "3")) {
        EXPECT_TRUE(s2n_libcrypto_supports_providers());
    }

    END_TEST();
}
