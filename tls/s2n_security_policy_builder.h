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

struct s2n_security_policy;

typedef enum {
    S2N_POLICY_STRICT,
    S2N_POLICY_COMPATIBLE,
    S2N_POLICY_LEGACY,
} s2n_base_policy;

typedef enum {
    S2N_STRICT_2025_1 = 1,
    S2N_STRICT_LATEST_V1 = S2N_STRICT_2025_1,
} s2n_strict_policy_version;

typedef enum {
    S2N_COMPAT_2024_1 = 1,
    S2N_COMPAT_2024_2,
    S2N_COMPAT_2025_1, 
    S2N_COMPAT_LATEST_V1 = S2N_COMPAT_2025_1,
} s2n_compat_policy_version;

typedef enum {
    S2N_LEGACY_2025_1 = 1,
    S2N_LEGACY_LATEST_V1 = S2N_LEGACY_2025_1,
} s2n_legacy_policy_version;

const struct s2n_security_policy* s2n_security_policy_get(s2n_base_policy policy, uint64_t version);

int s2n_config_set_security_policy(struct s2n_config *config, const struct s2n_security_policy *policy);
int s2n_connection_set_security_policy(struct s2n_connection *conn, const struct s2n_security_policy *policy);