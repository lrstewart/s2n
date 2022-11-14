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

#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <sys/param.h>

#include "api/s2n.h"

#include "testlib/s2n_testlib.h"

#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_safety_macros.h"
#include "crypto/s2n_hmac.h"

/*
 * This test has some complex math,
 * so printing the intermediary steps or raw data can help with debugging.
 */
enum s2n_debug_lvl {
    DEBUG_LVL_NONE = 0,
    DEBUG_LVL_SUMMARY,
    DEBUG_LVL_FAILURES,
    DEBUG_LVL_RESULTS,
    DEBUG_LVL_MATH,
    DEBUG_LVL_DATA,
};
#define DEBUG_LEVEL DEBUG_LVL_FAILURES
#define TEST_PRINT(level, ...) \
    if (level <= DEBUG_LEVEL) { \
        (void) fprintf(stdout, __VA_ARGS__); \
    }

/*
 * We choose an arbitrary but fairly large number.
 */
#define DATA_POINT_COUNT 1000

/*
 * How many times to run the tests.
 * These tests are prone to occasional false positives
 * due to noise in the measurements.
 */
#define TEST_RUNS 50

/*
 * Divide the standard CLOCKS_PER_SEC constant by
 * the number of microseconds in a second (1^6).
 */
#define CLOCKS_PER_USEC (CLOCKS_PER_SEC / 1000000)

/*
 * Placeholder key used in HMAC operations
 */
const uint8_t key[] = "arbitrary key";

typedef int (*target_fn)(struct s2n_connection*, struct s2n_hmac_state*, struct s2n_blob*);

/*
 * There are two Lucky 13 papers relevant to this test:
 *
 * The original paper: "Lucky Thirteen: Breaking the TLS and DTLS Record Protocols"
 * Nadhem J. AlFardan and Kenneth G. Paterson
 * http://www.isg.rhul.ac.uk/tls/TLStiming.pdf
 * This describes the general Lucky 13 attack.
 *
 * The updated paper: "Lucky Microseconds: A Timing Attack on Amazon’s s2n Implementation of TLS"
 * Martin R. Albrecht and Kenneth G. Paterson
 * https://eprint.iacr.org/2015/1129.pdf
 * This describes an updated attack specifically tailored to s2n-tls.
 *
 * Each paper describes two "cases". The original paper also describes a third case,
 * but that case is equivalent to Case 1 in s2n-tls's implementation.
 *
 * The difference between the timings of the "cases" is the basis for the Lucky 13 attack.
 */

enum s2n_case_id {
    S2N_CASE_1 = 0,
    S2N_CASE_2,
    S2N_CASE_COUNT,
};

struct s2n_scenario {
    const char *name;
    s2n_hmac_algorithm hmac_alg;
    size_t plaintext_len;
    uint8_t padding_cases[S2N_CASE_COUNT];
};

/* See page 7 of "Lucky Thirteen" */
const struct s2n_scenario original_scenario = {
    .name = "Original",
    .hmac_alg = S2N_HMAC_SHA1,
    .plaintext_len = 64,
    .padding_cases  = { 0x00, 0x01 },
};

/* See page 9 of "Lucky Microseconds */
const struct s2n_scenario updated_scenario = {
    .name = "Updated",
    .hmac_alg = S2N_HMAC_SHA256,
    .plaintext_len = 80,
    .padding_cases  = { 0x00, 0x05 },
};

const struct s2n_scenario *scenarios[] = { &original_scenario, &updated_scenario };

struct s2n_data {
    uint64_t datapoints[DATA_POINT_COUNT];
    size_t datapoints_size;
};

struct s2n_data_set {
    const char *name;
    const struct s2n_scenario *scenario;
    target_fn target;
    struct s2n_blob *plaintexts;
    struct s2n_data data[S2N_CASE_COUNT];
};

inline static uint64_t rdtsc(){
    unsigned int bot, top;
    __asm__ __volatile__ ("rdtsc" : "=a" (bot), "=d" (top));
    return ((uint64_t) top << 32) | bot;
}

static int s2n_u64cmp(const void *left, const void *right)
{
   if (*(const uint64_t *)left > *(const uint64_t *)right) return 1;
   if (*(const uint64_t *)left < *(const uint64_t *)right) return -1;
   return 0;
}

/*
 * A version of s2n_verify_cbc that deliberately removes some of the Lucky 13 countermeasures.
 *
 * Copying a function is not ideal, but it does let us test a known failure case.
 * We can remove that portion of the test if this method proves too difficult to maintain.
 *
 * This method should be a copy/paste of s2n_verify_cbc with:
 * - s2n_hmac_digest_two_compression_rounds replaced with a basic s2n_hmac_digest
 * - The extra hmac updates for the padding removed
 * - currently_in_hash_block, since it will no longer be used.
 */
static int s2n_bad_verify_cbc(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted)
{
    uint8_t mac_digest_size = 0;
    POSIX_GUARD(s2n_hmac_digest_size(hmac->alg, &mac_digest_size));

    /* The record has to be at least big enough to contain the MAC,
     * plus the padding length byte */
    POSIX_ENSURE_GT(decrypted->size, mac_digest_size);

    int payload_and_padding_size = decrypted->size - mac_digest_size;

    /* Determine what the padding length is */
    uint8_t padding_length = decrypted->data[decrypted->size - 1];

    int payload_length = MAX(payload_and_padding_size - padding_length - 1, 0);

    /* Update the MAC */
    POSIX_GUARD(s2n_hmac_update(hmac, decrypted->data, payload_length));

    /* Check the MAC */
    uint8_t check_digest[S2N_MAX_DIGEST_LEN];
    POSIX_ENSURE_LTE(mac_digest_size, sizeof(check_digest));
    POSIX_GUARD(s2n_hmac_digest(hmac, check_digest, mac_digest_size));

    int mismatches = s2n_constant_time_equals(decrypted->data + payload_length, check_digest, mac_digest_size) ^ 1;

    /* SSLv3 doesn't specify what the padding should actually be */
    if (conn->actual_protocol_version == S2N_SSLv3) {
        return 0 - mismatches;
    }

    /* Check the maximum amount that could theoretically be padding */
    int check = MIN(255, (payload_and_padding_size - 1));

    int cutoff = check - padding_length;
    for (uint32_t i = 0, j = decrypted->size - 1 - check; i < check && j < decrypted->size; i++, j++) {
        uint8_t mask = ~(0xff << ((i >= cutoff) * 8));
        mismatches |= (decrypted->data[j] ^ padding_length) & mask;
    }

    S2N_ERROR_IF(mismatches, S2N_ERR_CBC_VERIFY);

    return 0;
}

/*
 * A wrapper for s2n_cbc_verify (or s2n_bad_cbc_verify) that handles setup and measurement.
 *
 * Its primary purpose to to make sure we never forget to add 13 bytes to the HMAC in order
 * to trigger Lucky "13", since that is done outside of s2n_cbc_verify.
 */
static S2N_RESULT s2n_run_cbc_verify(target_fn target, struct s2n_hmac_state *hmac, struct s2n_blob *plaintext, uint64_t *time)
{
    RESULT_ENSURE_REF(hmac);
    RESULT_ENSURE_REF(plaintext);
    RESULT_ENSURE_REF(time);

    DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    RESULT_ENSURE_REF(conn);
    conn->actual_protocol_version = S2N_TLS12;

    /* Putting the sequence number and header in the HMAC is NOT handled by s2n_verify_cbc!
     * We MUST add 13 extra bytes of data, or we're not testing the real situation.
     *
     * This is where the name "Lucky 13" comes from: the relationship between this
     * 13-byte sequence, the length of the hmac tag, and the length of the padding
     * can trigger noticeably different amounts of work.
     */
    uint8_t seq_and_header[S2N_TLS_SEQUENCE_NUM_LEN + S2N_TLS_RECORD_HEADER_LENGTH] = { 0 };
    RESULT_GUARD_POSIX(s2n_hmac_update(hmac, seq_and_header, sizeof(seq_and_header)));
    RESULT_ENSURE_EQ(hmac->currently_in_hash_block, 13);

    uint64_t before = rdtsc();
    int result = target(conn, hmac, plaintext);
    uint64_t after = rdtsc();

    /*
     * It's safe to assume that s2n_verify_cbc will fail.
     * Since our plaintext is randomly generated, it's EXTREMELY unlikely
     * to pass the verification check.
     */
    RESULT_ENSURE_NE(result, S2N_SUCCESS);
    RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_CBC_VERIFY);

    RESULT_ENSURE_LT(before, after);
    *time = (after - before);
    return S2N_RESULT_OK;
}

/*
 * Lucky 13 relies on specific relationships between the block size and the bytes HMACed.
 * We need to retrieve the number of bytes HMACed in order to verify
 * that we're setting up our tests correctly.
 */
static S2N_RESULT s2n_get_bytes_in_hmac(const struct s2n_scenario *scenario,
        struct s2n_blob *plaintext, uint32_t *in_hmac)
{
    RESULT_ENSURE_REF(scenario);
    RESULT_ENSURE_REF(plaintext);
    RESULT_ENSURE_REF(in_hmac);

    DEFER_CLEANUP(struct s2n_hmac_state hmac = { 0 }, s2n_hmac_free);
    RESULT_GUARD_POSIX(s2n_hmac_new(&hmac));
    RESULT_GUARD_POSIX(s2n_hmac_init(&hmac, scenario->hmac_alg, key, sizeof(key)));

    /* Break the hmac so that it will fail before calculating the digest.
     * We want to be able to examine the hmac before it's reset.
     *
     * This is fragile, but it works.
     */
    hmac.digest_size = 0;

    uint64_t result = 0;
    s2n_result r = s2n_run_cbc_verify(s2n_verify_cbc, &hmac, plaintext, &result);
    RESULT_ENSURE(s2n_result_is_error(r), S2N_ERR_SAFETY);
    RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_SAFETY);

    *in_hmac = hmac.currently_in_hash_block;
    return S2N_RESULT_OK;
}

/*
 * Generate the input plaintexts required by a particular scenario.
 */
static S2N_RESULT s2n_plaintexts_new(const struct s2n_scenario *scenario,
        struct s2n_blob *plaintexts, size_t plaintexts_len)
{
    RESULT_ENSURE_REF(scenario);
    RESULT_ENSURE_REF(plaintexts);
    RESULT_ENSURE_EQ(plaintexts_len, S2N_CASE_COUNT);

    uint32_t in_hmac = 0;
    uint32_t length = scenario->plaintext_len;

    DEFER_CLEANUP(struct s2n_blob arbitrary_data = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&arbitrary_data, length));
    RESULT_GUARD(s2n_get_public_random_data(&arbitrary_data));

    for (size_t i = 0; i < plaintexts_len; i++) {
        RESULT_GUARD_POSIX(s2n_dup(&arbitrary_data, &plaintexts[i]));
        plaintexts[i].data[length - 1] = scenario->padding_cases[i];
    }

    /* Both papers place the same expectations on the number of bytes in the hmac */
    RESULT_GUARD(s2n_get_bytes_in_hmac(scenario, &plaintexts[S2N_CASE_1], &in_hmac));
    EXPECT_TRUE(in_hmac >= 56);
    RESULT_GUARD(s2n_get_bytes_in_hmac(scenario, &plaintexts[S2N_CASE_2], &in_hmac));
    EXPECT_TRUE(in_hmac <= 55);

    return S2N_RESULT_OK;
}

/*
 * Calculate the median of the data.
 *
 * We also calculate other values (min, max, range) for debugging purposes.
 */
static S2N_RESULT s2n_get_median(struct s2n_data *data, uint64_t *median)
{
    size_t size = data->datapoints_size;
    uint64_t min = data->datapoints[0];
    uint64_t max = data->datapoints[size - 1];
    uint64_t range = max - min;
    *median = data->datapoints[size / 2];

    TEST_PRINT(DEBUG_LVL_MATH, "min %lu max %lu range %lu mean %lu\n",
            min, max, range, *median);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_set_datapoint(struct s2n_data_set *dataset, uint8_t case_i)
{
    RESULT_ENSURE_REF(dataset);
    RESULT_ENSURE_REF(dataset->scenario);
    s2n_hmac_algorithm hmac_alg = dataset->scenario->hmac_alg;
    struct s2n_data *data = &dataset->data[case_i];

    DEFER_CLEANUP(struct s2n_hmac_state hmac = { 0 }, s2n_hmac_free);
    RESULT_GUARD_POSIX(s2n_hmac_new(&hmac));
    RESULT_GUARD_POSIX(s2n_hmac_init(&hmac, hmac_alg, key, sizeof(key)));

    uint64_t time = 0;
    RESULT_GUARD(s2n_run_cbc_verify(dataset->target, &hmac, &dataset->plaintexts[case_i], &time));
    TEST_PRINT(DEBUG_LVL_DATA, " %lu", time);

    data->datapoints[data->datapoints_size] = time;
    data->datapoints_size++;
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_set_datapoints(struct s2n_data_set *dataset)
{
    RESULT_ENSURE_REF(dataset);
    for (size_t i = 0; i < S2N_CASE_COUNT; i ++) {
        TEST_PRINT(DEBUG_LVL_DATA, "\n%s Case %i: ", dataset->name, (int) i + 1);
        for (size_t j = 0; j < DATA_POINT_COUNT; j++) {
            EXPECT_OK(s2n_set_datapoint(dataset, i));
        }
        TEST_PRINT(DEBUG_LVL_DATA, "\n");
        qsort(dataset->data[i].datapoints, DATA_POINT_COUNT, sizeof(uint64_t), s2n_u64cmp);
    }
    return S2N_RESULT_OK;
}

/*
 * For a given scenario, we run three tests:
 *
 * 1. "Test": The primary test. Gather test datapoints and compare
 *    Case 1 and Case 2. We expect a difference, since s2n-tls intentionally
 *    did not implement a perfect solution to Lucky 13 for the sake of simplicity,
 *    but the difference should be too small to reasonably measure.
 *
 * 2. "Known good": Gather test datapoints a second time as a control,
 *    and compare Case 1 in the original test datapoints to Case 1
 *    in the control datapoints. Since they're the same case, we expect
 *    them to be indistinguishable.
 *    If this test fails, we have a false positive.
 *
 * 3. "Known bad": Gather test datapoints with some Lucky 13 countermeasures
 *    disabled. We expected an obvious difference between Case 1 and Case 2,
 *    since that is the basis of the Lucky 13 attack.
 *    If this test fails, we have a false negative.
 */
S2N_RESULT run_test(const struct s2n_scenario *scenario, bool *pass)
{
    /* Start measuring using both clock() and rdtsc().
     * rdtsc() is much more accurate for small measurements, but
     * translating cycles to seconds is difficult.
     */
    clock_t clock_start = clock();
    uint64_t cycles_start = rdtsc();

    /* Generate the plaintext records we will use as inputs.
     * To reduce the differences between tests, we will use the same plaintext
     * for every test.
     */
    struct s2n_blob plaintexts[S2N_CASE_COUNT] = { 0 };
    RESULT_GUARD(s2n_plaintexts_new(scenario, plaintexts, s2n_array_len(plaintexts)));

    /* Generate our data by running s2n_verify_cbc (or s2n_bad_verify_cbc)
     * repeatedly and recording the cycles each time.
     */
    struct s2n_data_set bad_dataset = {
        .name = "Testing without Lucky 13 countermeasures",
        .scenario = scenario,
        .plaintexts = plaintexts,
        .target = s2n_bad_verify_cbc,
    };
    RESULT_GUARD(s2n_set_datapoints(&bad_dataset));
    struct s2n_data_set test_dataset = {
        .name = "Testing target scenario",
        .scenario = scenario,
        .plaintexts = plaintexts,
        .target = s2n_verify_cbc,
    };
    RESULT_GUARD(s2n_set_datapoints(&test_dataset));
    struct s2n_data_set control_dataset = {
        .name = "Testing again for control comparison",
        .scenario = scenario,
        .plaintexts = plaintexts,
        .target = s2n_verify_cbc,
    };
    RESULT_GUARD(s2n_set_datapoints(&control_dataset));

    /* End both our timers */
    uint64_t cycles_end = rdtsc();
    clock_t clock_end = clock();
    uint64_t cycles_diff = cycles_end - cycles_start;
    clock_t clock_diff = clock_end - clock_start;

    /* Estimate the number of cycles per microsecond by comparing
     * our measured clock time to our measured cycles.
     * A more exact / correct calculation would require some tricky asm.
     * This estimate will not be perfect, but it should be close enough
     * for testing (and much more readable).
     */
    double clocks_diff_usec = (clock_diff) / (1.0 * CLOCKS_PER_USEC);
    double cycles_per_usec = cycles_diff / clocks_diff_usec;
    TEST_PRINT(DEBUG_LVL_MATH, "cycles %lu clock %.2f cycles_per_usec %.2f\n",
            cycles_diff, clocks_diff_usec, cycles_per_usec);

    /* Calculate the mean for each dataset */
    uint64_t bad_medians[S2N_CASE_COUNT] = { 0 };
    uint64_t test_medians[S2N_CASE_COUNT] = { 0 };
    uint64_t control_medians[S2N_CASE_COUNT] = { 0 };
    for (size_t i = 0; i < S2N_CASE_COUNT; i++) {
        RESULT_GUARD(s2n_get_median(&bad_dataset.data[i], &bad_medians[i]));
        RESULT_GUARD(s2n_get_median(&test_dataset.data[i], &test_medians[i]));
        RESULT_GUARD(s2n_get_median(&control_dataset.data[i], &control_medians[i]));
    }

    /* Calculate the diff between the means of Case 1 and Case 2.
     * If the data were graphed, this would basically be the difference
     * between the peaks of each distribution.
     *
     * We use this as an easy estimate of how similar the two distributions are.
     */
    uint64_t known_good_diff = abs(test_medians[S2N_CASE_1] - control_medians[S2N_CASE_1]);
    uint64_t known_bad_diff = abs(bad_medians[S2N_CASE_1] - bad_medians[S2N_CASE_2]);
    uint64_t test_diff = abs(test_medians[S2N_CASE_1] - test_medians[S2N_CASE_2]);

    /* We expect a difference, but the difference is considered acceptable
     * if it's too small to be reasonably measured, particularly over a real, noisy network.
     * We set the allowed difference to 0.1 us, or 100 ns.
     *
     * It's worth noting that even with most Lucky 13 countermeasures disabled,
     * the difference is still well below 1 us.
     */
    uint64_t allowed_diff = (cycles_per_usec / 10);

    bool known_good_pass = (known_good_diff < allowed_diff);
    bool known_bad_pass = (known_bad_diff > allowed_diff);
    bool test_pass = (test_diff < allowed_diff);
    bool test_against_bad_pass = (test_diff < known_bad_diff);
    *pass = known_good_pass && known_bad_pass && test_pass && test_against_bad_pass;

    /* Bail early if all tests passed but only failure debugging was set.
     * A lower debug level won't print anything anyway, and a higher debug level
     * should print regardless of whether or not the tests passed.
     */
    if (*pass && DEBUG_LEVEL == DEBUG_LVL_FAILURES) {
        return S2N_RESULT_OK;
    }

    TEST_PRINT(DEBUG_LVL_FAILURES, "known good (comparing the same case): %lu < %lu (%s)\n", known_good_diff, allowed_diff,
            known_good_pass ? "PASS" : "FAIL");
    TEST_PRINT(DEBUG_LVL_FAILURES, "known bad (countermeasures removed): %lu > %lu (%s)\n", known_bad_diff, allowed_diff,
            known_bad_pass ? "PASS" : "FAIL");
    TEST_PRINT(DEBUG_LVL_FAILURES, "test (comparing to .1us): %lu < %lu (%s)\n", test_diff, allowed_diff,
            test_pass ? "PASS" : "FAIL");
    TEST_PRINT(DEBUG_LVL_FAILURES, "test (comparing to known bad): %lu < %lu (%s)\n", test_diff, known_bad_diff,
            test_against_bad_pass ? "PASS" : "FAIL");

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    size_t successes = 0, total = 0;
    for (size_t scenario_i = 0; scenario_i < s2n_array_len(scenarios); scenario_i++) {
        const struct s2n_scenario *scenario = scenarios[scenario_i];

        for (size_t i = 0; i < TEST_RUNS; i++) {
            TEST_PRINT(DEBUG_LVL_RESULTS, "\nRunning test %lu\n", total);

            bool pass = false;
            EXPECT_OK(run_test(scenario, &pass));

            if (pass) {
                successes++;
            }
            total++;
        }
    }

    double success_percent = (1.0 * successes) / total;
    TEST_PRINT(DEBUG_LVL_SUMMARY, "\nSuccesses: %lu percent: %.2f\n\n",
            successes, success_percent);
    EXPECT_TRUE(success_percent > 0.9);

    END_TEST();
}
