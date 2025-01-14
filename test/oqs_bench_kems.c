// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <math.h>

#include "oqs/oqs.h"
#include "test_common.h"
#include <qkd-etsi-api/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api/etsi014/api.h>
#endif

#define DEBUG_QKD

#ifdef NDEBUG
#define QKD_DEBUG(fmt, ...)
#else
#ifdef DEBUG_QKD
#define QKD_DEBUG(fmt, ...)                                                    \
    fprintf(stderr, "QKD DEBUG: %s:%d: " fmt "\n", __func__, __LINE__,         \
            ##__VA_ARGS__)
#else
#define QKD_DEBUG(fmt, ...)
#endif
#endif

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static FILE *csv_file = NULL;

static void print_progress_bar(int current, int total, const char* algorithm) {
    const int bar_width = 50;
    float progress = (float)current / total;
    int filled = (int)(bar_width * progress);

    printf("\rBenchmarking: %-20s [", algorithm);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) printf("=");
        else printf(" ");
    }
    printf("] %.1f%%", progress * 100);
    fflush(stdout);
}

static inline double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

typedef struct {
    double keygen_time;
    double encaps_time;
    double decaps_time;
} timing_results_t;


static void write_csv_result(const char* alg_name, size_t iteration, 
                           timing_results_t* times) {
    if (csv_file) {
        fprintf(csv_file, "%s,%zu,%.3f,%.3f,%.3f\n",
                alg_name, iteration + 1,
                times->keygen_time,
                times->encaps_time,
                times->decaps_time);
        fflush(csv_file);  // Ensure data is written immediately
    }
}

static int bench_oqs_kems(const char *kemalg_name, size_t num_iterations) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    size_t outlen, seclen;
    double start, end;
    timing_results_t times = {0};
    int testresult = 1;

    if (!alg_is_enabled(kemalg_name)) {
        QKD_DEBUG("Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }

    for (size_t iter = 0; iter < num_iterations; iter++) {
        if (OSSL_PROVIDER_available(libctx, "default")) {
            // Key Generation timing
            start = get_time_ms();
            testresult &= (ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name,
                                                            NULL)) != NULL &&
                         EVP_PKEY_keygen_init(ctx) && 
                         EVP_PKEY_generate(ctx, &key);
            end = get_time_ms();
            times.keygen_time = end - start;

            if (!testresult) {
                QKD_DEBUG("Key generation failed\n");
                goto err;
            }

            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;

            // Setup for encapsulation
            ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL);
            if (ctx == NULL || !EVP_PKEY_encapsulate_init(ctx, NULL)) {
                testresult = 0;
                goto err;
            }

            if (!EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen)) {
                testresult = 0;
                goto err;
            }

            testresult &= (out = OPENSSL_malloc(outlen)) != NULL &&
                         (secenc = OPENSSL_malloc(seclen)) != NULL &&
                         memset(secenc, 0x11, seclen) != NULL &&
                         (secdec = OPENSSL_malloc(seclen)) != NULL &&
                         memset(secdec, 0xff, seclen) != NULL;

            // Encapsulation timing
            start = get_time_ms();
            testresult &= EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen);
            end = get_time_ms();
            times.encaps_time = end - start;

            // Setup for decapsulation
            if (!EVP_PKEY_decapsulate_init(ctx, NULL)) {
                testresult = 0;
                goto err;
            }

            // Decapsulation timing
            start = get_time_ms();
            testresult = EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen);
            end = get_time_ms();
            times.decaps_time = end - start;

            if (!testresult) {
                QKD_DEBUG("Operation failed in iteration %zu\n", iter);
                goto err;
            }

            // Write results to CSV
            write_csv_result(kemalg_name, iter, &times);

            // Progress bar
            print_progress_bar(iter + 1, num_iterations, kemalg_name);

            // Cleanup for next iteration
            EVP_PKEY_free(key);
            key = NULL;
            EVP_PKEY_CTX_free(ctx);
            ctx = NULL;
            OPENSSL_free(out);
            out = NULL;
            OPENSSL_free(secenc);
            secenc = NULL;
            OPENSSL_free(secdec);
            secdec = NULL;
        }
    }

    printf("\n");

err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(out);
    OPENSSL_free(secenc);
    OPENSSL_free(secdec);
    return testresult;
}

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs;
    size_t num_iterations;
    char csv_path[PATH_MAX];
    char timestamp[32];
    char benchmark_dir[PATH_MAX];

    // Verify arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <provider_module> <config_file> <iterations>\n", argv[0]);
        return 1;
    }

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    modulename = argv[1];
    configfile = argv[2];
    num_iterations = (size_t)atoi(argv[3]);

    if (num_iterations < 1) {
        fprintf(stderr, "Number of iterations must be positive\n");
        return 1;
    }

    // Create timestamp for filename (date only)
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(timestamp, sizeof(timestamp), "%Y%m%d", tm);

    snprintf(benchmark_dir, sizeof(benchmark_dir), "../../benchmarks");

    // Create benchmarks directory with full permissions
    if (mkdir(benchmark_dir, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Error creating benchmarks directory %s: %s\n", 
                benchmark_dir, strerror(errno));
        return 1;
    }

    // Use a simple relative path to create benchmarks in the parent directory
    snprintf(csv_path, sizeof(csv_path), "../../benchmarks/kem_bench_%s_%zu_iter.csv", timestamp,num_iterations);

    csv_file = fopen(csv_path, "w");
    if (!csv_file) {
        fprintf(stderr, "Error creating CSV file: %s\n", strerror(errno));
        return 1;
    }

    // Write CSV header
    fprintf(csv_file, "Algorithm,Iteration,KeyGen(ms),Encaps(ms),Decaps(ms)\n");

    // Load provider and run benchmarks
    load_oqs_provider(libctx, modulename, configfile);
    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    printf("Starting KEM benchmarks with %zu iterations...\n", num_iterations);
    printf("Results will be saved to: %s\n\n", csv_path);

    kemalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (bench_oqs_kems(kemalgs->algorithm_names, num_iterations)) {
                fprintf(stderr, cGREEN "  Benchmark completed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  Benchmark failed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

    // Cleanup
    if (csv_file) {
        fclose(csv_file);
    }
    OSSL_LIB_CTX_free(libctx);

    // Count total number of algorithms
    size_t total_algorithms = 0;
    const OSSL_ALGORITHM *count_kemalgs = OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (count_kemalgs) {
        for (; count_kemalgs->algorithm_names != NULL; count_kemalgs++) {
            total_algorithms++;
        }
    }

    printf("\nBenchmark Summary:\n");
    printf("Total algorithms tested: %zu\n", total_algorithms);
    printf("Algorithms with failed benchmarks: %d\n", errcnt);
    printf("Results saved to: %s\n", csv_path);

    TEST_ASSERT(errcnt == 0)
    return !test;
}
