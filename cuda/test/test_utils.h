#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Simple Test Framework for Rijndael-256 CUDA Implementation
 *
 * No external dependencies - uses simple assert-style macros
 */

// ANSI color codes for terminal output (optional, comment out if not supported)
#define COLOR_GREEN  "\x1b[32m"
#define COLOR_RED    "\x1b[31m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_RESET  "\x1b[0m"

// Test statistics
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

/**
 * Assert that a condition is true
 * If false, print error message and return -1
 */
#define TEST_ASSERT(condition, message) \
    do { \
        g_tests_run++; \
        if (!(condition)) { \
            fprintf(stderr, COLOR_RED "✗ FAIL" COLOR_RESET ": %s\n", message); \
            fprintf(stderr, "  at %s:%d\n", __FILE__, __LINE__); \
            g_tests_failed++; \
            return -1; \
        } else { \
            g_tests_passed++; \
        } \
    } while(0)

/**
 * Assert that two values are equal
 */
#define TEST_ASSERT_EQUAL(expected, actual, message) \
    do { \
        g_tests_run++; \
        if ((expected) != (actual)) { \
            fprintf(stderr, COLOR_RED "✗ FAIL" COLOR_RESET ": %s\n", message); \
            fprintf(stderr, "  Expected: %d, Actual: %d\n", (int)(expected), (int)(actual)); \
            fprintf(stderr, "  at %s:%d\n", __FILE__, __LINE__); \
            g_tests_failed++; \
            return -1; \
        } else { \
            g_tests_passed++; \
        } \
    } while(0)

/**
 * Assert that two byte arrays are equal
 */
#define TEST_ASSERT_BYTES_EQUAL(expected, actual, numBytes, message) \
    do { \
        g_tests_run++; \
        int equal = 1; \
        for (int i = 0; i < (numBytes); i++) { \
            if ((expected)[i] != (actual)[i]) { \
                equal = 0; \
                break; \
            } \
        } \
        if (!equal) { \
            fprintf(stderr, COLOR_RED "✗ FAIL" COLOR_RESET ": %s\n", message); \
            fprintf(stderr, "  Expected: "); \
            for (int i = 0; i < (numBytes); i++) { \
                fprintf(stderr, "%02X", (expected)[i]); \
            } \
            fprintf(stderr, "\n  Actual:   "); \
            for (int i = 0; i < (numBytes); i++) { \
                fprintf(stderr, "%02X", (actual)[i]); \
            } \
            fprintf(stderr, "\n  at %s:%d\n", __FILE__, __LINE__); \
            g_tests_failed++; \
            return -1; \
        } else { \
            g_tests_passed++; \
        } \
    } while(0)

/**
 * Print test section header
 */
#define TEST_SECTION(name) \
    printf("\n" COLOR_YELLOW "=== %s ===" COLOR_RESET "\n", name)

/**
 * Print test summary
 */
static inline void TEST_SUMMARY(const char* testName) {
    printf("\n" COLOR_YELLOW "=== Test Summary: %s ===" COLOR_RESET "\n", testName);
    printf("Total:  %d\n", g_tests_run);
    printf(COLOR_GREEN "Passed: %d" COLOR_RESET "\n", g_tests_passed);
    if (g_tests_failed > 0) {
        printf(COLOR_RED "Failed: %d" COLOR_RESET "\n", g_tests_failed);
    } else {
        printf("Failed: 0\n");
    }

    if (g_tests_failed == 0 && g_tests_run > 0) {
        printf(COLOR_GREEN "\n✓ All tests passed!\n" COLOR_RESET);
    } else if (g_tests_failed > 0) {
        printf(COLOR_RED "\n✗ Some tests failed\n" COLOR_RESET);
    }
}

/**
 * Reset test counters (call at start of each test file)
 */
static inline void TEST_RESET() {
    g_tests_run = 0;
    g_tests_passed = 0;
    g_tests_failed = 0;
}

/**
 * Return exit code based on test results
 */
static inline int TEST_EXIT_CODE() {
    return (g_tests_failed == 0) ? 0 : 1;
}

/**
 * Print hex dump of byte array (for debugging)
 */
static inline void PRINT_HEX(const char* label, const uint8_t* data, int numBytes) {
    printf("%s: ", label);
    for (int i = 0; i < numBytes; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 4 == 0 && i != numBytes - 1) printf(" ");
    }
    printf("\n");
}

/**
 * Compare CPU vs GPU results
 */
static inline int compareResults(const uint8_t* cpu, const uint8_t* gpu,
                                 int numBlocks, const char* testName) {
    int blockSize = 32; // Rijndael-256 block size
    int errors = 0;

    for (int i = 0; i < numBlocks; i++) {
        for (int j = 0; j < blockSize; j++) {
            if (cpu[i * blockSize + j] != gpu[i * blockSize + j]) {
                if (errors == 0) {
                    fprintf(stderr, COLOR_RED "\n✗ MISMATCH in %s" COLOR_RESET "\n", testName);
                    fprintf(stderr, "Block %d, byte %d:\n", i, j);
                    fprintf(stderr, "  CPU: %02X\n", cpu[i * blockSize + j]);
                    fprintf(stderr, "  GPU: %02X\n", gpu[i * blockSize + j]);
                }
                errors++;
                if (errors >= 10) {
                    fprintf(stderr, "... (showing first 10 errors only)\n");
                    return errors;
                }
            }
        }
    }

    if (errors == 0) {
        printf(COLOR_GREEN "✓ CPU vs GPU match (%d blocks)" COLOR_RESET "\n", numBlocks);
    } else {
        fprintf(stderr, COLOR_RED "Total errors: %d" COLOR_RESET "\n", errors);
    }

    return errors;
}

#endif // TEST_UTILS_H
