//
// Created by cl on 2021/1/6.
//

#include "odo_sha256_param_gen.h"

static const uint32_t TABLE_SIZE_BITS = 14;
static const uint32_t TABLE_SIZE = 16384;//pow(2, TABLE_SIZE_BITS);
static const uint64_t EPOCH_PERIOD = 864000;
static const uint64_t T = 1609653714;

extern void applog(int prio, const char *fmt, ...);

void bubble_sort(uint32_t *arr, size_t n) {
    for (size_t i = 0; i < n - 1; i++)
        for (size_t j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                uint32_t temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
}

void check_safe(uint32_t table[TABLE_SIZE])
{
    uint32_t* table_tmp = (uint32_t*)malloc(TABLE_SIZE * sizeof(uint32_t));
    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        table_tmp[i] = table[i];
    }

    bubble_sort(table_tmp, TABLE_SIZE);

    uint32_t i = 0;
    for (; i < TABLE_SIZE - 1; i++) {
        if (table_tmp[i] == table_tmp[i + 1])
            break;
    }

    free(table_tmp);
    if (i < TABLE_SIZE - 1) {
        assert(1 > 2 && "check safe, failed");
    }
}

void get_m(bigint m[1])
{
    bigint multiplier[1], multiplicand[1], n2[1];

    bigint_init(multiplier);
    bigint_init(multiplicand);
    bigint_init(n2);
    bigint_init(m);

    bigint_from_word(n2, 2);

    bigint_pow_word(multiplier, n2, 108);
    bigint_sub_word(multiplier, multiplier, 59);

    bigint_pow_word(multiplicand, n2, 126);
    bigint_sub_word(multiplicand, multiplicand, 335);

    bigint_mul(m, multiplier, multiplicand);
}

uint32_t is_prime(uint32_t n)
{
    uint32_t q = (uint32_t)sqrt((double)n);
    for (uint32_t i = 2; i <= q; i++) {
        if (n % i == 0) return 0;
    }
    return 1;
}

void get_first_table_size_primes(uint32_t primes_out[TABLE_SIZE])
{
    uint32_t primes_len = 0;
    for (uint32_t i = 2;; i++) {
        if (is_prime(i)) {
            primes_out[primes_len++] = i;
            if (primes_len >= TABLE_SIZE) {
                break;
            }
        }
    }
}

void create_decimals_of_square_root_of_primes(const uint32_t primes[TABLE_SIZE], uint32_t sqrts_out[TABLE_SIZE])
{
    uint32_t sqrts_len = 0;
    long double md = 1;

    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        sqrts_out[sqrts_len++] = floorl(powl(2, 32) * modfl(sqrtl(primes[i]), &md));
    }
    check_safe(sqrts_out);
}

void create_decimals_of_cube_roots_of_primes(const uint32_t primes[TABLE_SIZE], uint32_t curts_out[TABLE_SIZE])
{
    uint32_t curts_len = 0;
    long double md = 1;

    for (uint32_t i = 0; i < TABLE_SIZE; i++) {
        curts_out[curts_len++] = floorl(powl(2, 32) * modfl(cbrtl(primes[i]), &md));
    }
    check_safe(curts_out);
}

void blum_blum_shub_mod(uint64_t seed, const uint32_t table[TABLE_SIZE], uint32_t count, uint32_t* out) {
    char seed_char[20];
    sprintf(seed_char, "%lu", seed);

    bigint seed_bi[1], seed_bi_tmp[1], two[1], m[1];
    get_m(m);

    bigint_init(seed_bi);
    bigint_init(seed_bi_tmp);
    bigint_init(two);

    bigint_from_str(seed_bi, seed_char);
    bigint_mod(seed_bi, seed_bi, m);
    bigint_from_word(two, 2);

    size_t out_len = 0;

    uint32_t *used = (uint32_t *)calloc(count, sizeof(uint32_t));
    size_t used_len = 0;

    while (out_len < count) {
        uint32_t bits = 0;
        for (size_t i = 0; i < TABLE_SIZE_BITS; i++) {
            bigint_pow_mod(seed_bi, seed_bi, two, m);
            int trailing_zeros = bigint_count_trailing_zeros(seed_bi);
            bits = bits * 2 + (trailing_zeros == 0 ? 1 : 0);
        }
        size_t i = 0;
        for (; i < used_len; i++) {
            if (used[i] == bits) {
                break;
            }
        }
        if (i == used_len) {
            used[used_len++] = bits;
            out[out_len++] = table[bits];
        }
    }
}

void gen_k256(uint64_t t, uint32_t curts[TABLE_SIZE], uint32_t k256_out[64])
{
    blum_blum_shub_mod(t, curts, 64, k256_out);
}

void gen_h256(uint64_t t, uint32_t sqrts[TABLE_SIZE], uint32_t h256_out[8])
{
    blum_blum_shub_mod(t, sqrts, 8, h256_out);
}

static uint32_t primes[16384];
static uint32_t sqrts[16384];
static uint32_t curts[16384];
void generate(uint64_t key, uint32_t h256_out[8], uint32_t k256_out[64])
{
    // TODO: Can be optimized (eg:pthread_once_t).
    static int inited = 0;
    if (!inited) {
        inited = 1;
        get_first_table_size_primes(primes);
        create_decimals_of_square_root_of_primes(primes, sqrts);
        create_decimals_of_cube_roots_of_primes(primes, curts);
        applog(6, "-------generate-----.");
    }

    // uint32_t* primes = (uint32_t*)malloc(TABLE_SIZE * sizeof(uint32_t));
    // get_first_table_size_primes(primes);

    // uint32_t* sqrts = (uint32_t*)malloc(TABLE_SIZE * sizeof(uint32_t));
    // create_decimals_of_square_root_of_primes(primes, sqrts);

    // uint32_t* curts = (uint32_t*)malloc(TABLE_SIZE * sizeof(uint32_t));
    // create_decimals_of_cube_roots_of_primes(primes, curts);

    // free(primes);

    uint64_t next_t = ceill((long double)(T + key * EPOCH_PERIOD) / EPOCH_PERIOD);
    gen_h256(next_t, sqrts, h256_out);
    gen_k256(next_t, curts, k256_out);

    // free(sqrts);
    // free(curts);
}