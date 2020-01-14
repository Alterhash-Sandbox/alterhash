// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "ethash-internal.hpp"
#include "attributes.h"
#include "bit_manipulation.h"
#include "endianness.hpp"
#include "primes.h"
#include "keccak.hpp"
#include "helpers.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdio.h>
#include <string.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/math/constants/constants.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
//#include   <random>
#include    <time.h>
#include    <stdlib.h>
#include    <iostream>

#include "x16rv2.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"

#include "sha3/sph_sha2.h"

extern "C" {
  #include "siphash/siphash.h"
  #include "sha3/sph_tiger.h"
  #include "sha3/sph_whirlpool.h"
}
namespace x16r
{
    enum Algo 
{
    BLAKE = 0,
    BMW,
    GROESTL,
    JH,
    KECCAK,
    SKEIN,
    LUFFA,
    CUBEHASH,
    SHAVITE,
    SIMD,
    ECHO,
    HAMSI,
    FUGUE,
    SHABAL,
    WHIRLPOOL,
    SHA512,
    HASH_FUNC_COUNT
};

static void getAlgoString(const char * prevblock, char *output)
{
    char *sptr = output;
    int j;

    for (j = 0; j < HASH_FUNC_COUNT; j++) {
        char b = (15 - j) >> 1; // 16 ascii hex chars, reversed
        uint8_t algoDigit = (j & 1) ? (uint8_t)prevblock[b] & 0xF :  (uint8_t)prevblock[b] >> 4;
        if (algoDigit >= 10)
            sprintf(sptr, "%c", 'A' + (algoDigit - 10));
        else
            sprintf(sptr, "%u", (uint32_t) algoDigit);
        sptr++;
    }
    *sptr = '\0';
}

//static void 
//getAlgoName(uint8_t  prevblock, char *output)
//{
//    char *sptr = output;
//    int j;

//    for (j = 0; j < 2; j++) { //  only 2 algos are requiered
//        //char b = (15 - j) >> 1; // 16 ascii hex chars, reversed
//        uint8_t algoDigit = (j & 1) ? (uint8_t)prevblock & 0xF :  (uint8_t)prevblock >> 4;
//        if (algoDigit >= 10)
//            sprintf(sptr, "%c", 'A' + (algoDigit - 10));
//        else
//            sprintf(sptr, "%u", (uint32_t) algoDigit);
//        sptr++;
//    }
//    *sptr = '\0';
//}


void x16rv2_hash(const char* input, char* output, uint8_t single, uint8_t x16r_algo, size_t input_size)
{
    uint32_t hash[64/4];
    char hashOrder[HASH_FUNC_COUNT + 1] = { 0 };

    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context     ctx_luffa;
    sph_cubehash512_context  ctx_cubehash;
    sph_shavite512_context   ctx_shavite;
    sph_simd512_context      ctx_simd;
    sph_echo512_context      ctx_echo;
    sph_hamsi512_context     ctx_hamsi;
    sph_fugue512_context     ctx_fugue;
    sph_shabal512_context    ctx_shabal;
    sph_whirlpool_context    ctx_whirlpool;
    sph_sha512_context       ctx_sha512;
    sph_tiger_context        ctx_tiger;
    uint8_t algo_cnt;
    void *in = (void*) input;
    int size = 64;
    int i;
    if(single) {
      //getAlgoName( x16r_algo, hashOrder);
      algo_cnt = 1;
      //size     = input_size;
    } else {
      getAlgoString(input, hashOrder);
      algo_cnt = 16;
    }
    
     
    for (i = 0; i < algo_cnt; i++) {
        uint8_t algo;
        if (single) {
            algo = x16r_algo;
        } else {
            const char elem = hashOrder[i];
            algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';
        }

        switch (algo) {
            case BLAKE:
            sph_blake512_init(&ctx_blake);
            sph_blake512(&ctx_blake, in, size);
            sph_blake512_close(&ctx_blake, hash);
            break;
            case BMW:
            sph_bmw512_init(&ctx_bmw);
            sph_bmw512(&ctx_bmw, in, size);
            sph_bmw512_close(&ctx_bmw, hash);
            break;
            case GROESTL:
            sph_groestl512_init(&ctx_groestl);
            sph_groestl512(&ctx_groestl, in, size);
            sph_groestl512_close(&ctx_groestl, hash);
            break;
            case SKEIN:
            sph_skein512_init(&ctx_skein);
            sph_skein512(&ctx_skein, in, size);
            sph_skein512_close(&ctx_skein, hash);
            break;
            case JH:
            sph_jh512_init(&ctx_jh);
            sph_jh512(&ctx_jh, in, size);
            sph_jh512_close(&ctx_jh, hash);
            break;
            case KECCAK:
            sph_tiger_init(&ctx_tiger);
            sph_tiger(&ctx_tiger, (const void*) in, size);
            sph_tiger_close(&ctx_tiger, (void*) hash);
            for (int j = 24; j < 64; ++j) ((uint8_t*)hash)[j] = 0; // Pad the 24 bytes to bring it to 64 bytes

            sph_keccak512_init(&ctx_keccak);
            sph_keccak512(&ctx_keccak, hash, 64);
            sph_keccak512_close(&ctx_keccak, hash);
            break;
            case LUFFA:
            sph_tiger_init(&ctx_tiger);
            sph_tiger(&ctx_tiger, (const void*) in, size);
            sph_tiger_close(&ctx_tiger, (void*) hash);
            for (int j = 24; j < 64; ++j) ((uint8_t*)hash)[j] = 0; // Pad the 24 bytes to bring it to 64 bytes

            sph_luffa512_init(&ctx_luffa);
            sph_luffa512(&ctx_luffa, hash, 64);
            sph_luffa512_close(&ctx_luffa, hash);
            break;
            case CUBEHASH:
            sph_cubehash512_init(&ctx_cubehash);
            sph_cubehash512(&ctx_cubehash, in, size);
            sph_cubehash512_close(&ctx_cubehash, hash);
            break;
            case SHAVITE:
            sph_shavite512_init(&ctx_shavite);
            sph_shavite512(&ctx_shavite, in, size);
            sph_shavite512_close(&ctx_shavite, hash);
            break;
            case SIMD:
            sph_simd512_init(&ctx_simd);
            sph_simd512(&ctx_simd, in, size);
            sph_simd512_close(&ctx_simd, hash);
            break;
            case ECHO:
            sph_echo512_init(&ctx_echo);
            sph_echo512(&ctx_echo, in, size);
            sph_echo512_close(&ctx_echo, hash);
            break;
            case HAMSI:
            sph_hamsi512_init(&ctx_hamsi);
            sph_hamsi512(&ctx_hamsi, in, size);
            sph_hamsi512_close(&ctx_hamsi, hash);
            break;
            case FUGUE:
            sph_fugue512_init(&ctx_fugue);
            sph_fugue512(&ctx_fugue, in, size);
            sph_fugue512_close(&ctx_fugue, hash);
            break;
            case SHABAL:
            sph_shabal512_init(&ctx_shabal);
            sph_shabal512(&ctx_shabal, in, size);
            sph_shabal512_close(&ctx_shabal, hash);
            break;
            case WHIRLPOOL:
            sph_whirlpool_init(&ctx_whirlpool);
            sph_whirlpool(&ctx_whirlpool, in, size);
            sph_whirlpool_close(&ctx_whirlpool, hash);
            break;
            case SHA512:
            sph_tiger_init(&ctx_tiger);
            sph_tiger(&ctx_tiger, (const void*) in, size);
            sph_tiger_close(&ctx_tiger, (void*) hash);
            for (int j = 24; j < 64; ++j) ((uint8_t*)hash)[j] = 0; // Pad the 24 bytes to bring it to 64 bytes

            sph_sha512_init(&ctx_sha512);
            sph_sha512(&ctx_sha512,(const void*) hash, 64);
            sph_sha512_close(&ctx_sha512,(void*) hash);
            break;
        }
        in = (void*) hash;
        size = 64;
    }
    memcpy(output, hash, 64);
}
}

namespace ethash
{
// Internal constants:
constexpr static int light_cache_init_size = 1 << 24;
constexpr static int light_cache_growth = 1 << 17;
constexpr static int light_cache_rounds = 3;
constexpr static int full_dataset_init_size = 1 << 30;
constexpr static int full_dataset_growth = 1 << 23;
constexpr static int full_dataset_item_parents = 256;
constexpr size_t l1_cache_size = 16 * 1024;

// Verify constants:
static_assert(sizeof(hash512) == ETHASH_LIGHT_CACHE_ITEM_SIZE, "");
static_assert(sizeof(hash1024) == ETHASH_FULL_DATASET_ITEM_SIZE, "");
static_assert(light_cache_item_size == ETHASH_LIGHT_CACHE_ITEM_SIZE, "");
static_assert(full_dataset_item_size == ETHASH_FULL_DATASET_ITEM_SIZE, "");


namespace
{
using ::fnv1;

inline hash512 fnv1(const hash512& u, const hash512& v) noexcept
{
    hash512 r;
    for (size_t i = 0; i < sizeof(r) / sizeof(r.word32s[0]); ++i)
        r.word32s[i] = fnv1(u.word32s[i], v.word32s[i]);
    return r;
}

inline hash512 bitwise_xor(const hash512& x, const hash512& y) noexcept
{
    hash512 z;
    for (size_t i = 0; i < sizeof(z) / sizeof(z.word64s[0]); ++i)
        z.word64s[i] = x.word64s[i] ^ y.word64s[i];
    return z;
}
}  // namespace

int find_epoch_number(const hash256& seed) noexcept
{
    static constexpr int num_tries = 30000;  // Divisible by 16.

    // Thread-local cache of the last search.
    static thread_local int cached_epoch_number = 0;
    static thread_local hash256 cached_seed = {};

    // Load from memory once (memory will be clobbered by keccak256()).
    const uint32_t seed_part = seed.word32s[0];
    const int e = cached_epoch_number;
    hash256 s = cached_seed;

    if (s.word32s[0] == seed_part)
        return e;

    // Try the next seed, will match for sequential epoch access.
    s = keccak256(s);
    if (s.word32s[0] == seed_part)
    {
        cached_seed = s;
        cached_epoch_number = e + 1;
        return e + 1;
    }

    // Search for matching seed starting from epoch 0.
    s = {};
    for (int i = 0; i < num_tries; ++i)
    {
        if (s.word32s[0] == seed_part)
        {
            cached_seed = s;
            cached_epoch_number = i;
            return i;
        }

        s = keccak256(s);
    }

    return -1;
}

namespace generic
{
void build_light_cache(
    hash_fn_512 hash_fn, hash512 cache[], int num_items, const hash256& seed) noexcept
{
    hash512 item = hash_fn(seed.bytes, sizeof(seed));
    cache[0] = item;
    for (int i = 1; i < num_items; ++i)
    {
        item = hash_fn(item.bytes, sizeof(item));
        cache[i] = item;
    }

    for (int q = 0; q < light_cache_rounds; ++q)
    {
        for (int i = 0; i < num_items; ++i)
        {
            const uint32_t index_limit = static_cast<uint32_t>(num_items);

            // Fist index: 4 first bytes of the item as little-endian integer.
            const uint32_t t = le::uint32(cache[i].word32s[0]);
            const uint32_t v = t % index_limit;

            // Second index.
            const uint32_t w = static_cast<uint32_t>(num_items + (i - 1)) % index_limit;

            const hash512 x = bitwise_xor(cache[v], cache[w]);
            cache[i] = hash_fn(x.bytes, sizeof(x));
        }
    }
}

epoch_context_full* create_epoch_context(
    build_light_cache_fn build_fn, int epoch_number, bool full) noexcept
{
    static_assert(sizeof(epoch_context_full) < sizeof(hash512), "epoch_context too big");
    static constexpr size_t context_alloc_size = sizeof(hash512);

    const int light_cache_num_items = calculate_light_cache_num_items(epoch_number);
    const int full_dataset_num_items = calculate_full_dataset_num_items(epoch_number);
    const size_t volatile light_cache_size = get_light_cache_size(light_cache_num_items);
    //const size_t volatile full_dataset_size =
    //    full ? static_cast<size_t>(full_dataset_num_items) * sizeof(hash1024) :
    //           l1_cache_size;

    const size_t volatile alloc_size = context_alloc_size + light_cache_size;// + full_dataset_size;

    char* const alloc_data = static_cast<char*>(std::calloc(1, alloc_size));
    if (!alloc_data)
        return nullptr;  // Signal out-of-memory by returning null pointer.

    hash512* const light_cache = reinterpret_cast<hash512*>(alloc_data + context_alloc_size);
    const hash256 epoch_seed = calculate_epoch_seed(epoch_number);
    build_fn(light_cache, light_cache_num_items, epoch_seed);

    uint32_t* const l1_cache =
        reinterpret_cast<uint32_t*>(alloc_data + context_alloc_size + light_cache_size);

    hash1024* full_dataset = full ? reinterpret_cast<hash1024*>(l1_cache) : nullptr;

    epoch_context_full* const context = new (alloc_data) epoch_context_full{
        epoch_number,
        light_cache_num_items,
        light_cache,
        l1_cache,
        full_dataset_num_items,
        full_dataset,
    };
    
    //auto* full_dataset_1024 = reinterpret_cast<hash1024*>(l1_cache);
    //for (uint32_t i = 0; i < l1_cache_size / sizeof(full_dataset_1024[0]); ++i)
    //for (uint32_t i = 0; i < full_dataset_num_items; ++i)
    //    {
    //    full_dataset_1024[i] = calculate_dataset_item_1024(*context, i);
    //    }
    return context;
}
}  // namespace generic

void build_light_cache(hash512 cache[], int num_items, const hash256& seed) noexcept
{
    return generic::build_light_cache(keccak512, cache, num_items, seed);
}

struct item_state
{
    const hash512* const cache;
    const int64_t num_cache_items;
    const uint32_t seed;

    hash512 mix;

    ALWAYS_INLINE item_state(const epoch_context& context, int64_t index) noexcept
      : cache{context.light_cache},
        num_cache_items{context.light_cache_num_items},
        seed{static_cast<uint32_t>(index)}
    {
        mix = cache[index % num_cache_items];
        mix.word32s[0] ^= le::uint32(seed);
        mix = le::uint32s(keccak512(mix));
        x16r::x16rv2_hash(mix.str, mix.str, 0, 0, 0);
    }

     
    
         
    ALWAYS_INLINE void update(uint32_t round) noexcept
    {
        //int128_t randomInt = int64left << 64 | int64right;
        static constexpr size_t num_words = sizeof(mix) / sizeof(uint32_t);
        char * data_sip = mix.str;
        int new_round = round % 4;
        uint64_t sip_out = siphash(mix.word64s[(new_round*2)+1],mix.word64s[new_round*2],data_sip, 64, 1,2);
        //uint64_t sip_out = siphash(round,round,data_sip,2,4);
        const int64_t parent_index = sip_out % num_cache_items;
        //const uint32_t t = fnv1(seed ^ round, mix.word32s[round % num_words]);
        //const int64_t parent_index = t % num_cache_items;
        mix = fnv1(mix, le::uint32s(cache[parent_index]));
    }

    ALWAYS_INLINE hash512 final() noexcept { 
        mix = keccak512(le::uint32s(mix));
        x16r::x16rv2_hash(mix.str, mix.str, 0, 0, 0); 
        return mix;
    }
};

hash512 calculate_dataset_item_512(const epoch_context& context, int64_t index) noexcept
{
    item_state item0{context, index};
    for (uint32_t j = 0; j < full_dataset_item_parents; ++j)
        item0.update(j);
    return item0.final();
}

/// Calculates a full dataset item
///
/// This consist of two 512-bit items produced by calculate_dataset_item_partial().
/// Here the computation is done interleaved for better performance.
hash1024 calculate_dataset_item_1024(const epoch_context& context, uint32_t index) noexcept
{
    item_state item0{context, int64_t(index) * 2};
    item_state item1{context, int64_t(index) * 2 + 1};

    //printf("index == %d \n", index);


    for (uint32_t j = 0; j < full_dataset_item_parents; ++j)
    {
        item0.update(j);
        item1.update(j);
    }

    return hash1024{{item0.final(), item1.final()}};
}

hash2048 calculate_dataset_item_2048(const epoch_context& context, uint32_t index) noexcept
{
    item_state item0{context, int64_t(index) * 4};
    item_state item1{context, int64_t(index) * 4 + 1};
    item_state item2{context, int64_t(index) * 4 + 2};
    item_state item3{context, int64_t(index) * 4 + 3};

    for (uint32_t j = 0; j < full_dataset_item_parents; ++j)
    {
        item0.update(j);
        item1.update(j);
        item2.update(j);
        item3.update(j);
    }

    return hash2048{{item0.final(), item1.final(), item2.final(), item3.final()}};
}

namespace
{
using lookup_fn = hash1024 (*)(const epoch_context&, uint32_t);

inline hash512 hash_seed(const hash640& header_hash, uint8_t x16r_algo) noexcept
{
    hash512 mix_tmp;
    uint8_t init_data[sizeof(header_hash)];
    std::memcpy(&init_data[0], &header_hash, sizeof(header_hash));
    //return keccak512(init_data, sizeof(init_data));
    mix_tmp = keccak512(init_data, sizeof(init_data));
    x16r::x16rv2_hash(mix_tmp.str, mix_tmp.str, 1, ((x16r_algo >> 4) & 0xF), sizeof(hash512));
    return mix_tmp;
}

inline hash256 hash_final(const hash512& seed, const hash512& mix_hash)
{ 
    uint8_t final_data[sizeof(seed) + sizeof(mix_hash)];
    std::memcpy(&final_data[0], seed.bytes, sizeof(seed));
    std::memcpy(&final_data[sizeof(seed)], mix_hash.bytes, sizeof(mix_hash));
    return keccak256(final_data, sizeof(final_data));
}

inline hash512 hash_kernel(
    const epoch_context_full& context, const hash512& seed, uint8_t x16r_algo, lookup_fn lookup) noexcept
{
    static constexpr size_t num_words = sizeof(hash1024) / sizeof(uint32_t);
    const uint32_t index_limit = static_cast<uint32_t>(context.full_dataset_num_items);
    const uint32_t seed_init = le::uint32(seed.word32s[0]);
    hash1024 mix{{le::uint32s(seed), le::uint32s(seed)}};
    for (uint32_t i = 0; i < num_dataset_accesses; ++i)
    {
        char * data_sip = mix.str;
        int new_i = i % 8;
        uint64_t sip_out = siphash(mix.word64s[(new_i*2)+1],mix.word64s[new_i*2],data_sip, 128, 1,2);
        const uint32_t p = (uint32_t)sip_out % index_limit;
        //const hash1024 newdata = le::uint32s(context.full_dataset[p]);
        const hash1024 newdata = le::uint32s(lookup(context, p));

        for (size_t j = 0; j < num_words; ++j)
            mix.word32s[j] = fnv1(mix.word32s[j], newdata.word32s[j]);
    }

    hash512 int_hash;
    for (uint32_t i = 0; i < num_words; i += 2)
    {
        int_hash.word32s[i/2] = fnv1(mix.word32s[i], mix.word32s[i + 1]);
    }

    hash512 mix_hash;
    //for (size_t i = 0; i < num_words; i += 4)
    //{
    //    const uint32_t h1 = fnv1(mix.word32s[i], mix.word32s[i + 1]);
    //    const uint32_t h2 = fnv1(h1, mix.word32s[i + 2]);
    //    const uint32_t h3 = fnv1(h2, mix.word32s[i + 3]);
    //    mix_hash.word32s[i / 4] = h3;
    //}
    x16r::x16rv2_hash(int_hash.str, mix_hash.str, 1, (x16r_algo & 0xF), sizeof(hash512));
    //printf("mix_hash == %s\n", to_hex(mix_hash).c_str());
    return mix_hash;
}
}  // namespace

void hash(const char * header_hash_str, uint32_t block_number, char * final_hash_str) noexcept
{
    static const auto lazy_lookup = [](const epoch_context& ctx, uint32_t index) noexcept
    {
        //auto full_dataset = static_cast<const epoch_context_full&>(ctx).full_dataset;
        //hash1024& item = full_dataset[index];
        //if (item.word64s[0] == 0)
        //{
            // TODO: Copy elision here makes it thread-safe?
            hash1024 item = calculate_dataset_item_1024(ctx, index);
        //}

        return item;
    };

    static epoch_context_full_ptr context{nullptr, ethash_destroy_epoch_context_full};
    const int volatile epoch_number = (2250000 + (block_number - RVN_FORK_BLOCK_N)) / epoch_length;

    // Generate Light Cache only first time or when epoch_number has changed
    if (!context || context->epoch_number != epoch_number)
        context = create_epoch_context_full(epoch_number);

    const hash640 header_hash = to_hash640(header_hash_str);
    uint8_t x16r_algo = header_hash.bytes[4];

    const hash512 seed = hash_seed(header_hash, x16r_algo);
    //printf("seed == %s\n", to_hex(seed).c_str());

    const hash512 mix_hash = hash_kernel(*context, seed, x16r_algo, lazy_lookup);
    //printf("mix_hash == %s\n", to_hex(mix_hash).c_str());

    hash256 final_hash = hash_final(seed, mix_hash);

    //printf("final_hash == %s\n", to_hex(final_hash).c_str());

    memcpy(final_hash_str, to_hex(final_hash).c_str(), 32);
}


//search_result search(const epoch_context_full& context, const hash256& header_hash,
//    const hash256& boundary, uint64_t start_nonce, size_t iterations, uint8_t x16r_algo) noexcept
//{
//    const uint64_t end_nonce = start_nonce + iterations;
//    for (uint64_t nonce = start_nonce; nonce < end_nonce; ++nonce)
//    {
//        result r = hash(context, header_hash, nonce, x16r_algo);
//        if (is_less_or_equal(r.final_hash, boundary))
//            return {r, nonce};
//    }
//    return {};
//}
}  // namespace ethash

using namespace ethash;

extern "C" {

ethash_hash256 ethash_calculate_epoch_seed(int epoch_number) noexcept
{
    ethash_hash256 epoch_seed = {};
    for (int i = 0; i < epoch_number; ++i)
        epoch_seed = ethash_keccak256_32(epoch_seed.bytes);
    return epoch_seed;
}

int ethash_calculate_light_cache_num_items(int epoch_number) noexcept
{
    static constexpr int item_size = sizeof(hash512);
    static constexpr int num_items_init = light_cache_init_size / item_size;
    static constexpr int num_items_growth = light_cache_growth / item_size;
    static_assert(
        light_cache_init_size % item_size == 0, "light_cache_init_size not multiple of item size");
    static_assert(
        light_cache_growth % item_size == 0, "light_cache_growth not multiple of item size");

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = ethash_find_largest_prime(num_items_upper_bound);
    return num_items;
}

int ethash_calculate_full_dataset_num_items(int epoch_number) noexcept
{
    static constexpr int item_size = sizeof(hash1024);
    static constexpr int num_items_init = full_dataset_init_size / item_size;
    static constexpr int num_items_growth = full_dataset_growth / item_size;
    static_assert(full_dataset_init_size % item_size == 0,
        "full_dataset_init_size not multiple of item size");
    static_assert(
        full_dataset_growth % item_size == 0, "full_dataset_growth not multiple of item size");

    int num_items_upper_bound = num_items_init + epoch_number * num_items_growth;
    int num_items = ethash_find_largest_prime(num_items_upper_bound);
    return num_items;
}

epoch_context* ethash_create_epoch_context(int epoch_number) noexcept
{
    return generic::create_epoch_context(build_light_cache, epoch_number, false);
}

epoch_context_full* ethash_create_epoch_context_full(int epoch_number) noexcept
{
    return generic::create_epoch_context(build_light_cache, epoch_number, true);
}

void ethash_destroy_epoch_context_full(epoch_context_full* context) noexcept
{
    ethash_destroy_epoch_context(context);
}

void ethash_destroy_epoch_context(epoch_context* context) noexcept
{
    context->~epoch_context();
    std::free(context);
}



bool ethash_verify_final_hash(const hash256* header_hash, const hash256* mix_hash, uint64_t nonce,
    const hash256* boundary, uint8_t x16r_algo) noexcept
{
    // empty body as function is not used
    /*
    const hash512 seed = hash_seed(*header_hash, nonce, x16r_algo);
    return is_less_or_equal(hash_final(seed, *mix_hash, x16r_algo ), *boundary);
    */
}


}  // extern "C"
