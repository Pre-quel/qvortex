/**
 * Qvortex Hash Library
 * 
 * A lightweight cryptographic hash function with S-box and ARX operations.
 * This library version is designed to be compiled as a shared library
 * for integration with Python and other languages.
 */

 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 /* Platform detection for NEON support */
 #if defined(__ARM_NEON) || defined(__ARM_NEON__)
 #include <arm_neon.h>
 #define USE_NEON 1
 #else
 #define USE_NEON 0
 #endif
 
 /* Platform detection for crypto libraries */
 #if defined(__APPLE__)
 #include <CommonCrypto/CommonDigest.h>
 #define HAVE_COMMON_CRYPTO 1
 #else
 #define HAVE_COMMON_CRYPTO 0
 /* Add alternative crypto library includes here if needed */
 #endif
 
 /* Library version */
 #define QVORTEX_VERSION_MAJOR 1
 #define QVORTEX_VERSION_MINOR 0
 #define QVORTEX_VERSION_PATCH 0
 
 /* Hash configuration */
 #define QVORTEX_LITE_STATE_WORDS 8
 #define QVORTEX_LITE_BLOCK_BYTES 64
 #define QVORTEX_LITE_ROUNDS 2
 #define QVORTEX_LITE_DIGEST_BYTES 32  /* Change to 32 bytes (256-bit) output */
 
 /* Fixed rotation constants */
 #define QL_R1 32
 #define QL_R2 24
 #define QL_R3 16
 #define QL_R4 63
 
 /* Error codes */
 #define QVORTEX_SUCCESS 0
 #define QVORTEX_ERROR_NULL_POINTER -1
 #define QVORTEX_ERROR_MEMORY_ALLOCATION -2
 
 /* ------------------------------------------------------------------------
    SHAKE-128 Implementation (Minimal)
    ------------------------------------------------------------------------ */
 
 static inline uint64_t rotl64(uint64_t x, unsigned n) {
   return (x << n) | (x >> (64 - n));
 }
 
 #if USE_NEON
 static inline uint64x2_t rotate_left_64x2(uint64x2_t x, int shift) {
   shift &= 63;  /* Ensure shift is in [0..63] */
   int64x2_t sleft = vdupq_n_s64(shift);
   int64x2_t sright = vdupq_n_s64(-((int64_t)shift));
   uint64x2_t left = vshlq_u64(x, sleft);
   uint64x2_t right = vshlq_u64(x, sright);
   return vorrq_u64(left, right);
 }
 #endif
 
 static const uint64_t KECCAK_RC[24] = {
     0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
     0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
     0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
     0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
     0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
     0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
     0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
     0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
 };
 
 static void keccak_f1600_scalar(uint64_t st[25]) {
   for (int round = 0; round < 24; round++) {
     /* Theta */
     uint64_t bc[5];
     for (int i = 0; i < 5; i++) {
       bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
     }
     for (int i = 0; i < 5; i++) {
       uint64_t t = rotl64(bc[(i + 1) % 5], 1) ^ bc[(i + 4) % 5];
       st[i] ^= t;
       st[i + 5] ^= t;
       st[i + 10] ^= t;
       st[i + 15] ^= t;
       st[i + 20] ^= t;
     }
 
     /* Rho + Pi */
     uint64_t t = st[1];
     static const uint8_t keccak_rho[24] = {1, 3, 6, 10, 15, 21, 28, 36,
                                            45, 55, 2, 14, 27, 41, 56, 8,
                                            25, 43, 62, 18, 39, 61, 20, 44};
     static const uint8_t keccak_pi[24] = {1, 6, 9, 22, 14, 20, 2, 12,
                                           13, 19, 23, 15, 4, 24, 21, 8,
                                           16, 5, 3, 18, 17, 11, 7, 10};
     for (int i = 0; i < 24; i++) {
       int j = keccak_pi[i];
       uint64_t temp = st[j];
       st[j] = rotl64(t, keccak_rho[i]);
       t = temp;
     }
 
     /* Chi */
     for (int j = 0; j < 25; j += 5) {
       uint64_t a0 = st[j + 0], a1 = st[j + 1];
       uint64_t a2 = st[j + 2], a3 = st[j + 3];
       uint64_t a4 = st[j + 4];
       st[j + 0] ^= (~a1) & a2;
       st[j + 1] ^= (~a2) & a3;
       st[j + 2] ^= (~a3) & a4;
       st[j + 3] ^= (~a4) & a0;
       st[j + 4] ^= (~a0) & a1;
     }
 
     /* Iota */
     st[0] ^= KECCAK_RC[round];
   }
 }
 
 #if USE_NEON
 /* NEON-optimized Keccak implementation */
 static void keccak_f1600_neon(uint64_t st[25]) {
   /* Helper macros for NEON registers */
   #define GET_LANE(reg, idx) (vgetq_lane_u64((reg), (idx)))
   #define SET_LANE(reg, idx, val) do { (reg) = vsetq_lane_u64((val), (reg), (idx)); } while (0)
 
   /* Map 25 lanes to 13 NEON registers */
   uint64x2_t r0 = vld1q_u64(&st[0]);
   uint64x2_t r1 = vld1q_u64(&st[2]);
   uint64x2_t r2 = vld1q_u64(&st[4]);
   uint64x2_t r3 = vld1q_u64(&st[6]);
   uint64x2_t r4 = vld1q_u64(&st[8]);
   uint64x2_t r5 = vld1q_u64(&st[10]);
   uint64x2_t r6 = vld1q_u64(&st[12]);
   uint64x2_t r7 = vld1q_u64(&st[14]);
   uint64x2_t r8 = vld1q_u64(&st[16]);
   uint64x2_t r9 = vld1q_u64(&st[18]);
   uint64x2_t r10 = vld1q_u64(&st[20]);
   uint64x2_t r11 = vld1q_u64(&st[22]);
   
   /* Handle the last element separately */
   uint64_t lane24 = st[24];
   uint64x2_t r12 = vcombine_u64(vcreate_u64(lane24), vdup_n_u64(0ULL));
 
   static const uint8_t keccak_rho[24] = {1, 3, 6, 10, 15, 21, 28, 36,
                                          45, 55, 2, 14, 27, 41, 56, 8,
                                          25, 43, 62, 18, 39, 61, 20, 44};
   static const uint8_t keccak_pi[24] = {1, 6, 9, 22, 14, 20, 2, 12,
                                         13, 19, 23, 15, 4, 24, 21, 8,
                                         16, 5, 3, 18, 17, 11, 7, 10};
 
   for (int round = 0; round < 24; round++) {
     /* Extract all 25 lanes as 64-bit variables */
     uint64_t v[25];
     v[0] = GET_LANE(r0, 0);   v[1] = GET_LANE(r0, 1);
     v[2] = GET_LANE(r1, 0);   v[3] = GET_LANE(r1, 1);
     v[4] = GET_LANE(r2, 0);   v[5] = GET_LANE(r2, 1);
     v[6] = GET_LANE(r3, 0);   v[7] = GET_LANE(r3, 1);
     v[8] = GET_LANE(r4, 0);   v[9] = GET_LANE(r4, 1);
     v[10] = GET_LANE(r5, 0);  v[11] = GET_LANE(r5, 1);
     v[12] = GET_LANE(r6, 0);  v[13] = GET_LANE(r6, 1);
     v[14] = GET_LANE(r7, 0);  v[15] = GET_LANE(r7, 1);
     v[16] = GET_LANE(r8, 0);  v[17] = GET_LANE(r8, 1);
     v[18] = GET_LANE(r9, 0);  v[19] = GET_LANE(r9, 1);
     v[20] = GET_LANE(r10, 0); v[21] = GET_LANE(r10, 1);
     v[22] = GET_LANE(r11, 0); v[23] = GET_LANE(r11, 1);
     v[24] = GET_LANE(r12, 0);
 
     /* Theta step */
     uint64_t bc[5];
     for (int i = 0; i < 5; i++) {
       bc[i] = v[i + 0] ^ v[i + 5] ^ v[i + 10] ^ v[i + 15] ^ v[i + 20];
     }
     for (int i = 0; i < 5; i++) {
       uint64_t t = ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63)) ^ bc[(i + 4) % 5];
       v[i + 0] ^= t;
       v[i + 5] ^= t;
       v[i + 10] ^= t;
       v[i + 15] ^= t;
       v[i + 20] ^= t;
     }
 
     /* Rho and Pi steps */
     {
       uint64_t t = v[1];
       for (int i = 0; i < 24; i++) {
         int j = keccak_pi[i];
         uint64_t temp = v[j];
         uint8_t r = keccak_rho[i];
         uint64_t rot = (t << r) | (t >> (64 - r));
         v[j] = rot;
         t = temp;
       }
     }
 
     /* Chi step */
     for (int j = 0; j < 25; j += 5) {
       uint64_t a0 = v[j + 0], a1 = v[j + 1];
       uint64_t a2 = v[j + 2], a3 = v[j + 3];
       uint64_t a4 = v[j + 4];
       v[j + 0] ^= (~a1) & a2;
       v[j + 1] ^= (~a2) & a3;
       v[j + 2] ^= (~a3) & a4;
       v[j + 3] ^= (~a4) & a0;
       v[j + 4] ^= (~a0) & a1;
     }
 
     /* Iota step */
     v[0] ^= KECCAK_RC[round];
 
     /* Store values back to NEON registers */
     SET_LANE(r0, 0, v[0]);   SET_LANE(r0, 1, v[1]);
     SET_LANE(r1, 0, v[2]);   SET_LANE(r1, 1, v[3]);
     SET_LANE(r2, 0, v[4]);   SET_LANE(r2, 1, v[5]);
     SET_LANE(r3, 0, v[6]);   SET_LANE(r3, 1, v[7]);
     SET_LANE(r4, 0, v[8]);   SET_LANE(r4, 1, v[9]);
     SET_LANE(r5, 0, v[10]);  SET_LANE(r5, 1, v[11]);
     SET_LANE(r6, 0, v[12]);  SET_LANE(r6, 1, v[13]);
     SET_LANE(r7, 0, v[14]);  SET_LANE(r7, 1, v[15]);
     SET_LANE(r8, 0, v[16]);  SET_LANE(r8, 1, v[17]);
     SET_LANE(r9, 0, v[18]);  SET_LANE(r9, 1, v[19]);
     SET_LANE(r10, 0, v[20]); SET_LANE(r10, 1, v[21]);
     SET_LANE(r11, 0, v[22]); SET_LANE(r11, 1, v[23]);
     SET_LANE(r12, 0, v[24]);
   }
 
   /* Store back to state array */
   vst1q_u64(&st[0], r0);
   vst1q_u64(&st[2], r1);
   vst1q_u64(&st[4], r2);
   vst1q_u64(&st[6], r3);
   vst1q_u64(&st[8], r4);
   vst1q_u64(&st[10], r5);
   vst1q_u64(&st[12], r6);
   vst1q_u64(&st[14], r7);
   vst1q_u64(&st[16], r8);
   vst1q_u64(&st[18], r9);
   vst1q_u64(&st[20], r10);
   vst1q_u64(&st[22], r11);
   st[24] = GET_LANE(r12, 0);
   
   #undef GET_LANE
   #undef SET_LANE
 }
 #endif /* USE_NEON */
 
 /* Use optimized implementation if available */
 static void keccak_f1600(uint64_t st[25]) {
 #if USE_NEON
   keccak_f1600_neon(st);
 #else
   keccak_f1600_scalar(st);
 #endif
 }
 
 typedef struct {
   uint64_t state[25];
   int rate_used;
 } shake128_ctx;
 
 static inline void shake128_init(shake128_ctx *ctx) {
   memset(ctx->state, 0, sizeof(ctx->state));
   ctx->rate_used = 0;
 }
 
 static inline void shake128_absorb(shake128_ctx *ctx, const uint8_t *in, size_t inlen) {
   const int rate = 168;  /* SHAKE-128 rate in bytes */
   uint8_t *st_bytes = (uint8_t *)ctx->state;
   
   while (inlen > 0) {
     int can_absorb = rate - ctx->rate_used;
     int to_absorb = (inlen < (size_t)can_absorb) ? (int)inlen : can_absorb;
 
     for (int i = 0; i < to_absorb; i++) {
       st_bytes[ctx->rate_used + i] ^= in[i];
     }
 
     ctx->rate_used += to_absorb;
     in += to_absorb;
     inlen -= to_absorb;
 
     if (ctx->rate_used == rate) {
       keccak_f1600(ctx->state);
       ctx->rate_used = 0;
     }
   }
 }
 
 static inline void shake128_finalize(shake128_ctx *ctx) {
   uint8_t *st_bytes = (uint8_t *)ctx->state;
   st_bytes[ctx->rate_used] ^= 0x1F;  /* Domain separation for SHAKE */
   st_bytes[167] ^= 0x80;
   keccak_f1600(ctx->state);
   ctx->rate_used = 0;
 }
 
 static inline void shake128_squeeze(shake128_ctx *ctx, uint8_t *out, size_t outlen) {
   const int rate = 168;
   uint8_t *st_bytes = (uint8_t *)ctx->state;
   
   while (outlen > 0) {
     if (ctx->rate_used == rate) {
       keccak_f1600(ctx->state);
       ctx->rate_used = 0;
     }
     
     int can_take = rate - ctx->rate_used;
     int to_take = (outlen < (size_t)can_take) ? (int)outlen : can_take;
     
     memcpy(out, &st_bytes[ctx->rate_used], to_take);
     ctx->rate_used += to_take;
     out += to_take;
     outlen -= to_take;
   }
 }
 
 static inline void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
   shake128_ctx ctx;
   shake128_init(&ctx);
   shake128_absorb(&ctx, in, inlen);
   shake128_finalize(&ctx);
   shake128_squeeze(&ctx, out, outlen);
 }
 
 /* ------------------------------------------------------------------------
    Qvortex Hash Implementation
    ------------------------------------------------------------------------ */
 
 typedef struct {
   uint64_t state[QVORTEX_LITE_STATE_WORDS];
   uint8_t sbox[256];
   uint8_t buffer[QVORTEX_LITE_BLOCK_BYTES];
   size_t buffer_len;
   uint64_t total_len;
 } qvortex_lite_ctx;
 
 #if USE_NEON
 static inline void qvortex_lite_mix_neon(uint64x2_t *v0, uint64x2_t *v1, 
                                         uint64x2_t *v2, uint64x2_t *v3) {
   /* Round 1 (Diagonal) */
   *v0 = vaddq_u64(*v0, *v1);
   *v3 = veorq_u64(*v3, *v0);
   *v3 = vorrq_u64(vshlq_n_u64(*v3, 64 - QL_R1), vshrq_n_u64(*v3, QL_R1));
 
   *v2 = vaddq_u64(*v2, *v3);
   *v1 = veorq_u64(*v1, *v2);
   *v1 = vorrq_u64(vshlq_n_u64(*v1, 64 - QL_R2), vshrq_n_u64(*v1, QL_R2));
 
   /* Round 2 (Diagonal, different shift) */
   *v0 = vaddq_u64(*v0, *v1);
   *v3 = veorq_u64(*v3, *v0);
   *v3 = vorrq_u64(vshlq_n_u64(*v3, 64 - QL_R3), vshrq_n_u64(*v3, QL_R3));
 
   *v2 = vaddq_u64(*v2, *v3);
   *v1 = veorq_u64(*v1, *v2);
   *v1 = vorrq_u64(vshlq_n_u64(*v1, 64 - QL_R4), vshrq_n_u64(*v1, QL_R4));
 }
 #else
 static inline void qvortex_lite_mix_scalar(uint64_t *s, int a, int b, int c, int d) {
   s[a] = s[a] + s[b];
   s[d] = rotl64(s[d] ^ s[a], QL_R1);
   s[c] = s[c] + s[d];
   s[b] = rotl64(s[b] ^ s[c], QL_R2);
   s[a] = s[a] + s[b];
   s[d] = rotl64(s[d] ^ s[a], QL_R3);
   s[c] = s[c] + s[d];
   s[b] = rotl64(s[b] ^ s[c], QL_R4);
 }
 #endif
 
 static inline void qvortex_lite_process_block(qvortex_lite_ctx *ctx, 
                                              const uint8_t block[QVORTEX_LITE_BLOCK_BYTES]) {
   uint64_t m[QVORTEX_LITE_STATE_WORDS];
   uint8_t temp_block[QVORTEX_LITE_BLOCK_BYTES];
   int i;
 
   /* Substitution step */
   for (i = 0; i < QVORTEX_LITE_BLOCK_BYTES; i++) {
     temp_block[i] = ctx->sbox[block[i]];
   }
   
   /* Load substituted block into message words (little-endian) */
   for (i = 0; i < QVORTEX_LITE_STATE_WORDS; i++) {
     memcpy(&m[i], &temp_block[i * 8], 8);
   }
 
   /* Input-Driven Rotation Mixer (working on a copy of state) */
   uint64_t s_copy[QVORTEX_LITE_STATE_WORDS];
   memcpy(s_copy, ctx->state, sizeof(s_copy));
 
   for (i = 0; i < QVORTEX_LITE_STATE_WORDS; i++) {
     uint8_t rot = (uint8_t)(m[i] >> 56) & 63;  /* Use high 6 bits of m[i] */
     s_copy[i] ^= rotl64(m[i], rot);
   }
 
   /* ARX Mixing Rounds */
 #if USE_NEON
   /* Load state into NEON registers (4 pairs) */
   uint64x2_t v0 = vld1q_u64(&s_copy[0]);
   uint64x2_t v1 = vld1q_u64(&s_copy[2]);
   uint64x2_t v2 = vld1q_u64(&s_copy[4]);
   uint64x2_t v3 = vld1q_u64(&s_copy[6]);
 
   for (int r = 0; r < QVORTEX_LITE_ROUNDS; r++) {
     qvortex_lite_mix_neon(&v0, &v1, &v2, &v3);
     
     /* Simple permutation: rotate state vector */
     uint64x2_t tmp = v0;
     v0 = v1;
     v1 = v2;
     v2 = v3;
     v3 = tmp;
   }
   
   /* Store back to state copy */
   vst1q_u64(&s_copy[0], v0);
   vst1q_u64(&s_copy[2], v1);
   vst1q_u64(&s_copy[4], v2);
   vst1q_u64(&s_copy[6], v3);
 #else
   /* Scalar ARX mixing */
   uint64_t *s = s_copy;
   for (int r = 0; r < QVORTEX_LITE_ROUNDS; r++) {
     /* Apply mixing functions */
     qvortex_lite_mix_scalar(s, 0, 1, 2, 3);
     qvortex_lite_mix_scalar(s, 4, 5, 6, 7);
     
     /* Apply permutation between rounds */
     qvortex_lite_mix_scalar(s, 0, 5, 2, 7);
     qvortex_lite_mix_scalar(s, 4, 1, 6, 3);
     
     /* Rotate state left for next round */
     uint64_t t = s[0];
     memmove(&s[0], &s[1], 7 * sizeof(uint64_t));
     s[7] = t;
   }
 #endif
 
   /* Feed-forward: Add mixed state back to original state */
   for (i = 0; i < QVORTEX_LITE_STATE_WORDS; ++i) {
     ctx->state[i] ^= s_copy[i];
   }
 }
 
 static inline void qvortex_lite_init(qvortex_lite_ctx *ctx, const uint8_t *key, size_t key_len) {
   /* Initialize state with constants */
   static const uint64_t QL_IV[QVORTEX_LITE_STATE_WORDS] = {
     0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL,
     0xA54FF53A5F1D36F1ULL, 0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
     0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
   };
   memcpy(ctx->state, QL_IV, sizeof(ctx->state));
 
   /* Generate the S-box using SHAKE-128 */
   uint8_t sbox_seed[32];
   if (key && key_len > 0) {
     shake128(key, key_len, sbox_seed, 32);
   } else {
     /* Default seed if no key */
     memset(sbox_seed, 0xCC, 32);
   }
   shake128(sbox_seed, 32, ctx->sbox, 256);
 
   /* Initialize buffer state */
   ctx->buffer_len = 0;
   ctx->total_len = 0;
 }
 
 static inline void qvortex_lite_update(qvortex_lite_ctx *ctx, const uint8_t *data, size_t len) {
   ctx->total_len += len;
   size_t data_off = 0;
 
   /* Process remaining buffer first */
   if (ctx->buffer_len > 0) {
     size_t needed = QVORTEX_LITE_BLOCK_BYTES - ctx->buffer_len;
     size_t can_copy = (len < needed) ? len : needed;
     
     memcpy(&ctx->buffer[ctx->buffer_len], data, can_copy);
     ctx->buffer_len += can_copy;
     data_off += can_copy;
     len -= can_copy;
 
     if (ctx->buffer_len == QVORTEX_LITE_BLOCK_BYTES) {
       qvortex_lite_process_block(ctx, ctx->buffer);
       ctx->buffer_len = 0;
     }
   }
 
   /* Process full blocks */
   while (len >= QVORTEX_LITE_BLOCK_BYTES) {
     qvortex_lite_process_block(ctx, data + data_off);
     data_off += QVORTEX_LITE_BLOCK_BYTES;
     len -= QVORTEX_LITE_BLOCK_BYTES;
   }
 
   /* Copy remaining data to buffer */
   if (len > 0) {
     memcpy(ctx->buffer, data + data_off, len);
     ctx->buffer_len = len;
   }
 }
 
 static inline void qvortex_lite_final(qvortex_lite_ctx *ctx, uint8_t out[QVORTEX_LITE_DIGEST_BYTES]) {
   /* Padding: Append 0x80, then zeros, then length */
   size_t current_len = ctx->buffer_len;
   ctx->buffer[current_len++] = 0x80;  /* Append 1 bit (0x80 byte) */
 
   /* Zero pad until space for length encoding */
   size_t pad_zeros = QVORTEX_LITE_BLOCK_BYTES - (current_len % QVORTEX_LITE_BLOCK_BYTES);
   if (pad_zeros < 8) {  /* Need at least 8 bytes for length */
     pad_zeros += QVORTEX_LITE_BLOCK_BYTES;
   }
   pad_zeros -= 8;  /* Reserve space for length */
 
   if (current_len + pad_zeros > QVORTEX_LITE_BLOCK_BYTES) {
     memset(&ctx->buffer[current_len], 0, QVORTEX_LITE_BLOCK_BYTES - current_len);
     qvortex_lite_process_block(ctx, ctx->buffer);
     current_len = 0;
     memset(ctx->buffer, 0, QVORTEX_LITE_BLOCK_BYTES);
   } else {
     memset(&ctx->buffer[current_len], 0, pad_zeros);
   }
   current_len += pad_zeros;
 
   /* Append total length in bits (little-endian 64-bit) */
   uint64_t total_bits = ctx->total_len * 8;
   memcpy(&ctx->buffer[QVORTEX_LITE_BLOCK_BYTES - 8], &total_bits, 8);
 
   /* Process the final padded block */
   qvortex_lite_process_block(ctx, ctx->buffer);
 
   /* Output: First N bytes of the state (little-endian) */
   uint8_t *state_bytes = (uint8_t *)ctx->state;
   memcpy(out, state_bytes, QVORTEX_LITE_DIGEST_BYTES);
 
   /* Zeroize context state for security */
   memset(ctx, 0, sizeof(qvortex_lite_ctx));
 }
 
 /* ------------------------------------------------------------------------
    Public API Functions (with C linkage)
    ------------------------------------------------------------------------ */
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 /**
  * One-shot hash function for Qvortex
  *
  * @param data            Input data to hash
  * @param len             Length of input data
  * @param blocks_per_sbox Legacy parameter (not used in Qvortex)
  * @param use_precomputed Legacy parameter (not used in Qvortex)
  * @param key             Optional key for keyed hashing
  * @param key_len         Length of key
  * @param out             Output buffer (32 bytes)
  *
  * @return 0 on success, non-zero on error
  */
 int qvortex_hash(const uint8_t *data, size_t len,
                 int blocks_per_sbox, int use_precomputed,
                 const uint8_t *key, size_t key_len,
                 uint8_t out[QVORTEX_LITE_DIGEST_BYTES]) {
   
   /* Parameter validation */
   if (!data && len > 0) return QVORTEX_ERROR_NULL_POINTER;
   if (!out) return QVORTEX_ERROR_NULL_POINTER;
   
   /* Backward compatibility with old VortexHash API, but using new QvortexLite */
   qvortex_lite_ctx ctx;
   qvortex_lite_init(&ctx, key, key_len);
   qvortex_lite_update(&ctx, data, len);
   qvortex_lite_final(&ctx, out);
   
   return QVORTEX_SUCCESS;
 }
 
 /**
  * Initialize a Qvortex context
  * 
  * @param ctx     Pointer to context structure
  * @param key     Optional key for keyed hashing
  * @param key_len Length of key
  * 
  * @return 0 on success, non-zero on error
  */
 int qvortex_init(qvortex_lite_ctx *ctx, const uint8_t *key, size_t key_len) {
   if (!ctx) return QVORTEX_ERROR_NULL_POINTER;
   
   qvortex_lite_init(ctx, key, key_len);
   return QVORTEX_SUCCESS;
 }
 
 /**
  * Update a Qvortex context with new data
  * 
  * @param ctx  Pointer to context structure
  * @param data Input data to hash
  * @param len  Length of input data
  * 
  * @return 0 on success, non-zero on error
  */
 int qvortex_update(qvortex_lite_ctx *ctx, const uint8_t *data, size_t len) {
   if (!ctx) return QVORTEX_ERROR_NULL_POINTER;
   if (!data && len > 0) return QVORTEX_ERROR_NULL_POINTER;
   
   qvortex_lite_update(ctx, data, len);
   return QVORTEX_SUCCESS;
 }
 
 /**
  * Finalize a Qvortex context and output the digest
  * 
  * @param ctx Pointer to context structure
  * @param out Output buffer (32 bytes)
  * 
  * @return 0 on success, non-zero on error
  */
 int qvortex_final(qvortex_lite_ctx *ctx, uint8_t out[QVORTEX_LITE_DIGEST_BYTES]) {
   if (!ctx) return QVORTEX_ERROR_NULL_POINTER;
   if (!out) return QVORTEX_ERROR_NULL_POINTER;
   
   qvortex_lite_final(ctx, out);
   return QVORTEX_SUCCESS;
 }
 
 /**
  * Return the version string of the Qvortex implementation
  * 
  * @return Version string
  */
 const char* qvortex_version(void) {
   static char version[16];
   snprintf(version, sizeof(version), "%d.%d.%d", 
            QVORTEX_VERSION_MAJOR, 
            QVORTEX_VERSION_MINOR, 
            QVORTEX_VERSION_PATCH);
   return version;
 }
 
 /* Backward compatibility with old VortexHash API */
 int vortex_hash(const uint8_t *data, size_t len,
                int blocks_per_sbox, int use_precomputed,
                const uint8_t *key, size_t key_len,
                uint8_t out[32]) {
   return qvortex_hash(data, len, blocks_per_sbox, use_precomputed, key, key_len, out);
 }
 
 #ifdef __cplusplus
 }
 #endif