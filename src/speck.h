#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>

#define u32 uint32_t
#define u64 uint64_t

#if defined (__AVX2__)	// AVX support ----------------------------------------------------
#define SPECK_ALIGNED_CTX 32
#include <immintrin.h>
#define u256 __m256i
typedef struct {
    u256 rk[34];
    u64 key[34];
} speck_context_t;
/* SSE intrinsic path ONLY for GCC/Clang (__SSE4_2__ via -msse4.2).
 * MSVC x64 (_M_AMD64/_M_X64) deliberately does NOT take this path:
 *   (1) it defines SPECK_CTX_BYVAL, so every speck_ctr() call copies the
 *       816-byte context (34x__m128i + 34xu64) onto the stack by value,
 *       while the pure C path passes a 272-byte context by pointer;
 *   (2) MSVC compiles the shuffle-heavy intrinsics (ROR8/ROL8 via
 *       _mm_shuffle_epi8) measurably worse than GCC.
 * Empirical: with -A1 (no crypto) forward = ~50 Mbps, with MSVC-SSE Speck
 * = 33 Mbps; the pure C scalar path sustains 64 Mbps decrypt on the same
 * i7-2720 (proven earlier).  cnn2n's Windows build uses the pure C path
 * too and reaches 52 Mbps WITH Speck. */
#elif defined (__SSE4_2__) // SSE support (GCC/Clang only — see comment above) -------------------------------------------------
#define SPECK_ALIGNED_CTX 16
#define SPECK_CTX_BYVAL 1
#include <immintrin.h>
#define u128 __m128i
typedef struct {
    u128 rk[34];
    u64 key[34];
} speck_context_t;
#elif defined (__ARM_NEON) && defined (SPECK_ARM_NEON)
#include <arm_neon.h>
#define u128 uint64x2_t
typedef struct {
    u128 rk[34];
    u64 key[34];
} speck_context_t;
#else
typedef struct {
    u64 key[34];
} speck_context_t;
#endif

int speck_ctr(unsigned char *out, const unsigned char *in,
              unsigned long long inlen, const unsigned char *n,
#if defined (SPECK_CTX_BYVAL)
              speck_context_t ctx);
#else
              speck_context_t *ctx);
#endif

int speck_expand_key(const unsigned char *k, speck_context_t *ctx);

#endif