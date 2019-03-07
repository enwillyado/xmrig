/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __CRYPTONIGHT_MONERO_H__
#define __CRYPTONIGHT_MONERO_H__

#ifdef __GNUC__
#include <fenv.h>
#endif

// VARIANT ALTERATIONS
#ifndef XMRIG_ARM
#   define VARIANT1_INIT(part) \
	uint64_t tweak1_2_##part = 0; \
	if (VARIANT == xmrig::VARIANT_V1) { \
		tweak1_2_##part = (*reinterpret_cast<const uint64_t*>(input + 35 + part * size) ^ \
		                   *(reinterpret_cast<const uint64_t*>(ctx[part]->state) + 24)); \
	}
#else
#   define VARIANT1_INIT(part) \
	uint64_t tweak1_2_##part = 0; \
	if (VARIANT == xmrig::VARIANT_V1) { \
		memcpy(&tweak1_2_##part, input + 35 + part * size, sizeof tweak1_2_##part); \
		tweak1_2_##part ^= *(reinterpret_cast<const uint64_t*>(ctx[part]->state) + 24); \
	}
#endif

#define VARIANT1_1(p) \
	if (VARIANT == xmrig::VARIANT_V1) { \
		const uint8_t tmp = reinterpret_cast<const uint8_t*>(p)[11]; \
		static const uint32_t table = 0x75310; \
		const uint8_t index = (((tmp >> 3) & 6) | (tmp & 1)) << 1; \
		((uint8_t*)(p))[11] = tmp ^ ((table >> index) & 0x30); \
	}

#define VARIANT1_2(p, part) \
	if (VARIANT == xmrig::VARIANT_V1) { \
		(p) ^= tweak1_2_##part; \
	}

#ifdef _MSC_VER
#   define VARIANT2_SET_ROUNDING_MODE() if (VARIANT == xmrig::VARIANT_V2 || VARIANT == xmrig::VARIANT_V4) { _control87(RC_DOWN, MCW_RC); }
#else
#   define VARIANT2_SET_ROUNDING_MODE() if (VARIANT == xmrig::VARIANT_V2 || VARIANT == xmrig::VARIANT_V4) { fesetround(FE_DOWNWARD); }
#endif

#if ! defined _WIN64  && defined _WIN32

/* this one was not implemented yet so here it is */
#if  defined(_MSC_VER) && _MSC_VER < 1900
static inline __m128i _mm_cvtsi64_si128(const __int64 & a)
{
	__m128i ret;
	ret.m128i_i64[0] = a;
	return ret;
}
static inline __int64 _mm_cvtsi128_si64(const __m128i & a)
{
	return a.m128i_i64[0];
}
#else
#include <math.h>
static inline __m128i _mm_cvtsi64_si128(const __int64 & a)
{
	__m128i ret;
	unsigned char* retBuffer = (unsigned char*)(&ret);
	for(size_t i = 0; i < sizeof(__int64); ++i)
	{
		retBuffer[i] = ((unsigned char*)&a)[i];
	}
	return ret;
}
static inline __int64 _mm_cvtsi128_si64(const __m128i & a)
{
	return static_cast<uint64_t>(a[0]);
}
#endif

#endif

#   define VARIANT2_INIT(part) \
	__m128i division_result_xmm_##part = _mm_cvtsi64_si128(h##part[12]); \
	__m128i sqrt_result_xmm_##part = _mm_cvtsi64_si128(h##part[13]);


#   define VARIANT2_INTEGER_MATH(part, cl, cx) \
	do { \
		const uint64_t sqrt_result = static_cast<uint64_t>(_mm_cvtsi128_si64(sqrt_result_xmm_##part)); \
		const uint64_t cx_0 = _mm_cvtsi128_si64(cx); \
		cl ^= static_cast<uint64_t>(_mm_cvtsi128_si64(division_result_xmm_##part)) ^ (sqrt_result << 32); \
		const uint32_t d = static_cast<uint32_t>(0xFFFFFFFF & (cx_0 + (sqrt_result << 1))) | 0x80000001UL; \
		const uint64_t cx_1 = _mm_cvtsi128_si64(_mm_srli_si128(cx, 8)); \
		const uint64_t division_result = static_cast<uint32_t>(0xFFFFFFFF & (cx_1 / d)) + ((cx_1 % d) << 32); \
		division_result_xmm_##part = _mm_cvtsi64_si128(static_cast<int64_t>(division_result)); \
		sqrt_result_xmm_##part = int_sqrt_v2(cx_0 + division_result); \
	} while (0)

#   define VARIANT2_SHUFFLE(base_ptr, offset, _a, _b, _b1, _c) \
	do { \
		const __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))); \
		const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
		const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
		if (VARIANT == xmrig::VARIANT_V4) { \
			_c = _mm_xor_si128(_mm_xor_si128(_c, chunk3), _mm_xor_si128(chunk1, chunk2)); \
		} \
	} while (0)

#   define VARIANT2_SHUFFLE2(base_ptr, offset, _a, _b, _b1, hi, lo) \
	do { \
		const __m128i chunk1 = _mm_xor_si128(_mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))), _mm_set_epi64x(lo, hi)); \
		const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
		hi ^= ((uint64_t*)((base_ptr) + ((offset) ^ 0x20)))[0]; \
		lo ^= ((uint64_t*)((base_ptr) + ((offset) ^ 0x20)))[1]; \
		const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
		_mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
	} while (0)


#define SWAP32LE(x) x
#define SWAP64LE(x) x
#define hash_extra_blake(data, length, hash) blake256_hash((uint8_t*)(hash), (uint8_t*)(data), (length))

#ifndef NOINLINE
#ifdef __GNUC__
#define NOINLINE __attribute__ ((noinline))
#elif _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif
#endif

#include "variant4_random_math.h"

#define VARIANT4_RANDOM_MATH_INIT(part) \
	uint32_t r##part[9]; \
	struct V4_Instruction code##part[256]; \
	if (VARIANT == xmrig::VARIANT_V4) { \
		r##part[0] = (uint32_t)(h##part[12] & 0xFFFFFFFF); \
		r##part[1] = (uint32_t)(h##part[12] >> 32); \
		r##part[2] = (uint32_t)(h##part[13] & 0xFFFFFFFF); \
		r##part[3] = (uint32_t)(h##part[13] >> 32); \
	} \
	v4_random_math_init<VARIANT>(code##part, height);

#define VARIANT4_RANDOM_MATH(part, al, ah, cl, bx0, bx1) \
	if (VARIANT == xmrig::VARIANT_V4) { \
		cl ^= (r##part[0] + r##part[1]) | ((uint64_t)(r##part[2] + r##part[3]) << 32); \
		r##part[4] = static_cast<uint32_t>(al & 0xFFFFFFFF); \
		r##part[5] = static_cast<uint32_t>(ah & 0xFFFFFFFF); \
		r##part[6] = static_cast<uint32_t>(_mm_cvtsi128_si32(bx0)); \
		r##part[7] = static_cast<uint32_t>(_mm_cvtsi128_si32(bx1)); \
		r##part[8] = static_cast<uint32_t>(_mm_cvtsi128_si32(_mm_srli_si128(bx1, 8))); \
		v4_random_math(code##part, r##part); \
	}

#endif /* __CRYPTONIGHT_MONERO_H__ */
