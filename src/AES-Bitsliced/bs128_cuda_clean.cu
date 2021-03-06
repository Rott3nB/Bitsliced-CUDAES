#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <inttypes.h>
#include <stddef.h>
#include <assert.h>

#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include "cuda_runtime_api.h"

#define bs2le(x) (x)
#define bs2be(x) (x)

#define THREADNUM           256
#define BLOCK_SIZE          128
#define KEY_SCHEDULE_SIZE   176
#define WORD_SIZE           64
#define BS_BLOCK_SIZE       (BLOCK_SIZE * WORD_SIZE / 8)
#define WORDS_PER_BLOCK     (BLOCK_SIZE / WORD_SIZE)

#if (WORD_SIZE==64)
using word_t = uint64_t;
#define ONE         1ULL
#define MUL_SHIFT   6
#define WFMT        "lx"
#define WPAD        "016"
#define __builtin_bswap_wordsize(x) __builtin_bswap64(x)
#endif


#define R0          0
#define R1          8
#define R2          16
#define R3          24

#define B0          0
#define B1          32
#define B2          64
#define B3          96

#define R0_shift        (BLOCK_SIZE/4)*0
#define R1_shift        (BLOCK_SIZE/4)*1
#define R2_shift        (BLOCK_SIZE/4)*2
#define R3_shift        (BLOCK_SIZE/4)*3
#define B_MOD           (BLOCK_SIZE)

#define gpuErrchk(ans) { gpuAssert((ans), __FILE__, __LINE__); }

inline void gpuAssert(cudaError_t code, const char* file, int line, bool abort = true)
{
	if (code != cudaSuccess)
	{
		fprintf(stderr, "GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
		if (abort) exit(code);
	}
}

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static void rotate(unsigned char* in)
{
	unsigned char a, c;
	a = in[0];
	for (c = 0; c < 3; c++)
		in[c] = in[c + 1];
	in[3] = a;
}

static unsigned char rcon(unsigned char in)
{
	unsigned char c = 1;
	if (in == 0)
		return 0;
	while (in != 1)
	{
		unsigned char b;
		b = c & 0x80;
		c <<= 1;
		if (b == 0x80)
		{
			c ^= 0x1b;
		}
		in--;
	}
	return c;
}

static void schedule_core(unsigned char* in, unsigned char i)
{
	char a;
	rotate(in);
	for (a = 0; a < 4; a++)
		in[a] = sbox[in[a]];
	in[0] ^= rcon(i);
}

void expand_key(unsigned char* in)
{
	unsigned char t[4];
	unsigned char c = 16;
	unsigned char i = 1;
	unsigned char a;

	while (c < 176)
	{
		for (a = 0; a < 4; a++)
			t[a] = in[a + c - 4];
		if (c % 16 == 0)
		{
			schedule_core(t, i);
			i++;
		}
		for (a = 0; a < 4; a++)
		{
			in[c] = in[c - 16] ^ t[a];
			c++;
		}
	}
}


__device__ __host__ void bs_addroundkey(word_t* B, word_t* rk)
{
	int i;
	for (i = 0; i < BLOCK_SIZE; i++)
		B[i] ^= rk[i];
}

__device__ __host__ void bs_sbox(word_t U[8])
{
	word_t
		T1, T2, T3, T4, T5, T6, T7, T8,
		T9, T10, T11, T12, T13, T14, T15, T16,
		T17, T18, T19, T20, T21, T22, T23, T24,
		T25, T26, T27;

	word_t
		M1, M2, M3, M4, M5, M6, M7, M8,
		M9, M10, M11, M12, M13, M14, M15,
		M16, M17, M18, M19, M20, M21, M22,
		M23, M24, M25, M26, M27, M28, M29,
		M30, M31, M32, M33, M34, M35, M36,
		M37, M38, M39, M40, M41, M42, M43,
		M44, M45, M46, M47, M48, M49, M50,
		M51, M52, M53, M54, M55, M56, M57,
		M58, M59, M60, M61, M62, M63;

	word_t
		L0, L1, L2, L3, L4, L5, L6, L7, L8,
		L9, L10, L11, L12, L13, L14,
		L15, L16, L17, L18, L19, L20,
		L21, L22, L23, L24, L25, L26,
		L27, L28, L29;

	T1 = U[7] ^ U[4];
	T2 = U[7] ^ U[2];
	T3 = U[7] ^ U[1];
	T4 = U[4] ^ U[2];
	T5 = U[3] ^ U[1];
	T6 = T1 ^ T5;
	T7 = U[6] ^ U[5];
	T8 = U[0] ^ T6;
	T9 = U[0] ^ T7;
	T10 = T6 ^ T7;
	T11 = U[6] ^ U[2];
	T12 = U[5] ^ U[2];
	T13 = T3 ^ T4;
	T14 = T6 ^ T11;
	T15 = T5 ^ T11;
	T16 = T5 ^ T12;
	T17 = T9 ^ T16;
	T18 = U[4] ^ U[0];
	T19 = T7 ^ T18;
	T20 = T1 ^ T19;
	T21 = U[1] ^ U[0];
	T22 = T7 ^ T21;
	T23 = T2 ^ T22;
	T24 = T2 ^ T10;
	T25 = T20 ^ T17;
	T26 = T3 ^ T16;
	T27 = T1 ^ T12;
	M1 = T13 & T6;
	M2 = T23 & T8;
	M3 = T14 ^ M1;
	M4 = T19 & U[0];
	M5 = M4 ^ M1;
	M6 = T3 & T16;
	M7 = T22 & T9;
	M8 = T26 ^ M6;
	M9 = T20 & T17;
	M10 = M9 ^ M6;
	M11 = T1 & T15;
	M12 = T4 & T27;
	M13 = M12 ^ M11;
	M14 = T2 & T10;
	M15 = M14 ^ M11;
	M16 = M3 ^ M2;
	M17 = M5 ^ T24;
	M18 = M8 ^ M7;
	M19 = M10 ^ M15;
	M20 = M16 ^ M13;
	M21 = M17 ^ M15;
	M22 = M18 ^ M13;
	M23 = M19 ^ T25;
	M24 = M22 ^ M23;
	M25 = M22 & M20;
	M26 = M21 ^ M25;
	M27 = M20 ^ M21;
	M28 = M23 ^ M25;
	M29 = M28 & M27;
	M30 = M26 & M24;
	M31 = M20 & M23;
	M32 = M27 & M31;
	M33 = M27 ^ M25;
	M34 = M21 & M22;
	M35 = M24 & M34;
	M36 = M24 ^ M25;
	M37 = M21 ^ M29;
	M38 = M32 ^ M33;
	M39 = M23 ^ M30;
	M40 = M35 ^ M36;
	M41 = M38 ^ M40;
	M42 = M37 ^ M39;
	M43 = M37 ^ M38;
	M44 = M39 ^ M40;
	M45 = M42 ^ M41;
	M46 = M44 & T6;
	M47 = M40 & T8;
	M48 = M39 & U[0];
	M49 = M43 & T16;
	M50 = M38 & T9;
	M51 = M37 & T17;
	M52 = M42 & T15;
	M53 = M45 & T27;
	M54 = M41 & T10;
	M55 = M44 & T13;
	M56 = M40 & T23;
	M57 = M39 & T19;
	M58 = M43 & T3;
	M59 = M38 & T22;
	M60 = M37 & T20;
	M61 = M42 & T1;
	M62 = M45 & T4;
	M63 = M41 & T2;
	L0 = M61 ^ M62;
	L1 = M50 ^ M56;
	L2 = M46 ^ M48;
	L3 = M47 ^ M55;
	L4 = M54 ^ M58;
	L5 = M49 ^ M61;
	L6 = M62 ^ L5;
	L7 = M46 ^ L3;
	L8 = M51 ^ M59;
	L9 = M52 ^ M53;
	L10 = M53 ^ L4;
	L11 = M60 ^ L2;
	L12 = M48 ^ M51;
	L13 = M50 ^ L0;
	L14 = M52 ^ M61;
	L15 = M55 ^ L1;
	L16 = M56 ^ L0;
	L17 = M57 ^ L1;
	L18 = M58 ^ L8;
	L19 = M63 ^ L4;
	L20 = L0 ^ L1;
	L21 = L1 ^ L7;
	L22 = L3 ^ L12;
	L23 = L18 ^ L2;
	L24 = L15 ^ L9;
	L25 = L6 ^ L10;
	L26 = L7 ^ L9;
	L27 = L8 ^ L10;
	L28 = L11 ^ L14;
	L29 = L11 ^ L17;
	U[7] = L6 ^ L24;
	U[6] = ~(L16 ^ L26);
	U[5] = ~(L19 ^ L28);
	U[4] = L6 ^ L21;
	U[3] = L20 ^ L22;
	U[2] = L25 ^ L29;
	U[1] = ~(L13 ^ L27);
	U[0] = ~(L6 ^ L23);
}


__device__ __host__ void bs_apply_sbox(word_t* input)
{
	int i;
	for (i = 0; i < BLOCK_SIZE; i += 8)
	{
		bs_sbox(input + i);
	}
}


__device__ __host__ void bs_transpose_rev(word_t* blocks)
{
	int k;
	word_t w;
	word_t transpose[BLOCK_SIZE];
	memset(transpose, 0, sizeof(transpose));
	for (k = 0; k < BLOCK_SIZE; k++)
	{
		w = blocks[k];
		word_t bitpos = bs2be(ONE << (k % WORD_SIZE));
		word_t offset = k / WORD_SIZE;
#ifndef UNROLL_TRANSPOSE
		int j;
		for (j = 0; j < WORD_SIZE; j++)
		{
			word_t bit = (w & (ONE << j)) ? (ONE << (k % WORD_SIZE)) : 0;
			transpose[j * WORDS_PER_BLOCK + (offset)] |= bit;
		}
#else
        transpose[0 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 0)) ? bitpos : 0;
        transpose[1 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 1)) ? bitpos : 0;
        transpose[2 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 2)) ? bitpos : 0;
        transpose[3 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 3)) ? bitpos : 0;
        transpose[4 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 4)) ? bitpos : 0;
        transpose[5 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 5)) ? bitpos : 0;
        transpose[6 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 6)) ? bitpos : 0;
        transpose[7 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 7)) ? bitpos : 0;
#if WORD_SIZE > 8
        transpose[8 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 8)) ? bitpos : 0;
        transpose[9 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 9)) ? bitpos : 0;
        transpose[10 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 10)) ? bitpos : 0;
        transpose[11 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 11)) ? bitpos : 0;
        transpose[12 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 12)) ? bitpos : 0;
        transpose[13 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 13)) ? bitpos : 0;
        transpose[14 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 14)) ? bitpos : 0;
        transpose[15 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 15)) ? bitpos : 0;
#endif
#if WORD_SIZE > 16
        transpose[16 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 16)) ? bitpos : 0;
        transpose[17 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 17)) ? bitpos : 0;
        transpose[18 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 18)) ? bitpos : 0;
        transpose[19 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 19)) ? bitpos : 0;
        transpose[20 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 20)) ? bitpos : 0;
        transpose[21 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 21)) ? bitpos : 0;
        transpose[22 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 22)) ? bitpos : 0;
        transpose[23 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 23)) ? bitpos : 0;
        transpose[24 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 24)) ? bitpos : 0;
        transpose[25 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 25)) ? bitpos : 0;
        transpose[26 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 26)) ? bitpos : 0;
        transpose[27 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 27)) ? bitpos : 0;
        transpose[28 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 28)) ? bitpos : 0;
        transpose[29 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 29)) ? bitpos : 0;
        transpose[30 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 30)) ? bitpos : 0;
        transpose[31 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 31)) ? bitpos : 0;
#endif
#if WORD_SIZE > 32
        transpose[32 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 32)) ? bitpos : 0;
        transpose[33 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 33)) ? bitpos : 0;
        transpose[34 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 34)) ? bitpos : 0;
        transpose[35 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 35)) ? bitpos : 0;
        transpose[36 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 36)) ? bitpos : 0;
        transpose[37 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 37)) ? bitpos : 0;
        transpose[38 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 38)) ? bitpos : 0;
        transpose[39 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 39)) ? bitpos : 0;
        transpose[40 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 40)) ? bitpos : 0;
        transpose[41 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 41)) ? bitpos : 0;
        transpose[42 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 42)) ? bitpos : 0;
        transpose[43 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 43)) ? bitpos : 0;
        transpose[44 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 44)) ? bitpos : 0;
        transpose[45 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 45)) ? bitpos : 0;
        transpose[46 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 46)) ? bitpos : 0;
        transpose[47 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 47)) ? bitpos : 0;
        transpose[48 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 48)) ? bitpos : 0;
        transpose[49 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 49)) ? bitpos : 0;
        transpose[50 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 50)) ? bitpos : 0;
        transpose[51 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 51)) ? bitpos : 0;
        transpose[52 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 52)) ? bitpos : 0;
        transpose[53 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 53)) ? bitpos : 0;
        transpose[54 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 54)) ? bitpos : 0;
        transpose[55 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 55)) ? bitpos : 0;
        transpose[56 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 56)) ? bitpos : 0;
        transpose[57 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 57)) ? bitpos : 0;
        transpose[58 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 58)) ? bitpos : 0;
        transpose[59 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 59)) ? bitpos : 0;
        transpose[60 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 60)) ? bitpos : 0;
        transpose[61 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 61)) ? bitpos : 0;
        transpose[62 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 62)) ? bitpos : 0;
        transpose[63 * WORDS_PER_BLOCK + (offset)] |= (w & (ONE << 63)) ? bitpos : 0;
#endif
#endif
	}
	for (int i = 0; i < sizeof(transpose) / sizeof(word_t); i++)
	{
		blocks[i] = transpose[i];
	}
}


__device__ __host__ void bs_transpose_dst(word_t* transpose, word_t* blocks)
{
	int i, k;
	word_t w;
	for (k = 0; k < WORD_SIZE; k++)
	{
		int bitpos = ONE << k;
		for (i = 0; i < WORDS_PER_BLOCK; i++)
		{
			w = bs2le(blocks[k * WORDS_PER_BLOCK + i]);
			int offset = i << MUL_SHIFT;

#ifndef UNROLL_TRANSPOSE
			int j;
			for (j = 0; j < WORD_SIZE; j++)
			{
				// TODO make const time
				transpose[offset + j] |= (w & (ONE << j)) ? bitpos : 0;
			}
#else

            transpose[(offset)+0] |= (w & (ONE << 0)) ? (bitpos) : 0;
            transpose[(offset)+1] |= (w & (ONE << 1)) ? (bitpos) : 0;
            transpose[(offset)+2] |= (w & (ONE << 2)) ? (bitpos) : 0;
            transpose[(offset)+3] |= (w & (ONE << 3)) ? (bitpos) : 0;
            transpose[(offset)+4] |= (w & (ONE << 4)) ? (bitpos) : 0;
            transpose[(offset)+5] |= (w & (ONE << 5)) ? (bitpos) : 0;
            transpose[(offset)+6] |= (w & (ONE << 6)) ? (bitpos) : 0;
            transpose[(offset)+7] |= (w & (ONE << 7)) ? (bitpos) : 0;
#if WORD_SIZE > 8
            transpose[(offset)+8] |= (w & (ONE << 8)) ? (bitpos) : 0;
            transpose[(offset)+9] |= (w & (ONE << 9)) ? (bitpos) : 0;
            transpose[(offset)+10] |= (w & (ONE << 10)) ? (bitpos) : 0;
            transpose[(offset)+11] |= (w & (ONE << 11)) ? (bitpos) : 0;
            transpose[(offset)+12] |= (w & (ONE << 12)) ? (bitpos) : 0;
            transpose[(offset)+13] |= (w & (ONE << 13)) ? (bitpos) : 0;
            transpose[(offset)+14] |= (w & (ONE << 14)) ? (bitpos) : 0;
            transpose[(offset)+15] |= (w & (ONE << 15)) ? (bitpos) : 0;
#endif
#if WORD_SIZE > 16
            transpose[(offset)+16] |= (w & (ONE << 16)) ? (bitpos) : 0;
            transpose[(offset)+17] |= (w & (ONE << 17)) ? (bitpos) : 0;
            transpose[(offset)+18] |= (w & (ONE << 18)) ? (bitpos) : 0;
            transpose[(offset)+19] |= (w & (ONE << 19)) ? (bitpos) : 0;
            transpose[(offset)+20] |= (w & (ONE << 20)) ? (bitpos) : 0;
            transpose[(offset)+21] |= (w & (ONE << 21)) ? (bitpos) : 0;
            transpose[(offset)+22] |= (w & (ONE << 22)) ? (bitpos) : 0;
            transpose[(offset)+23] |= (w & (ONE << 23)) ? (bitpos) : 0;
            transpose[(offset)+24] |= (w & (ONE << 24)) ? (bitpos) : 0;
            transpose[(offset)+25] |= (w & (ONE << 25)) ? (bitpos) : 0;
            transpose[(offset)+26] |= (w & (ONE << 26)) ? (bitpos) : 0;
            transpose[(offset)+27] |= (w & (ONE << 27)) ? (bitpos) : 0;
            transpose[(offset)+28] |= (w & (ONE << 28)) ? (bitpos) : 0;
            transpose[(offset)+29] |= (w & (ONE << 29)) ? (bitpos) : 0;
            transpose[(offset)+30] |= (w & (ONE << 30)) ? (bitpos) : 0;
            transpose[(offset)+31] |= (w & (ONE << 31)) ? (bitpos) : 0;
#endif
#if WORD_SIZE > 32
            transpose[(offset)+32] |= (w & (ONE << 32)) ? (bitpos) : 0;
            transpose[(offset)+33] |= (w & (ONE << 33)) ? (bitpos) : 0;
            transpose[(offset)+34] |= (w & (ONE << 34)) ? (bitpos) : 0;
            transpose[(offset)+35] |= (w & (ONE << 35)) ? (bitpos) : 0;
            transpose[(offset)+36] |= (w & (ONE << 36)) ? (bitpos) : 0;
            transpose[(offset)+37] |= (w & (ONE << 37)) ? (bitpos) : 0;
            transpose[(offset)+38] |= (w & (ONE << 38)) ? (bitpos) : 0;
            transpose[(offset)+39] |= (w & (ONE << 39)) ? (bitpos) : 0;
            transpose[(offset)+40] |= (w & (ONE << 40)) ? (bitpos) : 0;
            transpose[(offset)+41] |= (w & (ONE << 41)) ? (bitpos) : 0;
            transpose[(offset)+42] |= (w & (ONE << 42)) ? (bitpos) : 0;
            transpose[(offset)+43] |= (w & (ONE << 43)) ? (bitpos) : 0;
            transpose[(offset)+44] |= (w & (ONE << 44)) ? (bitpos) : 0;
            transpose[(offset)+45] |= (w & (ONE << 45)) ? (bitpos) : 0;
            transpose[(offset)+46] |= (w & (ONE << 46)) ? (bitpos) : 0;
            transpose[(offset)+47] |= (w & (ONE << 47)) ? (bitpos) : 0;
            transpose[(offset)+48] |= (w & (ONE << 48)) ? (bitpos) : 0;
            transpose[(offset)+49] |= (w & (ONE << 49)) ? (bitpos) : 0;
            transpose[(offset)+50] |= (w & (ONE << 50)) ? (bitpos) : 0;
            transpose[(offset)+51] |= (w & (ONE << 51)) ? (bitpos) : 0;
            transpose[(offset)+52] |= (w & (ONE << 52)) ? (bitpos) : 0;
            transpose[(offset)+53] |= (w & (ONE << 53)) ? (bitpos) : 0;
            transpose[(offset)+54] |= (w & (ONE << 54)) ? (bitpos) : 0;
            transpose[(offset)+55] |= (w & (ONE << 55)) ? (bitpos) : 0;
            transpose[(offset)+56] |= (w & (ONE << 56)) ? (bitpos) : 0;
            transpose[(offset)+57] |= (w & (ONE << 57)) ? (bitpos) : 0;
            transpose[(offset)+58] |= (w & (ONE << 58)) ? (bitpos) : 0;
            transpose[(offset)+59] |= (w & (ONE << 59)) ? (bitpos) : 0;
            transpose[(offset)+60] |= (w & (ONE << 60)) ? (bitpos) : 0;
            transpose[(offset)+61] |= (w & (ONE << 61)) ? (bitpos) : 0;
            transpose[(offset)+62] |= (w & (ONE << 62)) ? (bitpos) : 0;
            transpose[(offset)+63] |= (w & (ONE << 63)) ? (bitpos) : 0;
#endif
#endif
			// constant time:
			//transpose[(i<<MUL_SHIFT)+ j] |= (((int64_t)((w & (ONE << j)) << (WORD_SIZE-1-j)))>>(WORD_SIZE-1)) & (ONE<<k);
		}
	}
}

__device__ __host__ void bs_transpose(word_t* blocks)
{
	word_t transpose[BLOCK_SIZE];
	memset(transpose, 0, sizeof(transpose));
	bs_transpose_dst(transpose, blocks);

	for (int i = 0; i < sizeof(transpose) / sizeof(word_t); i++)
	{
		blocks[i] = transpose[i];
	}
}


__device__ __host__ void bs_shiftrows(word_t* B)
{
	word_t Bp_space[BLOCK_SIZE];
	word_t* Bp = Bp_space;
	word_t* Br0 = B + 0;
	word_t* Br1 = B + 32;
	word_t* Br2 = B + 64;
	word_t* Br3 = B + 96;
	uint8_t offsetr0 = 0;
	uint8_t offsetr1 = 32;
	uint8_t offsetr2 = 64;
	uint8_t offsetr3 = 96;


	int i;
	for (i = 0; i < 4; i++)
	{
		Bp[B0 + 0] = Br0[0];
		Bp[B0 + 1] = Br0[1];
		Bp[B0 + 2] = Br0[2];
		Bp[B0 + 3] = Br0[3];
		Bp[B0 + 4] = Br0[4];
		Bp[B0 + 5] = Br0[5];
		Bp[B0 + 6] = Br0[6];
		Bp[B0 + 7] = Br0[7];
		Bp[B1 + 0] = Br1[0];
		Bp[B1 + 1] = Br1[1];
		Bp[B1 + 2] = Br1[2];
		Bp[B1 + 3] = Br1[3];
		Bp[B1 + 4] = Br1[4];
		Bp[B1 + 5] = Br1[5];
		Bp[B1 + 6] = Br1[6];
		Bp[B1 + 7] = Br1[7];
		Bp[B2 + 0] = Br2[0];
		Bp[B2 + 1] = Br2[1];
		Bp[B2 + 2] = Br2[2];
		Bp[B2 + 3] = Br2[3];
		Bp[B2 + 4] = Br2[4];
		Bp[B2 + 5] = Br2[5];
		Bp[B2 + 6] = Br2[6];
		Bp[B2 + 7] = Br2[7];
		Bp[B3 + 0] = Br3[0];
		Bp[B3 + 1] = Br3[1];
		Bp[B3 + 2] = Br3[2];
		Bp[B3 + 3] = Br3[3];
		Bp[B3 + 4] = Br3[4];
		Bp[B3 + 5] = Br3[5];
		Bp[B3 + 6] = Br3[6];
		Bp[B3 + 7] = Br3[7];

		offsetr0 = (offsetr0 + BLOCK_SIZE / 16 + BLOCK_SIZE / 4) & 0x7f;
		offsetr1 = (offsetr1 + BLOCK_SIZE / 16 + BLOCK_SIZE / 4) & 0x7f;
		offsetr2 = (offsetr2 + BLOCK_SIZE / 16 + BLOCK_SIZE / 4) & 0x7f;
		offsetr3 = (offsetr3 + BLOCK_SIZE / 16 + BLOCK_SIZE / 4) & 0x7f;

		Br0 = B + offsetr0;
		Br1 = B + offsetr1;
		Br2 = B + offsetr2;
		Br3 = B + offsetr3;

		Bp += 8;
	}
	for (int i = 0; i < sizeof(Bp_space) / sizeof(word_t); i++)
	{
		B[i] = Bp_space[i];
	}
}


#define A0  0
#define A1  8
#define A2  16
#define A3  24

__device__ __host__ void bs_mixcolumns(word_t* B)
{
	word_t Bp_space[BLOCK_SIZE];
	word_t* Bp = Bp_space;

	int i = 0;
	for (; i < 4; i++)
	{
		word_t of = B[A0 + 7] ^ B[A1 + 7];

		Bp[A0 + 0] = B[A1 + 0] ^ B[A2 + 0] ^ B[A3 + 0] ^ of;
		Bp[A0 + 1] = B[A0 + 0] ^ B[A1 + 0] ^ B[A1 + 1] ^ B[A2 + 1] ^ B[A3 + 1] ^ of;
		Bp[A0 + 2] = B[A0 + 1] ^ B[A1 + 1] ^ B[A1 + 2] ^ B[A2 + 2] ^ B[A3 + 2];
		Bp[A0 + 3] = B[A0 + 2] ^ B[A1 + 2] ^ B[A1 + 3] ^ B[A2 + 3] ^ B[A3 + 3] ^ of;
		Bp[A0 + 4] = B[A0 + 3] ^ B[A1 + 3] ^ B[A1 + 4] ^ B[A2 + 4] ^ B[A3 + 4] ^ of;
		Bp[A0 + 5] = B[A0 + 4] ^ B[A1 + 4] ^ B[A1 + 5] ^ B[A2 + 5] ^ B[A3 + 5];
		Bp[A0 + 6] = B[A0 + 5] ^ B[A1 + 5] ^ B[A1 + 6] ^ B[A2 + 6] ^ B[A3 + 6];
		Bp[A0 + 7] = B[A0 + 6] ^ B[A1 + 6] ^ B[A1 + 7] ^ B[A2 + 7] ^ B[A3 + 7];

		of = B[A1 + 7] ^ B[A2 + 7];

		Bp[A1 + 0] = B[A0 + 0] ^ B[A2 + 0] ^ B[A3 + 0] ^ of;
		Bp[A1 + 1] = B[A0 + 1] ^ B[A1 + 0] ^ B[A2 + 0] ^ B[A2 + 1] ^ B[A3 + 1] ^ of;
		Bp[A1 + 2] = B[A0 + 2] ^ B[A1 + 1] ^ B[A2 + 1] ^ B[A2 + 2] ^ B[A3 + 2];
		Bp[A1 + 3] = B[A0 + 3] ^ B[A1 + 2] ^ B[A2 + 2] ^ B[A2 + 3] ^ B[A3 + 3] ^ of;
		Bp[A1 + 4] = B[A0 + 4] ^ B[A1 + 3] ^ B[A2 + 3] ^ B[A2 + 4] ^ B[A3 + 4] ^ of;
		Bp[A1 + 5] = B[A0 + 5] ^ B[A1 + 4] ^ B[A2 + 4] ^ B[A2 + 5] ^ B[A3 + 5];
		Bp[A1 + 6] = B[A0 + 6] ^ B[A1 + 5] ^ B[A2 + 5] ^ B[A2 + 6] ^ B[A3 + 6];
		Bp[A1 + 7] = B[A0 + 7] ^ B[A1 + 6] ^ B[A2 + 6] ^ B[A2 + 7] ^ B[A3 + 7];

		of = B[A2 + 7] ^ B[A3 + 7];

		Bp[A2 + 0] = B[A0 + 0] ^ B[A1 + 0] ^ B[A3 + 0] ^ of;
		Bp[A2 + 1] = B[A0 + 1] ^ B[A1 + 1] ^ B[A2 + 0] ^ B[A3 + 0] ^ B[A3 + 1] ^ of;
		Bp[A2 + 2] = B[A0 + 2] ^ B[A1 + 2] ^ B[A2 + 1] ^ B[A3 + 1] ^ B[A3 + 2];
		Bp[A2 + 3] = B[A0 + 3] ^ B[A1 + 3] ^ B[A2 + 2] ^ B[A3 + 2] ^ B[A3 + 3] ^ of;
		Bp[A2 + 4] = B[A0 + 4] ^ B[A1 + 4] ^ B[A2 + 3] ^ B[A3 + 3] ^ B[A3 + 4] ^ of;
		Bp[A2 + 5] = B[A0 + 5] ^ B[A1 + 5] ^ B[A2 + 4] ^ B[A3 + 4] ^ B[A3 + 5];
		Bp[A2 + 6] = B[A0 + 6] ^ B[A1 + 6] ^ B[A2 + 5] ^ B[A3 + 5] ^ B[A3 + 6];
		Bp[A2 + 7] = B[A0 + 7] ^ B[A1 + 7] ^ B[A2 + 6] ^ B[A3 + 6] ^ B[A3 + 7];

		of = B[A0 + 7] ^ B[A3 + 7];

		Bp[A3 + 0] = B[A0 + 0] ^ B[A1 + 0] ^ B[A2 + 0] ^ of;
		Bp[A3 + 1] = B[A0 + 1] ^ B[A0 + 0] ^ B[A1 + 1] ^ B[A2 + 1] ^ B[A3 + 0] ^ of;
		Bp[A3 + 2] = B[A0 + 2] ^ B[A0 + 1] ^ B[A1 + 2] ^ B[A2 + 2] ^ B[A3 + 1];
		Bp[A3 + 3] = B[A0 + 3] ^ B[A0 + 2] ^ B[A1 + 3] ^ B[A2 + 3] ^ B[A3 + 2] ^ of;
		Bp[A3 + 4] = B[A0 + 4] ^ B[A0 + 3] ^ B[A1 + 4] ^ B[A2 + 4] ^ B[A3 + 3] ^ of;
		Bp[A3 + 5] = B[A0 + 5] ^ B[A0 + 4] ^ B[A1 + 5] ^ B[A2 + 5] ^ B[A3 + 4];
		Bp[A3 + 6] = B[A0 + 6] ^ B[A0 + 5] ^ B[A1 + 6] ^ B[A2 + 6] ^ B[A3 + 5];
		Bp[A3 + 7] = B[A0 + 7] ^ B[A0 + 6] ^ B[A1 + 7] ^ B[A2 + 7] ^ B[A3 + 6];

		Bp += BLOCK_SIZE / 4;
		B += BLOCK_SIZE / 4;
	}


	for (int i = 0; i < sizeof(Bp_space) / sizeof(word_t); i++)
	{
		B[i - BLOCK_SIZE] = Bp[i - BLOCK_SIZE];
	}
}

__host__ void bs_expand_key(word_t (*rk)[BLOCK_SIZE], uint8_t* _key)
{
	// TODO integrate this better
	uint8_t key[KEY_SCHEDULE_SIZE];
	memmove(key, _key, BLOCK_SIZE / 8);
	expand_key(key);

	int i, j = 0, k, l;
	for (i = 0; i < KEY_SCHEDULE_SIZE; i += (BLOCK_SIZE / 8))
	{
		memmove(rk[j], key + i, BLOCK_SIZE / 8);

		for (k = WORDS_PER_BLOCK; k < 128; k += WORDS_PER_BLOCK)
		{
			for (l = 0; l < WORDS_PER_BLOCK; l++)
			{
				rk[j][k + l] = rk[j][l];
			}
		}
		bs_transpose(rk[j]);
		j++;
	}
}

__global__ void bs_cipher(word_t* state, word_t* rk, size_t size)
{
	word_t local_state[BLOCK_SIZE];
	int round;

	unsigned long pos = (blockIdx.x * THREADNUM * BLOCK_SIZE / 2) + (threadIdx.x * BLOCK_SIZE / 2);
	if (pos >= size / 8) { return; }

	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		local_state[i] = state[i + pos % (size / sizeof(word_t))];
	}

	bs_transpose(local_state);
	bs_addroundkey(local_state, &rk[0 * BLOCK_SIZE]);

	for (round = 1; round < 10; round++)
	{
		bs_apply_sbox(local_state);
		bs_shiftrows(local_state);
		bs_mixcolumns(local_state);
		bs_addroundkey(local_state, &rk[round * BLOCK_SIZE]);
	}
	bs_apply_sbox(local_state);
	bs_shiftrows(local_state);
	bs_addroundkey(local_state, &rk[10 * BLOCK_SIZE]);
	bs_transpose_rev(local_state);

	for (int i = 0; i < BLOCK_SIZE / 2; i++)
	{
		state[i + pos] = local_state[i];
	}
	free(local_state);
}


void aes_ecb_encrypt(uint8_t* outputb, uint8_t* inputb, size_t size, uint8_t* key)
{
	auto input_space = static_cast<word_t*>(malloc(sizeof(uint8_t) * size));
	word_t rk[11][BLOCK_SIZE];
	word_t* key_tmp;

	word_t* buf_d;
	word_t* ctx_deckey_d;


	gpuErrchk(cudaMallocManaged((void**)&buf_d, size));
	gpuErrchk(cudaMallocManaged((void**)&ctx_deckey_d, sizeof(word_t) * BLOCK_SIZE * 11));


	key_tmp = static_cast<word_t*>(malloc(sizeof(word_t) * BLOCK_SIZE * 11));

	memset(outputb, 0, size);
	bs_expand_key(rk, key);


	int ctr = 0;
	for (int i = 0; i < 11; i++)
	{
		for (int j = 0; j < BLOCK_SIZE; j++)
		{
			key_tmp[ctr] = rk[i][j];
			ctr++;
		}
	}

	memset(input_space, 0, size);
	memmove(input_space, inputb, size);

	gpuErrchk(cudaMemcpy(buf_d, input_space, size, cudaMemcpyHostToDevice)); // 1/ copy buf from host to device
	gpuErrchk(cudaMemcpy(ctx_deckey_d, key_tmp, sizeof(word_t) * BLOCK_SIZE * 11, cudaMemcpyHostToDevice));
	// 2. copy key from host to device


	dim3 dimBlock(ceil(static_cast<double>(size) / static_cast<double>((THREADNUM * BLOCK_SIZE / 2))));
	dim3 dimGrid(THREADNUM);

	printf("Creating %d threads over %d blocks\n", dimBlock.x * dimGrid.x, dimBlock.x);


	cudaEvent_t start, stop;
	float time_k = 0.0;
	cudaEventCreate(&start); // create event
	cudaEventCreate(&stop);


	cudaEventRecord(start, nullptr); // start record

	bs_cipher << <dimBlock, dimGrid >> >(buf_d, ctx_deckey_d, size);
	cudaEventRecord(stop, nullptr); // end record
	cudaEventSynchronize(start); // waits for an event to complete
	cudaEventSynchronize(stop); //Waits for an event to complete
	cudaEventElapsedTime(&time_k, start, stop); // calculate delta time


	gpuErrchk(cudaMemcpy(input_space, buf_d, size, cudaMemcpyDeviceToHost));
	memmove(outputb, input_space, size);
	printf("GPU encryption throughput: %f bytes/second\n",
	       static_cast<double>(size) / (static_cast<double>(time_k) / 1000));
	cudaFree(buf_d);
	cudaFree(ctx_deckey_d);
}


void dump_hex(uint8_t* h, int len)
{
	while (len--)
		printf("%02hhx", *h++);
	printf("\n");
}

void aes_ecb_test()
{
	uint8_t key_vector[16] = {
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
	};

	auto tests = static_cast<uint8_t**>(malloc(sizeof(uint8_t*) * 10));
	unsigned long sizes[10] = {1000, 10000, 50000, 100000, 500000, 1000000, 5000000, 10000000, 50000000, 80000000};
	for (int i = 0; i < 10; i++)
	{
		tests[i] = static_cast<uint8_t*>(malloc(sizeof(uint8_t) * sizes[i]));
		for (uint64_t j = 0; j < sizes[i]; j++)
		{
			tests[i][j] = j % 256;
		}
	}

	for (int i = 0; i < 10; i++)
	{
		printf("AES ECB on generated input %d\n", i);

		auto output = static_cast<uint8_t*>(calloc(sizes[i], sizeof(uint8_t)));

		aes_ecb_encrypt(output, tests[i], sizes[i], key_vector);
		/*for (int i = 0; i < 2000; i++)
		{
		    if (output[i] != test_vector[i])
		    {
		        printf("%d, ", i);
		    }
		}*/
		free(output);
		free(tests[i]);
	}
	free(tests);
}


int main(int argc, char* argv[])
{
	aes_ecb_test();


	return 0;
}
