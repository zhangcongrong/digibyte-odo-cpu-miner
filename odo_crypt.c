#include <stdint.h>
#include <string.h>

#include "odo_crypt.h"

/*******************OdoRandom*******************/



inline void OdoRandom_init(OdoRandom *ctx, uint32_t seed)
{
	if (ctx) {
		ctx->current = seed;
		ctx->multiplicand = 1;
		ctx->addend = 0;
	}
}

// For a standard LCG, every seed produces the same sequence, but from a different
// starting point.  This generator gives the 1st, 3rd, 6th, 10th, etc output from
// a standard LCG.  This ensures that every seed produces a unique sequence.
inline uint32_t OdoRandom_NextInt(OdoRandom *ctx)
{
	if (ctx) {
		ctx->addend += ctx->multiplicand * BASE_ADDEND;
		ctx->multiplicand *= BASE_MULTIPLICAND;
		ctx->current = ctx->current * ctx->multiplicand + ctx->addend;
		return (ctx->current) >> 32;
	}
	else {
		return 0;
	}
}

inline uint64_t OdoRandom_NextLong(OdoRandom *ctx)
{
	if (ctx) {
		uint64_t hi = (uint64_t)OdoRandom_NextInt(ctx);
		return (hi << 32) | OdoRandom_NextInt(ctx);
	}
	else {
		return 0;
	}
}

inline int OdoRandom_Next(OdoRandom *ctx, int N)
{
	return ((uint64_t)OdoRandom_NextInt(ctx) * N) >> 32;
}

void OdoRandom_Permutation_uint8(OdoRandom *ctx, uint8_t *arr, size_t size)
{
	int i=0;
	if (NULL == ctx || NULL == arr) {
		return;
	}	
	
	for (i = 0; i < size; i++) {
		arr[i] = (uint8_t)i;
	}

	for (i = 1; i < size; i++) {
		uint8_t tmp = arr[i];
		uint32_t pos = OdoRandom_Next(ctx, i + 1);
		arr[i] = arr[pos];
		arr[pos] = tmp;		
	}
}

void OdoRandom_Permutation_uint16(OdoRandom *ctx, uint16_t *arr, size_t size)
{
	int i=0;
	if (NULL == ctx || NULL == arr) {
		return;
	}

	for ( i = 0; i < size; i++) {
		arr[i] = (uint16_t)i;
	}

	for ( i = 1; i < size; i++) {
		uint16_t tmp = arr[i];
		uint32_t pos = OdoRandom_Next(ctx, i + 1);
		arr[i] = arr[pos];
		arr[pos] = tmp;
	}
}

void OdoRandom_Permutation_uint32(OdoRandom *ctx, uint32_t *arr, size_t size)
{
	int i=0;
	if (NULL == ctx || NULL == arr) {
		return;
	}

	for ( i = 0; i < size; i++) {
		arr[i] = (uint32_t)i;
	}

	for ( i = 1; i < size; i++) {
		uint32_t tmp = arr[i];
		uint32_t pos = OdoRandom_Next(ctx, i + 1);
		arr[i] = arr[pos];
		arr[pos] = tmp;
	}
}


/*******************OdoCrypt*******************/
void OdoCrypt_init(OdoCrypt *ctx, uint32_t seed)
{
	OdoRandom ctx_rand;
	int bits[WORD_BITS - 1];
	int sum = 0;
	int i=0,j=0,k=0;

	OdoRandom_init(&ctx_rand, seed);

	// Randomize each s-box
	for (i = 0; i < SMALL_SBOX_COUNT; i++)
	{
		OdoRandom_Permutation_uint8(&ctx_rand, ctx->Sbox1[i], 1 << SMALL_SBOX_WIDTH);
	}
	for (i = 0; i < LARGE_SBOX_COUNT; i++)
	{
		OdoRandom_Permutation_uint16(&ctx_rand, ctx->Sbox2[i], 1 << LARGE_SBOX_WIDTH);
	}

	// Randomize each p-box
	for (i = 0; i < 2; i++)
	{
		struct Pbox* perm = &(ctx->Permutation[i]);
		for (j = 0; j < PBOX_SUBROUNDS; j++)
			for ( k = 0; k < STATE_SIZE / 2; k++)
				perm->mask[j][k] = OdoRandom_NextLong(&ctx_rand);
		for ( j = 0; j < PBOX_SUBROUNDS - 1; j++)
			for ( k = 0; k < STATE_SIZE / 2; k++)
				perm->rotation[j][k] = OdoRandom_Next(&ctx_rand, 63) + 1;
	}

	// Randomize rotations
	// Rotations must be distinct, non-zero, and have odd sum
	{
		OdoRandom_Permutation_uint32(&ctx_rand, bits, WORD_BITS - 1);

		for ( j = 0; j < ROTATION_COUNT - 1; j++)
		{
			ctx->Rotations[j] = bits[j] + 1;
			sum += ctx->Rotations[j];
		}

		for ( j = ROTATION_COUNT - 1; ; j++)
		{
			if ((bits[j] + 1 + sum) % 2)
			{
				ctx->Rotations[ROTATION_COUNT - 1] = bits[j] + 1;
				break;
			}
		}
	}

	// Randomize each round key
	for ( i = 0; i < ROUNDS; i++)
		ctx->RoundKey[i] = OdoRandom_Next(&ctx_rand, 1 << STATE_SIZE);
}


void OdoCrypt_Unpack(uint64_t state[STATE_SIZE], const char bytes[DIGEST_SIZE])
{
	int i=0,j=0;
	memset(state, 0, STATE_SIZE * sizeof(state[0]));

	for ( i = 0; i < STATE_SIZE; i++)
	{
		for ( j = 0; j < 8; j++)
		{
			state[i] |= (uint64_t)(uint8_t)bytes[8 * i + j] << (8 * j);
		}
	}
}

void OdoCrypt_Pack(const uint64_t state[STATE_SIZE], char bytes[DIGEST_SIZE])
{
	int i=0,j=0;
	memset(bytes, 0, DIGEST_SIZE * sizeof(bytes[0]));

	for ( i = 0; i < STATE_SIZE; i++)
	{
		for ( j = 0; j < 8; j++)
		{
			bytes[8 * i + j] = (state[i] >> (8 * j)) & 0xff;
		}
	}
}

void OdoCrypt_PreMix(uint64_t state[STATE_SIZE])
{
	int i=0,j=0;
	uint64_t total = 0;
	for ( i = 0; i < STATE_SIZE; i++)
		total ^= state[i];
	total ^= total >> 32;
	for ( i = 0; i < STATE_SIZE; i++)
		state[i] ^= total;
}

void OdoCrypt_ApplySboxes(
	uint64_t state[STATE_SIZE],
	const uint8_t sbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH],
	const uint16_t sbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH])
{
	const static uint64_t MASK1 = (1 << SMALL_SBOX_WIDTH) - 1;
	const static uint64_t MASK2 = (1 << LARGE_SBOX_WIDTH) - 1;
	int i=0,j=0;

	int smallSboxIndex = 0;
	for ( i = 0; i < STATE_SIZE; i++)
	{
		uint64_t next = 0;
		int pos = 0;
		int largeSboxIndex = i;
		for ( j = 0; j < SMALL_SBOX_COUNT / STATE_SIZE; j++)
		{
			next |= (uint64_t)sbox1[smallSboxIndex][(state[i] >> pos) & MASK1] << pos;
			pos += SMALL_SBOX_WIDTH;
			next |= (uint64_t)sbox2[largeSboxIndex][(state[i] >> pos) & MASK2] << pos;
			pos += LARGE_SBOX_WIDTH;
			smallSboxIndex++;
		}
		state[i] = next;
	}
}

void OdoCrypt_ApplyMaskedSwaps(uint64_t state[STATE_SIZE], const uint64_t mask[STATE_SIZE / 2])
{
	int i=0,j=0;
	for ( i = 0; i < STATE_SIZE / 2; i++)
	{
		uint64_t *a = &state[2 * i];
		uint64_t *b = &state[2 * i + 1];
		// For each bit set in the mask, swap the corresponding bits in `a` and `b`
		uint64_t swp = mask[i] & ((*a) ^ (*b));
		*a ^= swp;
		*b ^= swp;
	}
}

void OdoCrypt_ApplyWordShuffle(uint64_t state[STATE_SIZE], int m)
{
	int i=0,j=0;
	uint64_t next[STATE_SIZE];
	for ( i = 0; i < STATE_SIZE; i++)
	{
		next[m*i % STATE_SIZE] = state[i];
	}
	
	memcpy(state, next, STATE_SIZE*sizeof(next[0]));
}

inline uint64_t Rot(uint64_t x, int r)
{
	return r == 0 ? x : (x << r) ^ (x >> (64 - r));
}

void OdoCrypt_ApplyPboxRotations(uint64_t state[STATE_SIZE], const int rotation[STATE_SIZE / 2])
{
	int i=0,j=0;
	for ( i = 0; i < STATE_SIZE / 2; i++)
	{
		// Only rotate the even words.  Rotating the odd words wouldn't actually
		// be useful - a transformation that rotates all the words can be
		// transformed into one that only rotates the even words, then rotates
		// the odd words once after the final iteration.
		state[2 * i] = Rot(state[2 * i], rotation[i]);
	}
}

void OdoCrypt_ApplyPbox(uint64_t state[STATE_SIZE], const struct Pbox* perm)
{
	int i=0,j=0;
	for ( i = 0; i < PBOX_SUBROUNDS - 1; i++)
	{
		// Conditionally move bits between adjacent pairs of words
		OdoCrypt_ApplyMaskedSwaps(state, perm->mask[i]);
		// Move the words around
		OdoCrypt_ApplyWordShuffle(state, PBOX_M);
		// Rotate the bits within words
		OdoCrypt_ApplyPboxRotations(state, perm->rotation[i]);
	}
	OdoCrypt_ApplyMaskedSwaps(state, perm->mask[PBOX_SUBROUNDS - 1]);
}

void OdoCrypt_ApplyInvPbox(uint64_t state[STATE_SIZE], const struct Pbox* perm)
{
	int i=0,j=0;
	OdoCrypt_ApplyMaskedSwaps(state, perm->mask[PBOX_SUBROUNDS - 1]);
	for ( i = PBOX_SUBROUNDS - 2; i >= 0; i--)
	{
		int invRotation[STATE_SIZE / 2];
		for ( j = 0; j < STATE_SIZE / 2; j++)
			invRotation[j] = WORD_BITS - perm->rotation[i][j];
		OdoCrypt_ApplyPboxRotations(state, invRotation);
		OdoCrypt_ApplyWordShuffle(state, INV_PBOX_M);
		OdoCrypt_ApplyMaskedSwaps(state, perm->mask[i]);
	}
}

void OdoCrypt_ApplyRotations(uint64_t state[STATE_SIZE], const int rotations[ROTATION_COUNT])
{
	int i=0,j=0;
	uint64_t next[STATE_SIZE];
	//std::rotate_copy(state, state + 1, state + STATE_SIZE, next);
	memcpy(next, state+1, (STATE_SIZE-1)*sizeof(next[0]));
	memcpy(next + STATE_SIZE - 1, state, sizeof(next[0]));

	for ( i = 0; i < STATE_SIZE; i++)
		for ( j = 0; j < ROTATION_COUNT; j++)
		{
			next[i] ^= Rot(state[i], rotations[j]);
		}
	//std::copy(next, next + STATE_SIZE, state);
	memcpy(state, next, STATE_SIZE * sizeof(next[0]));
}

void OdoCrypt_ApplyRoundKey(uint64_t state[STATE_SIZE], int roundKey)
{
	int i=0,j=0;
	for ( i = 0; i < STATE_SIZE; i++)
		state[i] ^= (roundKey >> i) & 1;
}


void OdoCrypt_Encrypt(OdoCrypt *ctx, char cipher[DIGEST_SIZE], const char plain[DIGEST_SIZE])
{
	int round = 0;
	uint64_t state[STATE_SIZE];
	OdoCrypt_Unpack(state, plain);
	OdoCrypt_PreMix(state);
	for ( round = 0; round < ROUNDS; round++)
	{
		OdoCrypt_ApplyPbox(state, &(ctx->Permutation[0]));
		OdoCrypt_ApplySboxes(state, ctx->Sbox1, ctx->Sbox2);
		OdoCrypt_ApplyPbox(state, &(ctx->Permutation[1]));
		OdoCrypt_ApplyRotations(state, ctx->Rotations);
		OdoCrypt_ApplyRoundKey(state, (uint16_t)ctx->RoundKey[round]);
	}
	OdoCrypt_Pack(state, cipher);
}