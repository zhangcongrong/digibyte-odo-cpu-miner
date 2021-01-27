#ifndef ODO_CTRYPT_H
#define ODO_CTRYPT_H

// LCG parameters from Knuth
#define BASE_MULTIPLICAND 6364136223846793005ull
#define BASE_ADDEND 1442695040888963407ull

typedef struct OdoRandom_t {
	uint64_t current;
	uint64_t multiplicand;
	uint64_t addend;
}OdoRandom;



// Block size, in bytes
#define DIGEST_SIZE 80

// Number of rounds.
#define ROUNDS 84
// Odo utilizes two sbox sizes - 6-bit sboxes, which are ideally suited for
// FPGA logic elements, and 10-bit sboxes, which are ideally suited for FPGA
// RAM elements.
#define SMALL_SBOX_WIDTH 6
#define LARGE_SBOX_WIDTH 10
// The pboxes are constructed using 3 primitives, applied multiple times.
#define PBOX_SUBROUNDS 6
// This constant should be a generator for the multiplicative group of
// integers modulo STATE_SIZE (3 or 7 for a STATE_SIZE of 10).  It controls
// one part of the pbox step.
#define PBOX_M 3
// The multiplicative inverse of PBOX_M modulo STATE_SIZE
#define INV_PBOX_M 7
// This constant must be even.  It controls the number of rotations used in
// the linear mixing step.
#define ROTATION_COUNT 6
// Odo internally operates on 64-bit words.
#define WORD_BITS 64

#define DIGEST_BITS (8 * DIGEST_SIZE)
#define STATE_SIZE (DIGEST_BITS / WORD_BITS)
#define SMALL_SBOX_COUNT (DIGEST_BITS / (SMALL_SBOX_WIDTH + LARGE_SBOX_WIDTH))
#define LARGE_SBOX_COUNT STATE_SIZE

struct Pbox
{
	uint64_t mask[PBOX_SUBROUNDS][STATE_SIZE / 2];
	int rotation[PBOX_SUBROUNDS - 1][STATE_SIZE / 2];
};

typedef struct OdoCrypt_t {
	uint8_t Sbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH];
	uint16_t Sbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH];
	struct Pbox Permutation[2];
	int Rotations[ROTATION_COUNT];
	uint16_t RoundKey[ROUNDS];
}OdoCrypt;


void OdoCrypt_init(OdoCrypt *ctx, uint32_t seed);
void OdoCrypt_Encrypt(OdoCrypt *ctx, char cipher[DIGEST_SIZE], const char plain[DIGEST_SIZE]);


#endif