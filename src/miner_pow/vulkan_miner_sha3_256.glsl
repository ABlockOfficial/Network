//
// SHA-3 implementation
// This is ported from https://github.com/brainhub/SHA3IUF
//

/* 'Words' here refers to uint64_t */
const uint SHA3_KECCAK_SPONGE_WORDS = ((1600)/8/*bits to byte*/)/8/*sizeof(uint64_t)*/; // 25
const uint SHA3_256_BYTES = 256 / 8; // 32
const uint SHA3_256_CAPACITY_WORDS = 2 * 256 / (8 * 8); // 8

const uint KECCAK_ROUNDS = 24;

/*
 * This flag is used to configure "pure" Keccak, as opposed to NIST SHA3.
 */
const bool SHA3_USE_KECCAK = false;

#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> (64/*(sizeof(uint64_t)*8)*/ - (y))))

struct sha3_256_context {
    uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
    uint64_t s[SHA3_KECCAK_SPONGE_WORDS]; /* Keccak's state */
    uint byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    uint wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
};

const uint keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

const uint keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

const uint64_t keccakf_rndc[24] = {
	0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
	0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
	0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
	0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
	0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
	0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words
 * are XORed into the state s
 */
void keccakf(inout uint64_t s[SHA3_KECCAK_SPONGE_WORDS]) {
    uint i, j, round;
    uint64_t t, bc[5];

    for(round = 0; round < KECCAK_ROUNDS; round++) {

        /* Theta */
        for(i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

        for(i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
            for(j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }

        /* Rho Pi */
        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for(j = 0; j < 25; j += 5) {
            for(i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for(i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }
}

void sha3_256_Init(inout sha3_256_context ctx) {
    ctx.saved = 0ul;
    for (uint i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) ctx.s[i] = 0ul;
    ctx.byteIndex = 0u;
    ctx.wordIndex = 0u;
}

void sha3_256_Update(inout sha3_256_context ctx, uint8_t byteIn) {
    ctx.saved |= ((uint64_t(byteIn) & uint64_t(0xFFu)) << ((ctx.byteIndex++) * 8u));
    if (ctx.byteIndex == 8u) {
        ctx.s[ctx.wordIndex] ^= ctx.saved;
        ctx.saved = 0u;
        ctx.byteIndex = 0u;
        if (++ctx.wordIndex == (SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS)) {
            ctx.wordIndex = 0u;
            keccakf(ctx.s);
        }
    }

    /*
    ctx.saved |= ((uint64_t(byteIn) & uint64_t(0xFFu)) << ((ctx.written_bytes % 8u) * 8u));
    if ((ctx.written_bytes % 8u) == 8u - 1u) {
        uint word_index = (ctx.written_bytes / 8u) % (SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS);
        ctx.s[word_index] ^= ctx.saved;
        ctx.saved = 0u;
        if (word_index == (SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS - 1u)) {
            keccakf(ctx.s);
        }
    }
    ctx.written_bytes++;
    */
}


void sha3_256_Update_int32le(inout sha3_256_context ctx, uint32_t bytesIn) {
    /*if ((ctx.written_bytes & 8u) < 4u) {
        //ctx.saved |= ((uint64_t(bytesIn) & uint64_t(0xFFFFFFFFu)) << ((ctx.written_bytes % 8u) * 8u));
        //if ((ctx.written_bytes % 8u) == 8u - 4u) {
        //    uint word_index = (ctx.written_bytes / 8u) % (SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS);
        //    ctx.s[word_index] ^= ctx.saved;
        //    ctx.saved = 0u;
        //    if (word_index == (SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS - 1u)) {
        //        keccakf(ctx.s);
        //    }
        //}
        //ctx.written_bytes += 4u;
    } else {*/
        sha3_256_Update(ctx, uint8_t((bytesIn >> 0u) & 0xFFu));
        sha3_256_Update(ctx, uint8_t((bytesIn >> 8u) & 0xFFu));
        sha3_256_Update(ctx, uint8_t((bytesIn >> 16u) & 0xFFu));
        sha3_256_Update(ctx, uint8_t((bytesIn >> 24u) & 0xFFu));
    //}
}

uint8_t[SHA3_256_BYTES] sha3_256_Finalize(inout sha3_256_context ctx) {
    /* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
     * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
     * Overall, we feed 0, then 1, and finally 1 to start padding. Without
     * M || 01, we would simply use 1 to start padding. */

    uint64_t t = SHA3_USE_KECCAK
        /* Keccak version */
        ? uint64_t((uint64_t(1)) << (ctx.byteIndex * 8u))
        /* SHA3 version */
        : uint64_t((uint64_t(0x02 | (1 << 2))) << ((ctx.byteIndex) * 8u));

    ctx.s[ctx.wordIndex] ^= ctx.saved ^ t;

    ctx.s[SHA3_KECCAK_SPONGE_WORDS - SHA3_256_CAPACITY_WORDS - 1u] ^= 0x8000000000000000UL;
    keccakf(ctx.s);

    uint8_t result[SHA3_256_BYTES];
    for (uint i = 0; i < SHA3_256_BYTES / 8u; i++) {
        t = ctx.s[i];
        result[i * 8 + 0] = uint8_t((t) & uint64_t(0xFFu));
        result[i * 8 + 1] = uint8_t((t >> 8u) & uint64_t(0xFFu));
        result[i * 8 + 2] = uint8_t((t >> 16u) & uint64_t(0xFFu));
        result[i * 8 + 3] = uint8_t((t >> 24u) & uint64_t(0xFFu));
        result[i * 8 + 4] = uint8_t((t >> 32u) & uint64_t(0xFFu));
        result[i * 8 + 5] = uint8_t((t >> 40u) & uint64_t(0xFFu));
        result[i * 8 + 6] = uint8_t((t >> 48u) & uint64_t(0xFFu));
        result[i * 8 + 7] = uint8_t((t >> 56u) & uint64_t(0xFFu));
    }
    return result;
}