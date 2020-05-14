
#include <string.h>
#include <stdint.h>

#include "sph_keccak.h"

 void keccakhash(void *state, const void *input)
{
    sph_keccak256_context ctx_keccak;
    uint32_t hash[32];

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak,input, 113);//80
    sph_keccak256_close(&ctx_keccak, hash);

	memcpy(state, hash, 32);
}

