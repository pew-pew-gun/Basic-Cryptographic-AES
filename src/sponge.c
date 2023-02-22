/* 
sponge.c

Implementations for sponge construction initialisation and manipulation.

Skeleton written by Aidan Dang for COMP20007 Assignment 2 2022
  with Minor modifications by Grady Fitzpatrick
*/
#include <permutation.h>
#include <sponge.h>
#include <string.h>

// Initialises a sponge by zeroing its state
void sponge_init(sponge_t *sponge) {
  // TODO: fill the rest of this function.

  for (int i = 0; i < SPONGE_STATE_SIZE; i++) {
    //zeroing the state
    sponge->state[i] = 0;
  }

}

// Reads num bytes from the sponge's state into the dest buffer.
void sponge_read(uint8_t *dest, sponge_t const *sponge, uint64_t num) {
  // TODO: fill the rest of this function.
  memcpy(dest, sponge->state, num);

}

// Writes num bytes from the src buffer into the sponge's state, either by
// bit-wise XOR when bw_xor, else by overwriting.
void sponge_write(sponge_t *sponge, uint8_t const *src, uint64_t num, bool bw_xor) {
  // TODO: fill the rest of this function.
  // You may use the ^ operator to calculate a bit-wise XOR.

  if (bw_xor) {
    for (int i=0; i < num; i++) {
      //XOR bit-wise between existing state and src
      sponge->state[i] = sponge->state[i] ^ src[i];
    }
  } else {
    for(int i=0; i<num; i++) {
      //overwrite the state's first num bytes
      sponge->state[i] = src[i];
    }
  }
}

// Bit-wise XORs the delimiter into the i'th byte of the sponge's state.
void sponge_demarcate(sponge_t *sponge, uint64_t i, uint8_t delimiter) {
  // TODO: fill the rest of this function.
  sponge->state[i] = sponge->state[i] ^ delimiter;
}

// Applies the permutation to the sponge's state.
void sponge_permute(sponge_t *sponge) {
  // TODO: fill the rest of this function.
  // You should use the permute_384 function from include/permutation.h.
  permute_384(sponge->state);
}

