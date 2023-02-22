/* 
crypto.c

Implementations for cryptography primatives and functions
  making use of them.

Skeleton written by Aidan Dang for COMP20007 Assignment 2 2022
  with Minor modifications by Grady Fitzpatrick
  implementation by Bi Ho Shin ID: 1086159
*/
#include <crypto.h>
#include <sponge.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// The sponge's rate, in bytes. This represents the maximum number of bytes
// which can be read from or written the start of the sponge's state before a
// permutation must occur.
#define RATE 16 //max number of chars that can be read before permutation
// Delimiter byte value used after absorption of the message
#define DELIMITER_A 0xAD
// Delimiter byte used at the end of the last-used block
#define DELIMITER_B 0X77

// Helpful min function that might be useful.
uint64_t min(uint64_t a, uint64_t b) { return a < b ? a : b; }

void hash(uint8_t *output, uint64_t output_len, uint8_t const *msg, uint64_t msg_len) {

  //Zeroing the sponge's state
  sponge_t sponge;
  sponge_init(&sponge);

  /* Absorbing Phase: */
  //For every full block of size RATE (ie. the i'th block)
  for (int i=0; i<(msg_len/RATE); i++) {
    //1. Write blocks of size RATE bytes from the message into the sponge (after xoring)
    sponge_write(&sponge, msg + (i*RATE), RATE, true);
    //2. Then run the bijective function on the entire sponge state
    sponge_permute(&sponge);
  }

  int r = msg_len % RATE;
  //3. Handle the last tail block of the message, XOR but don't permutate
  sponge_write(&sponge, msg + (msg_len - r), r, true); 

  /* Demarcation Phase: */

  //Absorb DELIMITER_A to state's rth byte
  sponge_demarcate(&sponge, r, DELIMITER_A);
  //Absorb DELIMITER_B to state's (RATE - 1)th byte
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //Permute the sponge's state
  sponge_permute(&sponge);

  /* Squeezing Phase: */
  for(int i=0; i<(output_len/RATE); i++) { //i'th block
    //Read RATE bytes from sponge
    sponge_read(output + (i * RATE), &sponge, RATE);
    //Permutate
    sponge_permute(&sponge);
  }
  int r2 = output_len%RATE;
  //reading the tail end of bytes
  sponge_read(output + (output_len - r2), &sponge, r2);

  // TODO: fill the rest of this function.
  // Here are some examples of what sponge routines are called for various
  // invocations of this hash function:
  //hash(output, output_len, msg, msg_len);
  // hash(o, 5, m, 0) performs:
  //   sponge_write(&sponge, m, 0, true);
  //   sponge_demarcate(&sponge, 0, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, 5);
  //
  // hash(o, 16, m, 7) performs:
  //   sponge_write(&sponge, m, 7, true);
  //   sponge_demarcate(&sponge, 7, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, 16);
  /* My implementation actually runs a sponge_permute here but I don't think it matters
  because we probably won't need to access the sponge again*/
  //
  // hash(o, 23, m, 16) performs:
  //   sponge_write(&sponge, m, RATE, true);
  //   sponge_permute(&sponge);
  //   sponge_write(&sponge, m + RATE, 0, true);
  //   sponge_demarcate(&sponge, 0, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, RATE);
  //   sponge_permute(&sponge);
  //   sponge_read(o + RATE, &sponge, 7);
  //
  // hash(o, 32, m, 23) performs:
  //   sponge_write(&sponge, m, RATE, true);
  //   sponge_permute(&sponge);
  //   sponge_write(&sponge, m + RATE, 7, true);
  //   sponge_demarcate(&sponge, 7, DELIMITER_A);
  //   sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //   sponge_permute(&sponge);
  //   sponge_read(o, &sponge, RATE);
  //   sponge_permute(&sponge);
  //   sponge_read(o + RATE, &sponge, 16);
}

void mac(uint8_t *tag, uint64_t tag_len, uint8_t const *key, uint8_t const *msg, uint64_t msg_len) {

  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the hash
  // function's, but should include a keying phase before the absorbing phase.
  // If you wish, you may also treat this as calculating the hash of the key
  // prepended to the message.

  //Prepending the key to the message and running through the hash function
  uint8_t *concat_msg = (uint8_t *)malloc((CRYPTO_KEY_SIZE + msg_len) * sizeof(uint8_t));
  assert(concat_msg);
  memcpy(concat_msg, key, CRYPTO_KEY_SIZE);
  memcpy(concat_msg + CRYPTO_KEY_SIZE, msg, msg_len);

  hash(tag, tag_len, concat_msg, CRYPTO_KEY_SIZE + msg_len);
  free(concat_msg);

}

void auth_encr(uint8_t *ciphertext, uint8_t *tag, uint64_t tag_len, uint8_t const *key,
               uint8_t const *plaintext, uint64_t text_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  // Your implementation should like very similar to that of the mac function's,
  // but should after each write into the sponge's state, there should
  // immediately follow a read from the sponge's state of the same number of
  // bytes, into the ciphertext buffer.

  /* Keying Phase */
  //We are given that CRYPTO_KEY_SIZE = 32 (ie. divisible by RATE = 16)
  for (int i=0; i<(CRYPTO_KEY_SIZE/RATE); i++) {
    sponge_write(&sponge, key + (i*RATE), RATE, true);
    sponge_permute(&sponge);
  }
  
  /* Absorbing Phase for Actual Message */
  //Similar logic as per the hash/mac function above:

  //For every full block of size RATE (ie. the i'th block)
  for (int i=0; i<(text_len/RATE); i++) {
    //1. Write blocks of size RATE bytes from the message into the sponge (after XORing)
    sponge_write(&sponge, plaintext + (i*RATE), RATE, true);
    //2. Read the the same number of bytes into the ciphertext
    sponge_read(ciphertext + (i*RATE), &sponge, RATE);
    //3. Run the bijective function on the entire sponge state
    sponge_permute(&sponge);
  }

  int r = text_len % RATE;
  //4. Handle the last tail block of the message, XOR but don't permutate
  sponge_write(&sponge, plaintext + (text_len - r), r, true);
  sponge_read(ciphertext + (text_len - r), &sponge, r);

  /* Demarcation Phase for Actual Message */

  //Absorb DELIMITER_A to state's rth byte
  sponge_demarcate(&sponge, r, DELIMITER_A);
  //Absorb DELIMITER_B to state's (RATE - 1)th byte
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //Permute the sponge's state
  sponge_permute(&sponge);

  /* Squeezing Phase: */
  //For every full block of size RATE
  for(int i=0; i<(tag_len/RATE); i++) { //i'th block
    //Read RATE bytes from sponge
    sponge_read(tag + (i * RATE), &sponge, RATE);
    //Permutate
    sponge_permute(&sponge);
  }
  int r2 = tag_len%RATE;
  //reading the tail end of bytes
  sponge_read(tag + (tag_len - r2), &sponge, r2);

}

int auth_decr(uint8_t *plaintext, uint8_t const *key, uint8_t const *ciphertext,
              uint64_t text_len, uint8_t const *tag, uint64_t tag_len) {
  sponge_t sponge;
  sponge_init(&sponge);

  // TODO: fill the rest of this function.
  // The implementation of this function is left as a challenge. It may assist
  // you to know that a ^ b ^ b = a. Remember to return 0 on success, and 1 on
  // failure.

  /* Keying Phase */
  //We are given that CRYPTO_KEY_SIZE = 32 (ie. divisible by RATE = 16)
  for (int i=0; i<(CRYPTO_KEY_SIZE/RATE); i++) {
    sponge_write(&sponge, key + (i*RATE), RATE, true);
    sponge_permute(&sponge);
  }

  /* Absorbing Phase for Ciphertext*/
  //Similar logic as per the functions above

  //For every full block of size RATE (ie. the i'th block)
  for (int i=0; i <(text_len/RATE); i++) {
    //1. Write a block of decrypted text from the cipher into the sponge by 'inverse XORing'
    sponge_write(&sponge, ciphertext + (i*RATE), RATE, true);
    //2. Read the block of decrypted text into plaintext 
    sponge_read(plaintext + (i*RATE), &sponge, RATE);
    //3. Overwrite the decrypted text in the sponge with the corresponding ciphertext block
    sponge_write(&sponge, ciphertext + (i*RATE), RATE, false);
    //4. Then permutate the sponge to obtain required sponge rate to XOR with cipher
    sponge_permute(&sponge);
  }
  //4. Handle the last tail block of the cipher:
  int r = text_len % RATE;
  //Write final block of decrypted text from cipher into the sponge by XOR
  sponge_write(&sponge, ciphertext + (text_len - r), r, true);
  //Read the block of decrypted text into plaintext
  sponge_read(plaintext + (text_len - r), &sponge, r);
  //Insert Null byte at the end of a string
  //Skeleton code in decr.c was modified so that plaintext will have enough space to be null-terminated
  plaintext[text_len] = '\0';
  
  //Overwrite the decrypted text in sponge with corresponding ciphertext block (ensuring we have correct length)
  sponge_write(&sponge, ciphertext + (text_len - r), r, false);

  /* Authentication Tag Validation */

  /* Demarcation Phase */
  sponge_demarcate(&sponge, r, DELIMITER_A);
  //Absorb DELIMITER_B to state's (RATE - 1)th byte
  sponge_demarcate(&sponge, RATE - 1, DELIMITER_B);
  //Permute the sponge's state
  sponge_permute(&sponge);

  /* Squeezing Phase */

  //Create a new authentication tag to compare with the given authentication tag
  uint8_t *new_tag = (uint8_t *)malloc(tag_len * sizeof(uint8_t));
  //For every full block of size RATE
  for(int i=0; i<(tag_len/RATE); i++) { //i'th block
    //Read RATE bytes from sponge
    sponge_read(new_tag + (i * RATE), &sponge, RATE);
    //Permutate
    sponge_permute(&sponge);
  }
  int r2 = tag_len%RATE;
  //reading the tail end of bytes
  sponge_read(new_tag + (tag_len - r2), &sponge, r2);

  //Compare Authentication tags
  int valid = !(memcmp(new_tag, tag, tag_len) == 0);
  free(new_tag);
  return valid;
}

