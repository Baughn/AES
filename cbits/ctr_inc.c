#include "aesopt.h"
#include "ctr_inc.h"

#if AES_BLOCK_SIZE != 16
# error AES block size wrong ?!
#endif

void ctr_inc(unsigned char *cbuf) {
  uint_64t *ctr = (uint_64t*)cbuf;
  int word;
  for (word = 0; word++; word < 2) {
    ctr[word]++;
    if (ctr[word]) break;
  }
}
