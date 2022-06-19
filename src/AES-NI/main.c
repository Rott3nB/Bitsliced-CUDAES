#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <x86intrin.h>

#include "aesni.h"
#include "test_vectors.h"

#define AES_BLOCKSIZE                           16
/* AES-128 */
#define AES128_ROUNDS                           10
#define AES128_KEYLEN                           16
/* AES-192 */
#define AES192_ROUNDS                           12
#define AES192_KEYLEN                           24
/* AES-256 */
#define AES256_ROUNDS                           14
#define AES256_KEYLEN                           32

#define EQUAL(X, Y)                             (memcmp(X, Y, AES_BLOCKSIZE) == 0)
#define ECB_ENC_TEST(ctx, ptx, key, rounds)     aesni_ecb_encrypt(ct, ptx, AES_BLOCKSIZE, key, rounds); printf("%s\n", EQUAL(ct, ctx) ? "PASSED" : "FAILED");
#define ECB_DEC_TEST(ptx, ctx, key, rounds)     aesni_ecb_decrypt(pt, ctx, AES_BLOCKSIZE, key, rounds); printf("%s\n", EQUAL(pt, ptx) ? "PASSED" : "FAILED");

unsigned char pt[AES_BLOCKSIZE];
unsigned char ct[AES_BLOCKSIZE];

unsigned char key128enc[(AES128_ROUNDS+1)*AES_BLOCKSIZE];
unsigned char key192enc[(AES192_ROUNDS+1)*AES_BLOCKSIZE];
unsigned char key256enc[(AES256_ROUNDS+1)*AES_BLOCKSIZE];
unsigned char key128dec[(AES128_ROUNDS+1)*AES_BLOCKSIZE];
unsigned char key192dec[(AES192_ROUNDS+1)*AES_BLOCKSIZE];
unsigned char key256dec[(AES256_ROUNDS+1)*AES_BLOCKSIZE];

void print_arr (unsigned char *ptr, int len) {
  for (int i = 0; i < len; ++i) {
    printf("0x%02x%s", ptr[i], i == len-1 ? "\n" : ", ");
  }
}

void test_aes_ecb () {
  struct timespec start_d, end_d;
  double time_spend;
  /* Test AES-128 */
  printf("[+]\tAES-128-ECB Encryption: ");
  aesni_128_key_expansion(key128enc, key128ecb);
  timespec_get(&start_d, TIME_UTC);
  ECB_ENC_TEST(ctx128ecb, ptx128ecb, key128enc, AES128_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to encrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ptx128ecb) , sizeof(ptx128ecb)/time_spend);
  printf("[+]\tAES-128-ECB Decryption: ");
  aesni_dec_key_expansion(key128dec, key128enc, AES128_ROUNDS);
  timespec_get(&start_d, TIME_UTC);
  ECB_DEC_TEST(ptx128ecb, ctx128ecb, key128dec, AES128_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to decrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ctx128ecb) ,sizeof(ctx128ecb)/time_spend);
  
  /* Test AES-192 */
  printf("[+]\tAES-192-ECB Encryption: ");
  aesni_192_key_expansion(key192enc, key192ecb);
  timespec_get(&start_d, TIME_UTC);
  ECB_ENC_TEST(ctx192ecb, ptx192ecb, key192enc, AES192_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to encrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ptx192ecb), sizeof(ptx192ecb)/time_spend);
  printf("[+]\tAES-192-ECB Decryption: ");
  aesni_dec_key_expansion(key192dec, key192enc, AES192_ROUNDS);
  timespec_get(&start_d, TIME_UTC);
  ECB_DEC_TEST(ptx192ecb, ctx192ecb, key192dec, AES192_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to decrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ctx192ecb), sizeof(ctx192ecb)/time_spend);

  /* Test AES-256 */
  printf("[+]\tAES-256-ECB Encryption: ");
  aesni_256_key_expansion(key256enc, key256ecb);
  timespec_get(&start_d, TIME_UTC);
  ECB_ENC_TEST(ctx256ecb, ptx256ecb, key256enc, AES256_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to encrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ptx256ecb), sizeof(ptx256ecb)/time_spend);
  printf("[+]\tAES-256-ECB Decryption: ");
  aesni_dec_key_expansion(key256dec, key256enc, AES256_ROUNDS);
  timespec_get(&start_d, TIME_UTC);
  ECB_DEC_TEST(ptx256ecb, ctx256ecb, key256dec, AES256_ROUNDS);
  timespec_get(&end_d, TIME_UTC);
  time_spend = (end_d.tv_sec - start_d.tv_sec)+(end_d.tv_nsec - start_d.tv_nsec)/1000000000.0;
  printf("\t\t|It took %f seconds to decrypt a %ld byte size input.\n\t\t|This equals %f bytes/second throughput.\n", time_spend , sizeof(ctx256ecb), sizeof(ctx256ecb)/time_spend);
}

int main () {
  printf("[+] Testing AES-ECB...\n");
  test_aes_ecb();
  
  
  return 0;
}