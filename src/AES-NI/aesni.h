void aesni_128_key_expansion (unsigned char *roundkeys, const unsigned char *userkey);
void aesni_192_key_expansion (unsigned char *roundkeys, const unsigned char *userkey);
void aesni_256_key_expansion (unsigned char *roundkeys, const unsigned char *userkey);
void aesni_dec_key_expansion (unsigned char *dec_key, const unsigned char *roundkeys, int number_of_rounds);

void aesni_ecb_encrypt (
                    unsigned char *out,       /* pointer to the CIPHERTEXT buffer     */
                    const unsigned char *in,  /* pointer to the PLAINTEXT             */
                    unsigned long length,     /* text length in bytes                 */
                    const unsigned char *key, /* pointer to the expanded key schedule */
                    int number_of_rounds);    /* number of AES rounds 10, 12, or 14   */
void aesni_cbc_encrypt(
                    unsigned char *out,         /* pointer to the CIPHERTEXT buffer     */
                    const unsigned char *in,    /* pointer to the PLAINTEXT             */
                    unsigned char ivec[16],     /* array with INITIALIZATION VECTOR     */
                    unsigned long length,       /* text length in bytes                 */
                    unsigned char *key,         /* pointer to the expanded key schedule */
                    int number_of_rounds);      /* number of AES rounds 10, 12, or 14   */

void aesni_ecb_decrypt (
                    unsigned char *out,       /* pointer to the DECRYPTED TEXT buffer */
                    const unsigned char *in,  /* pointer to the CIPHERTEXT            */
                    unsigned long length,     /* text length in bytes                 */
                    const unsigned char *key, /* pointer to the expanded key schedule */
                    int number_of_rounds);    /* number of AES rounds 10, 12, or 14   */
void aesni_cbc_decrypt(
                    unsigned char *out,         /* pointer to the DECRYPTED TEXT buffer */
                    const unsigned char *in,    /* pointer to the CIPHERTEXT            */
                    unsigned char ivec[16],     /* array with INITIALIZATION VECTOR     */
                    unsigned long length,       /* text length in bytes                 */
                    unsigned char *key,         /* pointer to the expanded key schedule */
                    int number_of_rounds);      /* number of AES rounds 10, 12, or 14   */
