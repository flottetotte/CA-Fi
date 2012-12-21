/**
 * Calculates the DEKHash for a given char sequence and given length
 *
 * @param str		       	reference to the sequence
 * @param len              	len of the input sequence
 */
unsigned int DEKHash(char* str, unsigned int len);

/**
 * Calculates the FNVHash for a given char sequence and given length
 *
 * @param str		       	reference to the sequence
 * @param len              	len of the input sequence
 */
unsigned int FNVHash(char* str, unsigned int len);

/**
 * Sets a given bit in the bloom filter
 *
 * @param x		       	bit position to set
 * @param filter              	reference to the bloom filter
 */
void bloom_set_bit(unsigned int x, unsigned char* filter); 

/**
 * Tests a given bit position in the bloom filter 
 *
 * @param x		       	bit position to check
 * @param len              	reference to the bloom filter
 */
int bloom_test_bit(unsigned int x, unsigned char* filter);

/**
 * Inserts a given sequence into the bloom filter
 *
 * @param word		       	the sequence to insert
 * @param filter              	reference to the bloom filter
 */
void bloom_insert(char *word, unsigned char* filter);

/**
 * Checks if a given sequence is in the bloom filter
 *
 * @param word		       	the sequence to check
 * @param filter              	reference to the bloom filter
 */
int bloom_check(char *word, unsigned char* filter);

