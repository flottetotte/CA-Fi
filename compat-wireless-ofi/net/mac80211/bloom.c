#include <linux/module.h> 
#include "bloomconstants.h"

unsigned int DEKHash(char* str, unsigned int len)
{
	unsigned int hash = len;
	unsigned int i    = 0;

	for(i = 0; i < len; str++, i++)	{
		hash = ((hash << 5) ^ (hash >> 27)) ^ (*str);
	}

	return hash;
}

unsigned int FNVHash(char* str, unsigned int len)
{
	const unsigned int fnv_prime = 0x811C9DC5;
	unsigned int hash      = 0;
	unsigned int i         = 0;

	for (i = 0; i < len; str++, i++)	{
		hash *= fnv_prime;
		hash ^= (*str);
	}

	return hash;
}

void bloom_set_bit(unsigned int x, unsigned char* filter)
{
	filter[x / 8] |= 1u << x % 8;
}

int bloom_test_bit(unsigned int x, unsigned char* filter)
{
	return filter[x / 8] & (1u << x % 8);
}

void bloom_insert(char *word, unsigned char* filter)
{
	unsigned h;
	h = DEKHash(word, strlen(word)) % BLOOMBITS; bloom_set_bit(h,filter);
	h = FNVHash(word, strlen(word)) % BLOOMBITS; bloom_set_bit(h,filter);
}
EXPORT_SYMBOL(bloom_insert);

int bloom_check(char *word, unsigned char* filter)
{
	unsigned h;
	h = DEKHash(word, strlen(word)) % BLOOMBITS; if (!bloom_test_bit(h,filter)) return 0;
	h = FNVHash(word, strlen(word)) % BLOOMBITS; if (!bloom_test_bit(h,filter)) return 0;
	return 1;
}
EXPORT_SYMBOL(bloom_check);
