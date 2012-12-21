BLOOMBITS = 96
BLOOMBYTES = BLOOMBITS/8

def DEKHash(word):
	h = len(word)

	for c in word:
		h = ((h << 5) ^ (h >> 27)) ^ ord(c)
		h = h & 0xffffffff

	print "%x" % (h) 
	return h

def FNVHash(word):
	h = 0
	fnv_prime = 0x811C9DC5

	for c in word:
		h *= fnv_prime;
		h ^= ord(c);

	print "%x" % (h & 0xffffffff) 
	return (h & 0xffffffff)

def generate_bloom(word):
	bloomfilter = 0x000000000000000000000000
	d =  DEKHash(word)
	f =  FNVHash(word)
	posd = d % BLOOMBITS
	posf = f % BLOOMBITS
	bloomfilter |= 1 << ((posd % 8) + ((BLOOMBYTES-1)-posd / 8)*8)
	print hex(bloomfilter)
	bloomfilter |= 1 << ((posf % 8) + ((BLOOMBYTES-1)-posf / 8)*8)
	print hex(bloomfilter)
	return bloomfilter	

'''
def main():
	print hex(generate_bloom("DepecheMode"))
'''
if __name__ == "__main__":
	main()	
