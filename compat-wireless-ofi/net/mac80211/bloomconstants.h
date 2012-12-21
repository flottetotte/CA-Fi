/*The length of the bloom filter*/
#define BLOOMBITS   	96u

/*How many bytes it has*/
#define BLOOMBYTES     	(BLOOMBITS / 8u)

/*Macros for displaying numbers as bit patterns*/
#define BLOOMBYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BLOOMBYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 
