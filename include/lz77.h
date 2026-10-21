#ifndef __LZ77__H
#define __LZ77__H 1

#define MIN_MATCH 3
#define MAX_MATCH 258
#define WINDOW_SIZE 32768

#define MAX_CHAIN 4096
#define HASH_BIT 15
#define HASH_SIZE (1 << HASH_BIT)

#define MAX_LIT_TREE ((286 * 2) -1)
#define MAX_DIST_TREE ((30*2) - 1)


/*change the behaviour of F_Gzip()*/
#define M_FILE 300

struct LZstate{
	int32_t head[HASH_SIZE];
	int32_t prev[WINDOW_SIZE];
	uint32_t max_chain;
};

struct LDpair {
	uint16_t length;
	uint16_t distance;
	uint8_t literal;
};

struct Hnode{
	uint32_t freq;
	int16_t left,rigth;
	uint16_t symbol;
};

struct Heap{
	struct Hnode *nodes;
	uint32_t *idx; /*a pointer to the index array*/
	int16_t size;
};

struct Bit_writer{
	uint64_t bwritten; 
	uint64_t capacity;
	uint32_t accumulator;
	int nbits; /*how many bits are meaningful in accumulator*/
	uint8_t *buffer;
};

struct Bit_reader{
	uint64_t bread; 
	uint64_t capacity;
	uint32_t accumulator;
	int nbits; /*how many bits are meaningful in accumulator*/
	uint8_t *buffer;
};

/*use to read Huffman code from a deflated input*/
struct Huffman{
	uint16_t count[16];
	uint16_t symbol[288];
};


/*use to keep the file in memory*/
struct F_unzip{
	uint64_t size;
	uint8_t *data;
};

struct Dflate{
	uint8_t *buf;
	uint64_t size;
};

struct Zlib_header{
	uint8_t a;
	uint8_t b;
};

struct Http_dflate{
	struct Zlib_header h;
	struct Dflate *d;
	uint32_t alder32;
};

long long deflate(uint8_t *input, uint64_t input_size,uint8_t **deflate_input);
long long inflate(uint8_t *input, uint64_t input_size,uint8_t *output,uint64_t output_size);
int F_unGzip(char *file_name);
long long F_Gzip(char *file_name,int mode, uint8_t **buffer);
int unZIP(uint8_t *file_content, uint64_t file_size, struct F_unzip *d);
int write_extracted_ZIP(struct F_unzip *d);
int browse_extracted_ZIP(char *file_name, struct F_unzip *d, uint8_t **file_stream);
#endif
