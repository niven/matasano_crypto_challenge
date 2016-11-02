#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "../tiny-AES128-C/aes.h"

// alternative names for static to be less confused and to be able to find e.g. global_variable later
#define internal static
#define local_persist static
#define global_variable static

typedef unsigned char bool;
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#define ARRAY_COUNT(array) (sizeof(array) / sizeof((array)[0]))
#define LAST_INDEX(array) (ARRAY_COUNT(array)-1)

#define kilobyte( n ) (1024 * n)
#define megabyte( n ) (1024 * kilobyte(n))
#define gigabyte( n ) (1024 * (size_t)megabyte(n))
#define terabyte( n ) (1024 * gigabyte(n))

#define SWITCH_IS_EXHAUSTIVE(reason) default: { assert(!reason); };

#define FOPEN_CHECK( file, name, mode ) \
file = fopen( name, mode ); \
if( file == NULL ) { \
		perror("fopen()"); \
		printf( "%s:%d filename = %s\n", __FILE__, __LINE__, name); \
		exit( EXIT_FAILURE ); \
}


typedef struct byte_array {
	char* array;
	uint16 size;
} byte_array;

// murmurhash integer finalizer	
size_t hashcode( const char* b ) {

	size_t h = 0;
	for( uint16 i=0; i<strlen(b); i++ ) {
		h ^= b[i];
		h ^= h >> 33;
		h *= 0xff51afd7ed558ccd;
		h ^= h >> 33;
		h *= 0xc4ceb9fe1a85ec53;
		h ^= h >> 33;
	}

	return h;
}

typedef struct element {
	const char* key;
	byte_array val;
	struct element* next;
} element;

typedef struct hash {
	
	uint16 capacity;
	uint16 used;
	
	element** buckets;
	
} hash;

hash hash_new() {
	
	hash result = { .capacity = 8, .used = 0, .buckets = (element**)malloc( sizeof(element*) * 8 ) };
	memset( result.buckets, 0, sizeof(element*) * 8 );
	return result;
}


void hash_put( hash h, const char* key, byte_array val ) {
	
	assert( key != NULL );
	assert( val.array != NULL );
	
	printf("put %s:%.*s\n", key, val.size, val.array );

	size_t bucket_index = hashcode( key ) % h.capacity;
	printf("Bucket: %lu\n", bucket_index);
	element* new_element = (element*)malloc( sizeof(element) );
	new_element->key = key;
	new_element->val = val;
	new_element->next = NULL;

	if( !h.buckets[bucket_index] ) {
		h.buckets[bucket_index] = new_element;
	} else {
		new_element->next = h.buckets[bucket_index];
		h.buckets[bucket_index] = new_element;
	}
	
}

byte_array hash_get( hash h, const char* key ) {
	
	assert( key != NULL );
	size_t bucket_index = hashcode( key ) % h.capacity;
	element* current = h.buckets[ bucket_index ];
	
	while( current != NULL ) {
		if( strcmp( current->key, key ) == 0 ) {
			return current->val;
		}
		current = current->next;
	}
	
	return (byte_array){ .array = NULL, .size = 0 };
}

void hash_dump( hash h ) {
	
	printf("HD: capacity: %d\n", h.capacity);
	for( uint16 i=0; i<h.capacity; i++ ) {
		printf("\tBucket[%d]\n", i);
		element* current = h.buckets[i];
		while( current != NULL ) {
			printf("\t'%s' => %.*s\n", current->key, current->val.size, current->val.array );
			current = current->next;
		}
	}
}

void hash_free( hash h ) {
	
	for( uint16 i=0; i<h.capacity; i++ ) {
		element* current = h.buckets[i];
		while( current != NULL ) {
			element* temp = current;
			current = current->next;
			free( temp );
		}
	}
	
	free( h.buckets );
	
}


char* str_from_byte_array( byte_array b ) {
	
	char* result = NULL;

	result = malloc( b.size + 1 );
	memset( result, 0, b.size+1 );
	memcpy( result, b.array, b.size );
	
	return result;
}

byte_array byte_array_from_str( char* s ) {
	
	byte_array result;
	
	result.array = s;
	result.size = strlen(s);
	
	return result;
}

typedef struct letter_frequencies {
	double freq[UCHAR_MAX];
} letter_frequencies;

void count_frequencies( byte_array b, letter_frequencies* lf ) {
	
	memset( lf, 0, sizeof(letter_frequencies) );

	for( uint16 i=0; i<b.size; i++ ) {
		lf->freq[ (unsigned char)b.array[i] ]++;
	}

}

double cmp_letter_frequencies( letter_frequencies a, letter_frequencies b ) {
	
	int result = 0;
	
	for( int i=0; i<UCHAR_MAX; i++ ) {
		int diff = a.freq[i] - b.freq[i];
		if( diff < 0 ) {
			diff = -diff;
		}
		result += diff;
	}
	
	return result;
}

global_variable char* base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
// some wastage
global_variable char base64_table_reversed[UCHAR_MAX];
void init_base64_reverse_table() {
	// for each char in the base64 table
	// first char is 'A', which means:
	// 0b000 000 is encoded as A
	// 0b000 001 is encoded as B etc
	// we reverse now for easy decoding (if we see 'A', what do we get?)
	for( int i=0; i<strlen(base64_table); i++ ) {
		uint8 c = base64_table[i];
		base64_table_reversed[c] = i;
	}
}


byte_array base64_encode( byte_array b ) {
	
	uint32 output_len = (b.size / 3) * 4; // amount of bytes we output for every 3 bytes of input
	if( b.size % 3 > 0 ) { // if there is a group at the end less than 3, we pad with 4 more
		output_len += 4;
	}
	byte_array result	= { .array = malloc(output_len), .size = output_len };

	// chunk s into 3 byte batches and do 4 things after every 3,pad with 0 bytes and emit '='
	// we can't pad the string, since string == byte array
	uint32 buf;
	int i=0, r=0;
	for(i=0; i<b.size; i++) {
		buf <<= 8;
		buf |= b.array[i];

		if( i && ((i-2) % 3 == 0) ) {
			r += 4;
			for( int j=0; j<4; j++ ) { // this emits them in reverse order
				char c = base64_table[ buf & 0x3f ];
				buf >>= 6;
				result.array[r-j-1] = c;
			}
			buf = 0;
		}
	}

	// 1 or 2 bytes left
	if( b.size % 3 > 0 ) {
		int padding_bytes = 3 - b.size % 3;

		for( int i=0; i<padding_bytes; i++ ) {
			buf <<= 8; // right pad with some 0s
		}

		// readout the rest
		r += 4;
		for( int i=0; i<4; i++ ) {
			char c = base64_table[ buf & 0x3f ];
			buf >>= 6;
			result.array[r-i-1] = i >= padding_bytes ? c : '='; // TODO: ugly expression, hard to understand
		}
		
	}
	
	return result;
}

byte_array base64_decode( byte_array b ) {
	
	assert( b.size % 4 == 0 );
	
	// the number of bytes we output is 3 for every group of 4
	// except for the last group: ??== means 1 byte, ???= means 2 bytes, ???? means 3 bytes
	uint16 size = 3 * b.size / 4;
	if( b.array[size-1] == '=' ) {
		if( b.array[size-2] == '=' ) {
			size -= 2;
		} else {
			size -= 1;
		}
	} // it's a full block, no else

	byte_array result = { .array = malloc(size), .size = size };
	memset( result.array, '_', size );

	// this feels terrible, but I'm tired
	uint32 buf;
	int i, r = 0;
	for( i=0; i<b.size; i+=4 ) {
		
		buf = 0;
		for( int c=0; c<4; c++ ) {
			buf <<= 6;
			uint8 x = b.array[i+c];
			uint8 idx = base64_table_reversed[ x ];
			buf |= idx;
		}
		result.array[r++] = (buf >> 16) & 0xffff;
		result.array[r++] = (buf >> 8) & 0xffff;
		result.array[r++] = (buf >> 0) & 0xffff;
	}
	
	// now last 4
	buf = 0;
	for( int j=0; j<4; j++ ) {
		buf <<= 6;
		if( b.array[i+j] != '=' ) {
			uint8 x = b.array[i+j];
			uint8 idx = base64_table_reversed[ x ];
			buf |= idx;
		} // else "shift in 0" but that happens auto
	}
	result.array[r++] = (buf >> 16) & 0xffff;
	result.array[r++] = (buf >> 8) & 0xffff;
	result.array[r++] = (buf >> 0) & 0xffff;

	return result;
}

uint8 val_from_hex( char c ) {
	
	if( c >= '0' && c <= '9' ) {
		return c - '0';
	} else if( c >= 'a' && c <= 'f' ) {
		return (c-'a') + 10;
	} else if( c >= 'A' && c <= 'F' ) {
		return (c-'A') + 10;
	} else {
		fprintf( stderr, "val_from_hex(): not a hex char: %c\n", c);
		abort();
	}
}

byte_array bytes_from_hex( char* s ) {
	
	byte_array result;
	// strnlen, malloc check
	result.size = strlen(s)/2;
	result.array = malloc( result.size );
	
	for( int i=0; i<result.size; i++ ) {
		result.array[i] = val_from_hex( s[i*2] ) * 16 + val_from_hex( s[i*2 + 1] );
	}
	
	return result;
}

global_variable char* hextable = "0123456789abcdef";

char* hex_from_bytes( byte_array b ) {
	
	char* result = malloc( b.size*2 + 1 );
	memset( result, 0, b.size*2 + 1 );
	
	uint16 r = 0;
	for( uint16 i=0; i<b.size; i++ ) {
		uint8 val = b.array[i] & 0xff; // char is unsigned and sign extension happens
		result[r++] = hextable[ val >> 4 ];
		result[r++] = hextable[ val & 0xf ];
	}
	assert( r == b.size*2 );
	
	return result;
}

byte_array xor_bytes( byte_array a, byte_array b ) {

	assert( a.size == b.size );
	byte_array result = { .array = malloc(a.size), .size = a.size };
	for( uint16 i=0; i<a.size; i++ ) {
		result.array[i] = a.array[i] ^ b.array[i];
	}
	
	return result;
}

byte_array read_file( const char* name ) {
	
	byte_array result;

	FILE* in;
	FOPEN_CHECK( in, name, "r" );
	
	struct stat s;
	fstat( fileno(in), &s );
	
	result.size = s.st_size;
	printf("Creating buf of size %hu\n", result.size);
	result.array = malloc(result.size);
	if( result.array == NULL ) {
		perror("malloc()");
		abort();
	}
	
	fread( result.array, result.size, 1, in ); // read 1 item, all of it
	fclose(in);
	
	return result;
}

char reverse_single_byte_xor( byte_array b, letter_frequencies lf ) {
	
	char result;
	
	byte_array xor_array = { .array = malloc(b.size), .size = b.size };

	unsigned char best_guess = 0;
	double best_guess_cmp = 0xffff;
	for( unsigned char c=1; c<UCHAR_MAX; c++ ) {
		memset( xor_array.array, c, b.size );
		byte_array xor_single_byte = xor_bytes( b, xor_array );
		letter_frequencies lf_plain;
		count_frequencies( xor_single_byte, &lf_plain );
		double cmp_val = cmp_letter_frequencies( lf_plain, lf );
		if( cmp_val < best_guess_cmp ) {
			best_guess_cmp = cmp_val;
			best_guess = c;
		}
	}
	// printf("Best guess: %d='%c' (match %f)\n", best_guess, best_guess, best_guess_cmp);
	result = best_guess;
	// printf("plaintext: %s\n", result );
	
	free( xor_array.array );
	
	return result;
}


// in and out pointers may alias
void ecb_crypt( char* in, const char* key, char* out, uint16 size ) {
	
	for( uint16 i=0; i<size; i++ ) {
		out[i] = in[i] ^ key[i];
	}
	
}


byte_array encrypt_repeating_xor( byte_array b, byte_array key ) {
	
	byte_array result = { .array = malloc(b.size), .size = b.size };
	
	for( uint16 i=0; i<b.size; i+= key.size ) {
		ecb_crypt( b.array + i, key.array, result.array + i, key.size );
		// char k = key.array[ i % key.size ];
		// result.array[i] = b.array[i] ^ k;
	}
	
	return result;
}

// lol
byte_array decrypt_repeating_xor( byte_array b, byte_array key ) {
	return encrypt_repeating_xor( b, key );
}

char* decrypt_single_byte_xor( byte_array b, char c ) {
	
	char* result = malloc( b.size + 1 );
	memset( result, 0, b.size + 1 );
	
	for( int i=0; i<b.size; i++ ) {
		result[i] = b.array[i] ^ c;
	}
	
	return result;
}

global_variable uint8 bits_in_char[UCHAR_MAX];
uint8 bits_set( char c ) {
	
	uint8 result = 0;

	// kernighan's way
	for (result = 0; c; result++) {
	  c &= c - 1; // clear the least significant bit set
	}
	
	return result;
}
void init_bitcount_table() {
	for( int i=0; i<=UCHAR_MAX; i++ ) { // don't make i usigned char otherwise it can't be 255
		bits_in_char[i] = bits_set(i);
	}
}

uint32 hamming_distance( const char* a, const char* b, uint16 size ) {
	
	uint32 result = 0;
	
	for( uint16 i=0; i<size; i++ ) {
		// printf("HD(%d): %d - %d\n", size, a[i], b[i]);
		uint8 x = a[i] ^ b[i];
		result += bits_in_char[ x ];
	}
	
	return result;
}

// split b into num_blocks taking the first byte of b and putting it into block 1
void transpose_blocks( byte_array b, int num_blocks, byte_array blocks[] ) {
	
	int block_size_min = b.size / num_blocks;
	int blocks_with_extra = b.size % num_blocks;
	// printf("b size: %d, tp into %d\n", b.size, num_blocks);
	// printf("%d blocks of size %d, %d of size %d\n", blocks_with_extra, block_size_min+1, num_blocks - blocks_with_extra, block_size_min);
	assert( b.size == (block_size_min*(num_blocks-blocks_with_extra)) + blocks_with_extra*(block_size_min+1) );
	
	// create the blocks (some might be larger if num_blocks does not divide b.sie)
	for( int i=0; i<num_blocks; i++ ) {
		int block_size = block_size_min + (i < blocks_with_extra ? 1 : 0 ); // being cute
		blocks[i].size = block_size;
		blocks[i].array = malloc(block_size);
	}
	
	for( uint32 i=0; i<b.size; i++ ) {
		blocks[ i % num_blocks ].array[ i / num_blocks ] = b.array[i];
	}
}

uint16 find_repeating_xor_keysize( byte_array b, uint16 max ) {
	
	uint16 result;

	// little guesswork here. if you oversample there is some way that FOOFOO becomes a smal edit distance
	// there is a bug somewhere I'm sure
	int samples = b.size / (max*5);

	char *mid, *start;
	double distance, shortest_distance = 1024 * 1024;
	for( int i=2; i<max; i++ ) {
		
		distance = 0;
		for( int s=0; s<samples; s++ ) {
			start = b.array + (s * i);
			mid = start + i;
			distance += hamming_distance( start, mid, i );
		}
		
		distance /= (double)i; // normalize
		// printf("distance for %d = %.5f\n", i, distance );
		if( distance < shortest_distance ) {
			shortest_distance = distance;
			result = i;
		}
	}

	return result;
}

byte_array recover_repeating_xor_key( byte_array b, letter_frequencies lf ) {

	byte_array result;
	
	int keysize = find_repeating_xor_keysize( b, 40 );
	printf("Keysize: %d\n", keysize );

	byte_array blocks[keysize];
	transpose_blocks( b, keysize, blocks );
		
	result.array = malloc(keysize);
	result.size = keysize;
	
	for( int i=0; i<keysize; i++ ) {
		char single_byte_key = reverse_single_byte_xor( blocks[i], lf );
		// printf("Char for block[%d] = %c\n", i, single_byte_key);
		result.array[i] = single_byte_key;
		free( blocks[i].array );
	}
	// printf("Recovered key: %.*s (size: %d)\n", keysize, result.array, keysize );
	
	return result;	
}



/*
	RFC 2315 section 10.3
	https://tools.ietf.org/html/rfc2315#section-10.3

	instructions unclear? RFC too hard to read? So tired.

	So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance, 
*/
byte_array pad_pkcs7( byte_array b, uint16 size ) {
	
	byte_array result = { .array = malloc(size), .size = size };
	
	assert( b.size <= size );
	memcpy( result.array, b.array, b.size );
	
	uint16 padding_size = size - b.size;
	assert( padding_size < 256 );
	// printf("padchar = %d\n", padding_size );
	memset( result.array + b.size, (unsigned char)padding_size, padding_size );
	
	return result;
}

uint8 ecb_mode( char* buf, uint16 size, uint16 block_size ) {
	
	for( int block = 0; block < size-block_size; block+=block_size ) {
		for( int next_block = block + block_size; next_block < size; next_block += block_size ) {
			if( memcmp( buf + block, buf + next_block, block_size) == 0 ) {
				return 1;
			}				
		}
	}
	
	return 0;
}

byte_array encrypt_cbc( byte_array plaintext, const char* iv, const char* key, uint16 keysize, void encrypt_func( uint8_t*, const uint8_t*, uint8_t*) ) {

	assert( plaintext.size % keysize == 0 );
	byte_array result = { .array = malloc(plaintext.size), .size = plaintext.size };
	memset( result.array, 0, result.size );

	byte_array mix = { .array = malloc(keysize), .size = keysize };
	memcpy( mix.array, iv, keysize );
	
	char *current_plaintext_block, *current_ciphertext_block;
	for( uint16 i=0; i<plaintext.size; i+=keysize ) {
		current_plaintext_block = plaintext.array + i;
		current_ciphertext_block = result.array + i;

		ecb_crypt( mix.array, current_plaintext_block, mix.array, keysize ); // IV XOR plaintext		
		encrypt_func( (uint8_t*)mix.array, (const uint8_t*)key, (uint8_t*)current_ciphertext_block );
		memcpy( mix.array, current_ciphertext_block, keysize ); // update IV/mix for next cycle
	}
	
	free( mix.array );
	return result;
}

byte_array decrypt_cbc( byte_array ciphertext, const char* iv, const char* key, uint16 keysize, void decrypt_func( uint8_t*, const uint8_t*, uint8_t*) ) {
	
	byte_array result = { .array = malloc(ciphertext.size), .size = ciphertext.size };
	memset( result.array, 0, result.size );

	byte_array block = { .array = malloc(keysize), .size = keysize };
	memcpy( block.array, iv, block.size );
	
	char *current_plaintext_block, *current_ciphertext_block;
	for( uint16 i=0; i<ciphertext.size; i+=keysize ) {
		current_ciphertext_block = ciphertext.array + i;
		current_plaintext_block = result.array + i;

		decrypt_func( (uint8_t*)current_ciphertext_block, (const uint8_t*)key, (uint8_t*)current_plaintext_block );
		ecb_crypt( current_plaintext_block, block.array, current_plaintext_block, keysize ); // mixing cipher block, first time this is the IV
		memcpy( block.array, current_ciphertext_block, keysize );
	}
	free( block.array );
	
	return result;
	
}

void random_bytes( char* buf, uint16 size ) {
	
	union {
		long l;
		char c[sizeof(long)];
	} u;
	
	for( uint16 i=0; i<size; i+=4 ) {
		u.l = random(); // size 31 bit integer
		// printf("rnd: %lu\n", u.l);
		memcpy( buf+i, u.c, 4 );
	}
	u.l = random();
	uint16 remainder = size % 4;
	// printf("rem: %d\n", remainder);
	memcpy( buf + size - remainder, u.c, remainder );

}

global_variable uint8 oracle_mode_is_cbc;
 
byte_array encryption_oracle( byte_array plaintext ) {
	
	byte_array result;
	
	uint16 keysize = 16;
	char key[keysize];
	random_bytes( key, keysize );
	
	uint16 pre = 5 + (random() % 6);
	uint16 post = 5 + (random() % 6);
	char stretch[pre+post];
	// printf("stretch is %d\n", pre+post);
	random_bytes( stretch, pre + post );
	byte_array stretched = { .array = malloc(pre + plaintext.size + post), .size = pre + plaintext.size + post };
	memcpy( stretched.array, stretch, pre );
	memcpy( stretched.array, plaintext.array, plaintext.size );
	memcpy( stretched.array, stretch+pre, post );
	
	uint16 block_size = keysize;
	byte_array padded = pad_pkcs7( stretched, (stretched.size/block_size)*block_size + (stretched.size % block_size == 0 ? 0 : block_size) );
	free( stretched.array );
	
	result = (byte_array){ .array = NULL, .size = padded.size };
	
	oracle_mode_is_cbc = random() % 2;
	if( oracle_mode_is_cbc ) {
		// printf("sssh, cbc\n");
		char iv[keysize];
		random_bytes( iv, keysize );
		result.array = (encrypt_cbc( padded, iv, key, keysize, AES128_ECB_encrypt )).array;
	} else {
		// printf("sssh, ecb\n");
		result.array = malloc( result.size );
		for( uint16 i=0; i<result.size; i+=16 ) {
			AES128_ECB_encrypt( (uint8_t*)(padded.array + i), (const uint8_t*)key, (uint8_t*)result.array + i);
		}
	}
	
	return result;
}

byte_array ecb_with_unknown_key( byte_array plaintext ) {
	
	uint16 keysize = 16;
	char key[keysize];
	srandom( 23458765 ); // ensure the same key every time
	random_bytes( key, keysize );	

	// secret to be encrypted with an unknown key
	char unknown_string_base64[] = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
	byte_array unknown_string = base64_decode( (byte_array){.array = unknown_string_base64, .size = strlen(unknown_string_base64)} );

	// append the unknown string
	byte_array in = { .array = malloc( plaintext.size + unknown_string.size ), .size = plaintext.size + unknown_string.size };
	memcpy( in.array, plaintext.array, plaintext.size );
	memcpy( in.array + plaintext.size, unknown_string.array, unknown_string.size );
	free( unknown_string.array );

	uint16 result_size = plaintext.size + unknown_string.size;
	// round that up to a multiple of the keysize/blocksize
	if( result_size % keysize != 0 ) {
		result_size += keysize - (result_size % keysize);
	}

	byte_array padded = pad_pkcs7( in, result_size );
	free( in.array );
	
	byte_array result = { .array = malloc( result_size ), .size = result_size };
	for( uint16 i = 0; i < result.size; i += keysize ) {
		AES128_ECB_encrypt( (uint8_t*)(padded.array + i), (const uint8_t*)key, (uint8_t*)result.array + i);
	}
	free( padded.array );
	
	return result;
}

byte_array decrypt_ecb_with_unknown_key( uint16 block_size, byte_array oracle_func( byte_array) ) {
	
	byte_array known = oracle_func( (byte_array){ .array = NULL, .size = 0} );
	uint16 message_size = known.size;
	printf("message size: %d\n", message_size);
	// Hmmmm
	assert( message_size % block_size == 0 );
	
	byte_array result = { .array = malloc(message_size), .size = message_size };
	memset( result.array, '_', result.size );

	// somehow things won't click, so here is a long explanation
	// I want to recover the plaintext. I know how long it is and the oracle will prepend
	// whatever I give it to the message and then encrypt (I've found it's 16 byte ECB already)
	// To get the first byte: give it AAAA AAAA AAAA AAA so the first block is 15 of my known bytes
	// and then the first byte of the plaintext. Then I try every AAAA AAAA AAAA AAAAi for 0<=i<=255
	// to recover the first byte. Good times and by induction we are done. In practice there is no clicking :)
	// ok, byte 2: we give it AAAA AAAA AAAA AAR so the block is again including a single unkown byte (R==recovered)
	// Then I try every AAAA AAAA AAAA AARi for 0<=i<=255 to get the second byte etc until I have the whole block.
	// seems ok, let's do that first. No wait, that is BS, there is no 'next byte' as we just get the same first byte of the
	// message again. maybe I submit AAAA AAAA AAAA AA ? then I do get the first 2 bytes (and I know the first one already)
	// then I compare that against all blocks AAAA AAAA AAAA AARi for 0<=i<=255 to see what is up?
	// sounds better.
	// ok, that worked. Now the second block??
	// I have RRRR RRRR RRRR RRRR, how do I get the next byte again of the second block?
	// I can't "shrink" the know text below 0 of course..
	// so I need to submit something long enough to make sure I end up with:
	// AAAA AAAA AAAA AAAR RRRR RRRR RRRR RRR? to get that next byte
	// so that's the same thing as before, except that I compare against the second block
	// ok, that made a bunch of messy code
	// breaking it down some more:
	// I can do the first block
	// the second block: prepend A so teh 2nd block that is returned consists of RRRR RRRR RRRR RRR?
	// then submit RRRR RRRR RRRR RRRi for 0<=i<=255 to find that byte
	/*
		Easier comments :)
		anyway, for block 0:
		prepend (block_size-1) A for the single unknown byte output block (output block 0)
		then trial A...A + i=0-255 and compare against output block 0 to find r0
		then prepend (block_size-(1+r)) A for the next single unkown byte block (output block 0)
		then trial A...(r..) + i=0-255 and compare against output block 0 to find r1
		etc
	
		for block 1:
		prepend (block_size-1) A for the single unknown byte output block, block 1
		then trial r0..r(block_size-1) + i=0-255 and compare against output block 1
	*/
	
	uint16 num_blocks = message_size / block_size;
	result.size = 0;
	for( int b=0; b<num_blocks; b++ ) {
		// printf("Block %d\n", b);
		for( int i=0; i<block_size; i++ ) {
			// printf("\tbyte %d\n", i);
			
			// get a block with a single unknown byte in the last position
			memset( known.array, 'A', block_size );
			known.size = block_size - (1+i);
			// printf("Prepend (%2d): %.*s\n", known.size, known.size, known.array );
			byte_array single_unknown_byte = oracle_func( known );
			char* output_block = single_unknown_byte.array + (b*block_size);

			// now trials. For the first block this is AAAA.... but for later ones we need the recovered bytes
			// since known still holds the right number of AAAA... we can copy the recovered over those to end up with
			// the bytes that we need.
			// To visualize this: whenever we trial things, the last N bytes of the block should be recovered bytes
			// (except the last byte, which we are checking) but those bytes must be the *last* recovered bytes
			// so it's really the first block that is exceptional
			if( b == 0 ) {
				memcpy( known.array + block_size - (1+i), result.array, result.size );
			} else {
				// take the last block_size bytes
				memcpy( known.array, result.array + result.size - block_size + 1, block_size );
			}
			// memcpy( known.array + block_size - (1+i), result.array + (b*block_size), result.size );
			known.size = block_size;
			for( int t=0; t<256; t++ ) {
				known.array[ block_size-1 ] = t;
				// printf("Trialling: %.*s + %d\n", block_size-1, known.array, t );
				byte_array trial_output = oracle_func( known );
				if( memcmp( trial_output.array, output_block, block_size ) == 0 ) {
					result.array[ result.size ] = t;
					result.size++;
					// printf("Recovered byte %d:%d = %c\n", b, i, t );
					break;
				}				
			}
			
			// printf("Recovered(%3d): %.*s\n", result.size, result.size, result.array );
		}
	}
	

	return result;
}

hash parse_kv( const char* kv ) {
	
	char* buf = malloc( strlen(kv) );
	strcpy( buf, kv );
	
	hash result = hash_new();
	
	char* k = strtok( buf, "=" );
	char* v;
	while( k != NULL ) {
		v = strtok( NULL, "&" );
		printf("k/v => %s/%s\n", k, v);
		hash_put( result, k, byte_array_from_str(v) );

		k = strtok( NULL, "=" );
	}
	
	free( buf );
	
	return result;
}

int main( int argc, char** argv ) {

	init_base64_reverse_table();
	char* str;

	// Base64 encoding
{	
	char hex[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	printf("hex[%lu]: %s\n", strlen(hex), hex);

	byte_array bytes = bytes_from_hex( hex );
	
	char* check = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	byte_array base64_encoded = base64_encode( bytes );
	free( bytes.array );

	str = str_from_byte_array( base64_encoded );
	printf("base64[%hu]: %s\n", base64_encoded.size, str);
	printf("expect[%lu]: %s\n", strlen(check), check);
	assert( strlen(str) == strlen(check) );
	assert( strcmp(str, check) == 0 );
	free( base64_encoded.array );
	free( str );
}

// base64 encoding tests
{	
	// "tests"
	char* test[] = { 
		"any carnal pleasur",
		"any carnal pleasure.",
		"any carnal pleasure",
	};
	const int num_tests = ARRAY_COUNT(test);
	
	char* test_result[] = {
		"YW55IGNhcm5hbCBwbGVhc3Vy",
		"YW55IGNhcm5hbCBwbGVhc3VyZS4=",
		"YW55IGNhcm5hbCBwbGVhc3VyZQ==",
	};

	for( int i=0; i<num_tests; i++ ) {
		byte_array t = { .array = test[i], .size = strlen(test[i]) };
		printf("test   [%hu]: %s\n", t.size, t.array );

		byte_array encoded = base64_encode( t );
		str = str_from_byte_array( encoded );
		printf("encoded[%lu]: %s\n", strlen(str), str);
		printf("expect [%lu]: %s\n", strlen(test_result[i]), test_result[i]);
		assert( strcmp(str, test_result[i]) == 0 );
		free( str );

		byte_array decoded = base64_decode( encoded );
		str = str_from_byte_array( decoded );
		printf("roundtr[%lu]: %s\n", strlen(str), str);
		assert( strcmp(str, test[i]) == 0 );
		free( str );

		free( decoded.array );
		free( encoded.array );		
	}
}
	
// xor bytes
{	
	char* xor_a = "1c0111001f010100061a024b53535009181c";
	char* xor_b = "686974207468652062756c6c277320657965";
	char* result = "746865206b696420646f6e277420706c6179";

	byte_array xor_a_bytes = bytes_from_hex( xor_a );
	byte_array xor_b_bytes = bytes_from_hex( xor_b );
	byte_array xor_ab_bytes = xor_bytes( xor_a_bytes, xor_b_bytes );
	char* xor_result_hex = hex_from_bytes( xor_ab_bytes );
	printf("expect: %s\nresult: %s\n", result, xor_result_hex);
	assert( strcmp(xor_result_hex, result) == 0 );
	free( xor_a_bytes.array );
	free( xor_b_bytes.array );
	free( xor_ab_bytes.array );
	free( xor_result_hex );
}

// Challenge 1.4
	byte_array en_text = read_file( "Meditation XVII.txt" );
	// printf("File: %s\n", en_text.array);
	letter_frequencies lf;
	count_frequencies( en_text, &lf );
	free( en_text.array );
	char* line;
	int line_count;
	char* sep = "\n";

{

	
	char* hex_encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	byte_array xored_bytes = bytes_from_hex( hex_encoded );
	char single_byte_key = reverse_single_byte_xor( xored_bytes, lf );
	char* plaintext = decrypt_single_byte_xor( xored_bytes, single_byte_key );
	printf("Plaintext: %s\n", plaintext);
	free( plaintext );
	free( xored_bytes.array );
	
	// Challenge 1.4
	byte_array file4 = read_file( "4.txt" );
	line = strtok(file4.array,sep);
	line_count = 0;
	double best_score = 0xffff;
	char* best_decoding = malloc( strlen(line)+1 );
	memset( best_decoding, 0, strlen(line)+1 ); 
	while( line != NULL ) {
		// printf("Line %d: %s\n", line_count++, line);

		byte_array cipher_bytes = bytes_from_hex( line );
		// find the best decoding
		char single_byte_key = reverse_single_byte_xor( cipher_bytes, lf );
		char* plaintext = decrypt_single_byte_xor( cipher_bytes, single_byte_key );
		free( cipher_bytes.array );
		
		letter_frequencies lf_plain;
		byte_array temp = { .array = plaintext, .size = strlen(plaintext) };
		count_frequencies( temp, &lf_plain );
		free( plaintext );

		double cmp_val = cmp_letter_frequencies( lf_plain, lf );
		if( cmp_val < best_score ) {
			best_score = cmp_val;
			strcpy( best_decoding, plaintext );
		}
		
		line = strtok( NULL, sep);
	}
	printf("Best decoding: %s\n", best_decoding);

	free( best_decoding );
	free( file4.array );
}

	// Challenge 1.5
{
	char* c15 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	char* c15_expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	
	printf("c15: %s\n", c15);
	byte_array c15_bytes = { .array = c15, .size = strlen(c15) };
	byte_array rep_xor_bytes = encrypt_repeating_xor( c15_bytes, byte_array_from_str("ICE") );
	char* c15_hex = hex_from_bytes( rep_xor_bytes );
	printf("Cipher: %s\n", c15_hex);
	assert( strcmp(c15_expected, c15_hex) == 0 );
	free( rep_xor_bytes.array );

	rep_xor_bytes = decrypt_repeating_xor( rep_xor_bytes, byte_array_from_str("ICE") );
	str = str_from_byte_array( rep_xor_bytes );
	printf("decrypted: %s\n", str);
	free( str );
	free( rep_xor_bytes.array );
	free( c15_hex );
}
	
	// Challenge 1.6
	init_bitcount_table();
{
	uint32 distance = hamming_distance( "this is a test", "wokka wokka!!!", strlen("this is a test") );
	assert( distance == 37 );
	
	char* test_text = "No man is an island, entire of itself; every man is a piece of the continent, a part of the main. If a clod be washed away by the sea, Europe is the less, as well as if a promontory were, as well as if a manor of thy friend's or of thine own were: any man's death diminishes me, because I am involved in mankind, and therefore never send to know for whom the bell tolls; it tolls for thee.";
	byte_array btt = byte_array_from_str( test_text );
	
	char* key = "SUGAR";
	byte_array btt_e = encrypt_repeating_xor( btt, byte_array_from_str(key) );
	
	byte_array recovered_key = recover_repeating_xor_key( btt_e, lf );

	byte_array btt_d = decrypt_repeating_xor( btt_e, recovered_key );	
	
	printf("Recovered key: %.*s decrypted: %.*s\n", recovered_key.size, recovered_key.array, btt_d.size, btt_d.array);
	free( btt_d.array );
	free( btt_e.array );

	byte_array file6_base64 = read_file( "6.txt" );
	byte_array file6_plain = base64_decode( file6_base64 );
	// byte_array file_base64_recoded = base64_encode( file6_plain );
	// printf("%.*s\n", file_base64_recoded.size, file_base64_recoded.array );
	// printf("cmp: %d\n", memcmp(file_base64_recoded.array, file6_base64.array, file6_base64.size) );
	free( file6_base64.array );
	
	
	recovered_key = recover_repeating_xor_key( file6_plain, lf );
	printf("Recovered key: %.*s\n", recovered_key.size, recovered_key.array );
	byte_array file6_decypted = decrypt_repeating_xor( file6_plain, recovered_key );
	printf("Plaintext: %.*s\n", file6_decypted.size, file6_decypted.array );
	free( recovered_key.array );
	free( file6_decypted.array );
}

	// Challenge 1.7 - AES in ECB mode
{
	byte_array file7_base64 = read_file( "7.txt" );
	byte_array file7_bytes = base64_decode( file7_base64 );
	free( file7_base64.array );

	uint8_t output[16];
	uint8_t aes_key[16];
	memcpy( aes_key, "YELLOW SUBMARINE", 16);

	for( uint64_t i=0; i<file7_bytes.size; i+= 16 ) {
		AES128_ECB_decrypt( (uint8_t*)(file7_bytes.array + i), aes_key, output);
		printf("%.16s", output );		
	}

	free( file7_bytes.array );
}

	// Challenge 1.8 - Detect AES in ECB mode
{
	// TL;DR: drunk
	// every 128 bits / 16 bytes are ECB, so maybe there are 2 which are the same? I mean 'something else is' my happen more often
	// maybe ther is one letter different but then hamming won't help us
	// 1. read file and split into hexlines
	// 2. bytes_from_hex on each line
	// 3. process line and find ECB
	// 4. SUGAR
	
	byte_array file8 = read_file( "8.txt" );
	sep = "\n";
	line = strtok( file8.array, sep );
	line_count = 0;
	int line_found = 0;
	while( !line_found && line != NULL ) {
		line_count++;
		// printf("line %d (%lu): %s\n", line_count, strlen(line), line );
		line = strtok( NULL, sep );
		// do something stupid
		assert( strlen(line) == 320 );
		if( ecb_mode( line, 320, 16 ) ) {
			line_found = line_count;
		}
	}
	assert( line_found );
	printf("Found AES128 ECB on line %d\n", line_found);		
	free( file8.array );
}

	// Challenge 2 - 9 PKCS#7 padding
{
	byte_array unpadded = byte_array_from_str( "YELLOW SUBMARINE" );
	byte_array padded_pkcs7 = pad_pkcs7( unpadded, 20 );
	char* padded_hex = hex_from_bytes( padded_pkcs7 );
	printf("PKCS#7: %s\n", padded_hex);
	free( padded_hex );
	free( padded_pkcs7.array );
}

// Challege 2 - 10 Implement CBC mode
{
	
	char key[] = "YELLOW SUBMARINE";
	uint16 keysize = strlen(key);
	char iv[ keysize ];
	
	// intermediate test
	{
	memset( iv, 0x00, keysize );
	byte_array cbc_test = byte_array_from_str( "ECB mode can also make protocols without integrity protection even more susceptible to replay attacks, since each block gets decrypted in exactly the same way.." );
	byte_array cbc_test_encrypted = encrypt_cbc( cbc_test, iv, key, keysize, AES128_ECB_encrypt );
	byte_array cbc_test_decypted = decrypt_cbc( cbc_test_encrypted, iv, key, keysize, AES128_ECB_decrypt );
	char* iv_hex = hex_from_bytes( (byte_array){.array = iv, .size = keysize} );
	printf("CBC Test size: %d\n", cbc_test.size );
	printf("CBC Test IV: %s\n", iv_hex );
	printf("CBC Test plain:   %.*s\n", cbc_test.size, cbc_test.array );
	// printf("CBC Test encrypt: %.*s\n", cbc_test_encrypted.size, cbc_test_encrypted.array );
	printf("CBC Test decoded: %.*s\n", cbc_test_decypted.size, cbc_test_decypted.array );
	assert( cbc_test.size == cbc_test_decypted.size );
	assert( memcmp( cbc_test.array, cbc_test_decypted.array, cbc_test.size ) == 0 );
	free( cbc_test_decypted.array );
	free( iv_hex );
	}
	
	// actual challenge
	memset( iv, 0x00, keysize );
	byte_array file10_base64 = read_file( "10.txt" );
	// printf("file10: %.*s\n", file10_base64.size, file10_base64.array );
	byte_array file10 = base64_decode( file10_base64 );
	free( file10_base64.array );


	byte_array file10_decrypted = decrypt_cbc( file10, iv, key, keysize, AES128_ECB_decrypt );
	printf("CBC decypt with %s: %.*s\n", key, file10_decrypted.size, file10_decrypted.array );
	free( file10.array );
	free( file10_decrypted.array );

}

// Challenge 2 - 11 An ECB/CBC detection oracle
{
	srandom( time(NULL) );
	uint16 block_size = 16;
	char random_key[block_size];
	random_bytes( random_key, block_size );
	char* hex_key = hex_from_bytes( (byte_array){.array = random_key, .size=block_size } );
	printf("Random key: %s\n", hex_key);
	free( hex_key );

	// 64x same letter so I can se if ECB is happening. I assume I can known plaintext this? Guess I'll see later on
	byte_array input = byte_array_from_str( "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" );

	for( int i=0; i<10; i++ ) {
		byte_array mystery = encryption_oracle( input );
		uint8 mode_is_ecb = ecb_mode( mystery.array, mystery.size, block_size );
		char* hex_mystery = hex_from_bytes( mystery );
		printf("oracled says: %s (should be %s)- %s\n", mode_is_ecb ? "ECB" : "CBC", oracle_mode_is_cbc ? "CBC" : "ECB", hex_mystery);
		assert( mode_is_ecb != oracle_mode_is_cbc );
		free( mystery.array );
		free( hex_mystery );
		
	}
}

// Challenge 2 - 12 Byte-at-a-time ECB decryption (Simple)
#if 0
{
	// find the block size (assuming ECB here, not sure how to when I'm unsure?)
	// seems to make more sense to use oracle to find CBC/ECB, then if ECB find blocksize
	// No idea how to find the blocksize in CBC
	byte_array known = { .array = malloc(128), .size = 0 };
	memset( known.array, 'A', 128 );
	// go by 2s as we find the blocksize when we input twice the blocksize
	uint16 blocksize = 0;
	for( int i=2; i<128; i += 2 ) {
		known.size = i;
		byte_array result = ecb_with_unknown_key( known );
		if( memcmp( result.array, result.array + i/2, i/2) == 0 ) {
			blocksize = i/2;
			break;
		}
	}
	free( known.array );
	printf("Found the blocksize: %d\n", blocksize);

	// Think about what the oracle function (ecb_with_unknown_key) is going to put in that last byte position.
	// Ehhhh....
	// so the input will be AAAA AAAA AAAA AAA?
	// which will be xored with the key (which I don't know)
	//                      KKKK KKKK KKKK KKKK
	// then I can make AAAA, AAAAB, AAAAC and find the one that matches the ecb_with_unknown_key output
	
	byte_array recovered_plaintext = decrypt_ecb_with_unknown_key( blocksize, ecb_with_unknown_key );
	printf("Recovered plaintext: %.*s\n", recovered_plaintext.size, recovered_plaintext.array );
	free( recovered_plaintext.array );
	
}
#endif

// intermezzo: build a hash data structure
{
	hash test = hash_new();
	
	hash_put( test, "one", byte_array_from_str("111") );
	hash_put( test, "two", byte_array_from_str("222") );
	hash_put( test, "three", byte_array_from_str("333") );
	hash_put( test, "four", byte_array_from_str("444") );
	hash_dump( test );
	
	byte_array val = hash_get( test, "one" );
	printf("one => %.*s\n", val.size, val.array );
	val = hash_get( test, "four" );
	printf("four => %.*s\n", val.size, val.array );
	val = hash_get( test, "two" );
	printf("two => %.*s\n", val.size, val.array );
	
	val = hash_get( test, "not_present" );
	assert( val.array == NULL && val.size == 0 );

	hash_free( test );
}
// Challenge 2 - 13 ECB cut-and-paste
{
	hash kv = parse_kv( "foo=bar&baz=qux&zap=zazzle" );
	hash_dump( kv );
	hash_free( kv );
}
	printf("Done.\n");
	exit(0);
}


























