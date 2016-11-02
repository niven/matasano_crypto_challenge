#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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


char* encode_base64(char* s, uint16 size) {
	
	uint32 output_len = (size / 3) * 4; // amount of bytes we output for every 3 bytes of input
	if( size % 3 > 0 ) { // if there is a group at the end less than 3, we pad with 4 more
		output_len += 4;
	}
		
	// printf("Input size: %hu, Output length: %u\n", size, output_len);
	
	char* result = malloc( output_len+1 ); // terminating 0
	if( result == NULL ) {
		perror("malloc()");
		abort();
	}
	memset( result, '_', output_len );
	result[output_len] = '\0';

	// chunk s into 3 byte batches and do 4things after every 3,pad with 0 bytes and emit '='
	// we can't pad the string, since string == byte array
	uint32 buf;
	int i=0, r=0;
	for(i=0; i<size; i++) {
		buf <<= 8;
		buf |= s[i];

		if( i && ((i-2) % 3 == 0) ) {
			r += 4;
			for( int j=0; j<4; j++ ) { // this emits them in reverse order
				char c = base64_table[ buf & 0x3f ];
				buf >>= 6;
				result[r-j-1] = c;
			}
			buf = 0;
		}
	}

	// 1 or 2 bytes left
	if( size % 3 > 0 ) {

		int padding_bytes = 3 - size % 3;

		for( int i=0; i<padding_bytes; i++ ) {
			buf <<= 8; // right pad with some 0s
		}

		// readout the rest
		r += 4;
		for( int i=0; i<4; i++ ) {
			char c = base64_table[ buf & 0x3f ];
			buf >>= 6;
			result[r-i-1] = i >= padding_bytes ? c : '='; // TODO: ugly expression, hard to understand
		}
		
	}
	
	return result;
}

uint8 val_from_hex( char c ) {
	
	if( c >= '0' && c <= '9' ) {
		return c - '0';
	} else if( c >= 'a' && c <= 'f' ) {
		return (c-'a') + 10;
	} else {
		fprintf( stderr, "val_from_hex(): %c\n", c);
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
		result[r++] = hextable[ b.array[i] >> 4 ];
		result[r++] = hextable[ b.array[i] & 0xf ];
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

char* reverse_single_byte_xor( byte_array b, letter_frequencies lf ) {
	
	char* result;
	
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
	memset( xor_array.array, best_guess, xor_array.size );
	byte_array xor_single_byte = xor_bytes( b, xor_array );
	result = xor_single_byte.array;
	// printf("plaintext: %s\n", result );
	
	free( xor_array.array );
	
	return result;
}

byte_array encrypt_repeating_xor( byte_array b, const char* key ) {
	
	byte_array result = { .array = malloc(b.size), .size = b.size };
	
	uint16 key_size = strlen(key);
	for( uint16 i=0; i<b.size; i++ ) {
		char k = key[ i % key_size ];
		result.array[i] = b.array[i] ^ k;
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
void init_bits_table() {
	for( int i=0; i<=UCHAR_MAX; i++ ) { // don't make i usigned char otherwise it can't be 255
		bits_in_char[i] = bits_set(i);
	}
}

uint32 hamming_distance( const char* a, const char* b ) {
	
	// what if sizes are different? Assume 0s?
	assert( strlen(a) == strlen(b) );
	
	uint32 result = 0;
	
	for( int i=0; i<strlen(a); i++ ) {
		char x = a[i] ^ b[i];
		result += bits_in_char[ x ];
	}
	
	return result;
}

uint32 hamming_distance_size( const char* a, const char* b, unsigned int size ) {
	
	uint32 result = 0;
	
	for( int i=0; i<size; i++ ) {
		char x = a[i] ^ b[i];
		result += bits_in_char[ x ];
	}
	
	return result;
}


int main( int argc, char** argv ) {

	char hex[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
	printf("hex[%lu]: %s\n", strlen(hex), hex);

	byte_array bytes = bytes_from_hex( hex );
	
	char* check = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
	char* base64_encoded = encode_base64( bytes.array, bytes.size );
	free( bytes.array );

	printf("base64[%lu]: %s\n", strlen(base64_encoded), base64_encoded);
	printf("expect[%lu]: %s\n", strlen(check), check);
	printf("Correct: %s\n", strcmp(base64_encoded, check) == 0 ? "Yes" : "No");
	free( base64_encoded );
	
	// "tests"
	char* test[] = { 
		"any carnal pleasur",
		"any carnal pleasure.",
		"any carnal pleasure",
	};
	const int num_tests = ARRAY_COUNT(test);
	
	char* test_result[num_tests] = {
		"YW55IGNhcm5hbCBwbGVhc3Vy",
		"YW55IGNhcm5hbCBwbGVhc3VyZS4=",
		"YW55IGNhcm5hbCBwbGVhc3VyZQ==",
	};

	for( int i=0; i<num_tests; i++ ) {
		printf("Test: '%s'\n", test[i]);
		char* encoded = encode_base64( test[i], strlen(test[i]) );
		printf("base64[%lu]: %s\n", strlen(encoded), encoded);
		printf("expect[%lu]: %s\n", strlen(test_result[i]), test_result[i]);
		assert( strcmp(encoded, test_result[i]) == 0 );
		free( encoded );		
	}
	
	char* xor_a = "1c0111001f010100061a024b53535009181c";
	char* xor_b = "686974207468652062756c6c277320657965";
	char* result = "746865206b696420646f6e277420706c6179";
	uint16 xor_size = strlen(xor_a)/2 ;
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
	
	byte_array en_text = read_file( "Meditation XVII.txt" );
	// printf("File: %s\n", en_text.array);
	letter_frequencies lf;
	count_frequencies( en_text, &lf );
	free( en_text.array );

	
	char* hex_encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	byte_array xored_bytes = bytes_from_hex( hex_encoded );
	char* plaintext = reverse_single_byte_xor( xored_bytes, lf );
	printf("Plaintext: %s\n", plaintext);
	free( plaintext );
	free( xored_bytes.array );
	
	// Challenge 1.4
	byte_array file4 = read_file( "4.txt" );
	char* sep = "\n";
	char* line = strtok(file4.array,sep);
	int line_count = 0;
	double best_score = 0xffff;
	char* best_decoding = malloc( strlen(line)+1 );
	memset( best_decoding, 0, strlen(line)+1 ); 
	while( line != NULL ) {
		// printf("Line %d: %s\n", line_count++, line);

		byte_array cipher_bytes = bytes_from_hex( line );
		// find the best decoding
		char* plaintext = reverse_single_byte_xor( cipher_bytes, lf );
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

	// Challenge 1.5
	char* c15 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
	char* c15_expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
	
	printf("c15: %s\n", c15);
	byte_array c15_bytes = { .array = c15, .size = strlen(c15) };
	byte_array rep_xor_bytes = encrypt_repeating_xor( c15_bytes, "ICE" );
	char* c15_hex = hex_from_bytes( rep_xor_bytes );
	printf("Cipher: %s\n", c15_hex);
	assert( strcmp(c15_expected, c15_hex) == 0 );
	free( c15_hex );
	free( rep_xor_bytes.array );
	
	// Challenge 1.6
	init_bits_table();
	
	uint32 distance = hamming_distance( "this is a test", "wokka wokka!!!" );
	assert( distance == 37 );
	
	int max_keysize = 40;
	int shortest_distance = max_keysize * 256; 
	int best_keysize = -1;
	
	byte_array file6 = read_file( "6.txt" );
	char* a = file6.array;
	for( int i=2; i<max_keysize; i++ ) {
		char* b = a + i;
		distance = hamming_distance_size( a, b, i );
		printf("distance for %d = %d\n", i, distance);
	}
	
	free( file6.array );
	
	
	printf("Done.\n");
	exit(0);
}


























