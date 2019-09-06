#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <sstream>

/*
enum ByteOrder {
	LITTLE_ENDIAN_ORDER = 0,
	BIG_ENDIAN_ORDER = 1};
*/

// BIG_ENDIAN_ORDER or LITTLE_ENDIAN_ORDER
/*
namespace CryptoPP
{
extern void  SHA1_HashMultipleBlocks_SHANI(
	uint32_t *state, const uint32_t *data, size_t length, CryptoPP::ByteOrder order);
}
*/


void sha1_process_x86(uint32_t state[5], uint32_t* data)
{
}


// メイン関数
int main(int argc, char* argv[])
{
    /* empty message with padding */
    uint32_t __attribute__ ((aligned (16))) data[16];
    memset(data, 0, sizeof(data));

	data[0] = 0x8000'0000;
	data[15] = 0x0000'0000;
//	data[0] = 0x30;
//	data[1] = 0x80;
//	data[63] = 8;

    /* initial state */
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    sha1_process_x86(state, data);

	std::cout << "SHA1 hash of empty message: DA39A3EE 5E6B4B0D...\n";

	std::stringstream  ss;
	ss << "state: " << std::hex << state[0] << " " << std::hex << state[1];
	
	std::cout << ss.str() << std::endl;

    return  0;
}



