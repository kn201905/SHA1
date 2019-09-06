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

extern "C" void sha1_update_intel(unsigned int* state, const char* data);

/*
void sha1_process_x86(uint32_t state[5], uint32_t* data)
{
}
*/

// メイン関数
int main()
{
#if false
	uint32_t __attribute__ ((aligned (16))) data[16];
    memset(data, 0, sizeof(data));

	data[0] = 0x8000'0000;
	data[15] = 0x0000'0000;
//	data[0] = 0x30;
//	data[1] = 0x80;
//	data[63] = 8;
#endif
    /* initial state */
    uint32_t state[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

//	sha1_process_x86(state, data);

	char __attribute__ ((aligned (16))) data[64];
    memset(data, 0, sizeof(data));
	data[0] = 0x80;

	sha1_update_intel(state, data);


	std::stringstream  ss;
	ss << "state: " << std::hex << state[0];
	std::cout << ss.str() << std::endl;


#if false
	std::cout << "SHA1 hash of empty message: DA39A3EE 5E6B4B0D...\n";

	std::stringstream  ss;
	ss << "state: " << std::hex << state[0] << " " << std::hex << state[1];
	
	std::cout << ss.str() << std::endl;
#endif
    return  0;
}



#if false

template <unsigned int R, class T> inline T rotlConstant(T x)
{
	// Portable rotate that reduces to single instruction...
	// http://gcc.gnu.org/bugzilla/show_bug.cgi?id=57157,
	// http://software.intel.com/en-us/forums/topic/580884
	// and http://llvm.org/bugs/show_bug.cgi?id=24226
	CRYPTOPP_CONSTANT(THIS_SIZE = sizeof(T)*8)
	CRYPTOPP_CONSTANT(MASK = THIS_SIZE-1)
	CRYPTOPP_ASSERT(R < THIS_SIZE);
	return T((x<<R)|(x>>(-R&MASK)));
}

#define blk0(i) (W[i] = data[i])
#define blk1(i) (W[i&15] = rotlConstant<1>(W[(i+13)&15]^W[(i+8)&15]^W[(i+2)&15]^W[i&15]))

#define f1(x,y,z) (z^(x&(y^z)))
#define f2(x,y,z) (x^y^z)
#define f3(x,y,z) ((x&y)|(z&(x|y)))
#define f4(x,y,z) (x^y^z)

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=f1(w,x,y)+blk0(i)+0x5A827999+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R1(v,w,x,y,z,i) z+=f1(w,x,y)+blk1(i)+0x5A827999+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R2(v,w,x,y,z,i) z+=f2(w,x,y)+blk1(i)+0x6ED9EBA1+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R3(v,w,x,y,z,i) z+=f3(w,x,y)+blk1(i)+0x8F1BBCDC+rotlConstant<5>(v);w=rotlConstant<30>(w);
#define R4(v,w,x,y,z,i) z+=f4(w,x,y)+blk1(i)+0xCA62C1D6+rotlConstant<5>(v);w=rotlConstant<30>(w);

void SHA1_HashBlock_CXX(uint32_t *state, const uint32_t *data)
{
    uint32_t W[16];
    /* Copy context->state[] to working vars */
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

#endif
