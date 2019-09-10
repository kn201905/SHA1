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

//extern "C" void sha1_update_intel(unsigned int* state, const char* data, size_t num_blocks);
//extern "C" uint64_t sha1_update_intel(unsigned int* state, const char* data, size_t num_blocks);
extern "C" uint64_t sha1_update_intel(unsigned int* state, const char* data, char* pstack, uint8_t* pW_asm);

/////////////////////////////////////////////////////////////////////////////////////

uint8_t*  G_cout_16bytes(uint8_t* psrc)
{
	auto  tohex = [](uint8_t chr) -> char { return  chr < 10 ? chr + 0x30 : chr + 0x30 + 7 + 0x20; };
	char  hex[4] = { 0, 0, 0x20, 0 };
	std::string  str;

	for (int i = 0; i < 16; ++i)
	{
		uint8_t  a = *psrc++;
		hex[0] = tohex( a >> 4 );
		hex[1] = tohex( a & 0xf );
		str += hex;

		if ((i & 3) == 3) { str += ' '; }
	}
	std::cout << str << std::endl;

	return  psrc;
}

void  G_cout_ui32(uint32_t srcval)
{
	auto  tohex = [](uint8_t chr) -> char { return  chr < 10 ? chr + 0x30 : chr + 0x30 + 7 + 0x20; };
	auto  cout_bytes = [&](uint8_t byte, char* pdst) {
		*pdst++ = tohex( byte >> 4);
		*pdst = tohex( byte & 0xf );
	};
	char  hexes[] = "00 00 00 00  ";

	cout_bytes( srcval >> 24, hexes);

	srcval &= 0xff'ffff;
	cout_bytes( srcval >> 16, hexes + 3);

	srcval &= 0xffff;
	cout_bytes( srcval >> 8, hexes + 6);

	cout_bytes( srcval & 0xff, hexes + 9);

	std::cout << hexes;
}

void  G_out_ui32_4(uint32_t* psrc_ui32)
{
	for (int i = 0; i < 4; ++i)
	{ G_cout_ui32(*psrc_ui32++); }
	std::cout << std::endl;
}

void  G_out_ui32_8(uint32_t* psrc_ui32)
{
	for (int i = 0; i < 4; ++i)
	{ G_cout_ui32(*psrc_ui32++); }
	std::cout << ' ';

	for (int i = 0; i < 4; ++i)
	{ G_cout_ui32(*psrc_ui32++); }
	std::cout << std::endl;
}

void  G_out_ui8_32(uint8_t* psrc_ui8)
{
	for (int i = 0; i < 4; ++i)
	{
		uint32_t  val_ui32 = (*psrc_ui8++ << 24) + (*psrc_ui8++ << 16) + (*psrc_ui8++ << 8) + *psrc_ui8++;
		G_cout_ui32(val_ui32);
	}
	std::cout << ' ';

	for (int i = 0; i < 4; ++i)
	{
		uint32_t  val_ui32 = (*psrc_ui8++ << 24) + (*psrc_ui8++ << 16) + (*psrc_ui8++ << 8) + *psrc_ui8++;
		G_cout_ui32(val_ui32);
	}
	std::cout << std::endl;
}


/////////////////////////////////////////////////////////////////////////////////////

int main()
{
    /* initial state */
    uint32_t state[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

	char __attribute__ ((aligned (32))) data[64];
    memset(data, 0, sizeof(data));
	data[0] = 0x30;
	data[1] = 0x80;
	data[63] = 8;

	// アセンブラ内での W情報
	uint8_t __attribute__ ((aligned (32))) W_asm[320];
	memset(W_asm, 0, sizeof(W_asm));

// ====================
// テストコード
	{
		// stack コピーエリア
		char __attribute__ ((aligned (32))) stack[160];  // vmovdaq の利用のため

		uint8_t*  psrc = (uint8_t*)(stack + 72);  // 72 = 16 * 4 + 8（スタック + rax）
		for (uint8_t i = 0; i < 32; ++i)
		{ *psrc++ = i; }

		// ----------------------------------------
		// アセンブラ呼び出し
		const uint64_t  retv = sha1_update_intel(state, data, stack, W_asm);

		// ----------------------------------------
		// スタック（64 bytes）のダンプ
		std::cout << "stack ダンプ\n";
		psrc = (uint8_t*)stack;
		G_out_ui8_32(psrc);
		G_out_ui8_32(psrc + 32);
	}

	// ----------------------------------------
	// W_asm[80] のダンプ
	{
		std::cout << std::endl;
		std::cout << "W_asm[80] ダンプ" << std::endl;

		uint8_t*  pW_asm = W_asm;
		for (int i = 0; i < 10; ++i)
		{
			G_out_ui8_32(pW_asm);
			pW_asm += 32;
		}
	}
	// ----------------------------------------




	// ----------------------------------------
	// W[80] の生成
	uint32_t  W[80];
	uint8_t*  psrc_ui8 = (uint8_t*)data;
	int  w_idx = 0;
	for (int i = 0; i < 16; ++i)
	{
		const uint8_t a = *psrc_ui8++;
		const uint8_t b = *psrc_ui8++;
		const uint8_t c = *psrc_ui8++;
		const uint8_t d = *psrc_ui8++;

		W[w_idx] = (a << 24) + (b << 16) + (c << 8) + d;
		w_idx++;
	}

	for (int t = 16; t < 80; ++t)
	{
		const uint32_t  preW = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
		W[t] = (preW << 1) | (preW >> 31);
	}

	// ----------------------------------------
	// W[80] に K値を加える
/*
	for (int i = 0; i < 20; ++i) { W[i] += 0x5a82'7999; }
	for (int i = 20; i < 40; ++i) { W[i] += 0x6ed9'eba1; }
	for (int i = 40; i < 60; ++i) { W[i] += 0x8f1b'bcdc; }
	for (int i = 60; i < 80; ++i) { W[i] += 0xca62'c1d6; }
*/
	// ----------------------------------------
	// W[80] のダンプ
	std::cout << std::endl;
	std::cout << "W[80]" << std::endl;

	uint32_t*  psrc_W = W;
	for (int i = 0; i < 10; ++i)
	{
		G_out_ui32_8(psrc_W);
		psrc_W += 8;
	}
	// ----------------------------------------


	uint32_t  a, b, c, d, e, temp;
	uint32_t  h0 = 0x6745'2301;
	uint32_t  h1 = 0xEFCD'AB89;
	uint32_t  h2 = 0x98BA'DCFE;
	uint32_t  h3 = 0x1032'5476;
	uint32_t  h4 = 0xC3D2'E1F0;
	a = h0;  b = h1;  c = h2;  d = h3;  e = h4;

	auto  S5 = [](uint32_t a) -> uint32_t { return (a << 5) | (a >> 27); };
	auto  S30 = [](uint32_t a) -> uint32_t { return (a << 30) | (a >> 2); };

	int t = 0;
	for (; t < 20; ++t)
	{
		temp = S5(a) + ((b & c) | ((~b) & d)) + e + W[t] + 0x5a82'7999;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 40; ++t)
	{
		temp = S5(a) + (b ^ c ^ d) + e + W[t] + 0x6ed9'eba1;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 60; ++t)
	{
		temp = S5(a) + ((b & c) | (b & d) | (c & d)) + e + W[t] + 0x8f1b'bcdc;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 80; ++t)
	{
		temp = S5(a) + (b ^ c ^ d) + e + W[t] + 0xca62'c1d6;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	h0 += a;
	h1 += b;
	h2 += c;
	h3 += d;
	h4 += e;

	// ----------------------------------------
	// SHA1 のダンプ
	std::cout << std::endl;
	std::cout << "SHA1 値" << std::endl;
	G_cout_ui32(h0);
	G_cout_ui32(h1);
	G_cout_ui32(h2);
	G_cout_ui32(h3);
	G_cout_ui32(h4);
	std::cout << std::endl;


	// ----------------------------------------
	// W_asm と W の値の比較
	{
		bool  bsame = true;
		uint32_t*  pW_asm = (uint32_t*)W_asm;
		for (int i = 0; i < 80; ++i)
		{ if (*pW_asm++ != W[i]) { bsame = false; } }

		if (bsame)
		{ std::cout << "W[] == W_asm[] -> OK!!" << std::endl; }
		else
		{ std::cout << "W[] != W_asm[] -> fail.." << std::endl; }
	}

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
