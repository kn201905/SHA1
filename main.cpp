#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <sstream>

//extern "C" uint64_t sha1_update_intel(unsigned int* o_pHash, const char* i_pBuffer);
extern "C" uint64_t sha1_update_intel(unsigned int* o_pHash, const char* i_pBuffer, uint8_t* o_pW_asm);

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

// ハッシュ値表示用
void  G_out_ui32_5(uint32_t* psrc_ui32)
{
	for (int i = 0; i < 5; ++i)
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
    uint32_t  hash[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

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

	// ----------------------------------------
	// アセンブラルーチン呼び出し
	const uint64_t  retv = sha1_update_intel(hash, data, W_asm);


	// ----------------------------------------
	// hash値のダンプ
	std::cout << std::endl;
	std::cout << "ハッシュ値 ダンプ" << std::endl;
	G_out_ui32_5(hash);


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

#if false
	// ----------------------------------------
	// W[80] に K値を加える
	for (int i = 0; i < 20; ++i) { W[i] += 0x5a82'7999; }
	for (int i = 20; i < 40; ++i) { W[i] += 0x6ed9'eba1; }
	for (int i = 40; i < 60; ++i) { W[i] += 0x8f1b'bcdc; }
	for (int i = 60; i < 80; ++i) { W[i] += 0xca62'c1d6; }

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
#endif

	// ----------------------------------------
	// ハッシュ算出
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
		W[t] = temp;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 40; ++t)
	{
		temp = S5(a) + (b ^ c ^ d) + e + W[t] + 0x6ed9'eba1;
		W[t] = temp;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 60; ++t)
	{
		temp = S5(a) + ((b & c) | (b & d) | (c & d)) + e + W[t] + 0x8f1b'bcdc;
		W[t] = temp;
		e = d;
		d = c;
		c = S30(b);
		b = a;
		a = temp;
	}

	for (; t < 80; ++t)
	{
		temp = S5(a) + (b ^ c ^ d) + e + W[t] + 0xca62'c1d6;
		W[t] = temp;
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

#if true
	// ----------------------------------------
	// W[80] のダンプ（<- ここでは temp に書き換わっている）
	std::cout << std::endl;
	std::cout << "W[80]（<- temp）" << std::endl;

	uint32_t*  psrc_W = W;
	for (int i = 0; i < 10; ++i)
	{
		G_out_ui32_8(psrc_W);
		psrc_W += 8;
	}
	std::cout << std::endl;
#endif

	// ----------------------------------------
	// W_asm と W の値の比較
	{
		bool  bsame = true;
		uint32_t*  pW_asm = (uint32_t*)W_asm;
		for (int i = 0; i < 80; ++i)
		{ if (*pW_asm++ != W[i]) { bsame = false; } }

		if (bsame)
		{ std::cout << "W[] == W_asm[] -> OK!!\n" << std::endl; }
		else
		{ std::cout << "W[] != W_asm[] -> fail..\n" << std::endl; }
	}

    return  0;
}
