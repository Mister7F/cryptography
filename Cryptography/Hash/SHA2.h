#pragma once

#include <vector>

using namespace std;

namespace SHA256 {

	//Fonction de base du SHA-256
	#define Ch(x, y, z)		((x & y) ^ ( (~x) & z))
	#define Maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
	#define SHR(x, n)		(x >> n)

	#define ROT32(x, n)		((x >> n) | (x << (32-n)))
	#define Summ0(x)		(ROT32(x, 2) ^ ROT32(x, 13) ^ ROT32(x, 22))
	#define Summ1(x)		(ROT32(x, 6) ^ ROT32(x, 11) ^ ROT32(x, 25))

	#define Sigm0(x)		(ROT32(x, 7) ^ ROT32(x, 18) ^ SHR(x, 3))
	#define Sigm1(x)		(ROT32(x, 17) ^ ROT32(x, 19) ^ SHR(x, 10))

	void complete(vector<uint8_t> &data) {

		uint64_t l = data.size() * 8;

		//Ajout d'un bit "1", suivis de bits "0" pour compléter l'octet
		data.push_back(0b10000000);

		//Ajout d'octet nul, afin que la taille finale soit un multiple de 64
		while (data.size() % 64 != 56)
			data.push_back(0);

		//On écris le nombre de bit de data, en big endian, sur 64 bits
		data.push_back(l >> 56);
		data.push_back(l >> 48);
		data.push_back(l >> 40);
		data.push_back(l >> 32);
		data.push_back(l >> 24);
		data.push_back(l >> 16);
		data.push_back(l >> 8);
		data.push_back(l >> 0);
	}

	const uint32_t K[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};
	
	vector<uint8_t> SHA_256(vector<uint8_t> data_plain) {

		complete(data_plain);

		//Initialisation du vecteur H
		uint32_t H[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
		
		//Mot de 32 bits
		uint32_t *data = (uint32_t *)data_plain.data();

		//Nombre de mots de 32 bits (4 octets)
		unsigned int N = data_plain.size() / 4.;

		uint32_t W[64];

		uint32_t a, b, c, d, e, f, g, h;

		uint32_t T1, T2;

		//On traite chaque bloc de 512 bits (16x32 bits ou 8x64 octets)
		for (int i = 0; i < N; i += 16) {

			//Initialisation du vecteur W
			for (int t = 0; t < 16; t++)
				W[t] = _byteswap_ulong(data[t + i]);	//Convertit en big endian

			for (int t = 16; t < 64; t++)
				W[t] = Sigm1(W[t - 2]) + W[t - 7] + Sigm0(W[t - 15]) + W[t - 16];
			
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];

			for (int t = 0; t < 64; t++) {
				T1 = h + Summ1(e) + Ch(e, f, g) + K[t] + W[t];
				T2 = Summ0(a) + Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;			
		}

		//Création du vecteur de retour (convertit les mots de 32 bits en suite d'octet...)
		vector<uint8_t> ret(32, 0);
		for (int i = 0; i < 32; i++)
			ret[i] = H[i / 4] >> (24 - (8 * i));

		return ret;
	}	
}

namespace SHA512 {
	//Fonction de base du SHA-512
	#define Ch(x, y, z)		((x & y) ^ ( (~x) & z))
	#define Maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
	#define SHR(x, n)		(x >> n)

	#define ROT64(x, n)		((x >> n) | (x << (64-n)))
	#define Summ0(x)		(ROT64(x, 28) ^ ROT64(x, 34) ^ ROT64(x, 39))
	#define Summ1(x)		(ROT64(x, 14) ^ ROT64(x, 18) ^ ROT64(x, 41))

	#define Sigm0(x)		(ROT64(x, 1) ^ ROT64(x, 8) ^ SHR(x, 7))
	#define Sigm1(x)		(ROT64(x, 19) ^ ROT64(x, 61) ^ SHR(x, 6))

	void complete(vector<uint8_t> &data) {		
		//Normalement la taille en bit doit être stockée sur 128 bits..., mais size() retourne 32 ou 64 bits...
		//Cela changerai cette fonction

		uint64_t l = data.size() * 8;
		
		data.push_back(0b10000000);
		
		while (data.size() % 128 != 120)
			data.push_back(0);
		
		data.push_back(l >> 56);
		data.push_back(l >> 48);
		data.push_back(l >> 40);
		data.push_back(l >> 32);
		data.push_back(l >> 24);
		data.push_back(l >> 16);
		data.push_back(l >> 8);
		data.push_back(l >> 0);
	}
	
	const uint64_t K[80] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd,	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019,	0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe,	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1,	0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3,	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483,	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210,	0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725,	0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926,	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8,	0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001,	0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910,	0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53,	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60,	0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9,	0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207,	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6,	0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493,	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	vector<uint8_t> SHA_512(vector<uint8_t> data_plain) {

		complete(data_plain);

		//Initialisation du vecteur H
		uint64_t H[8] = {	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
							0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
		
		//Mot de 64 bits
		uint64_t *data = (uint64_t *)data_plain.data();

		//Nombre de mots de 64 bits (8 octets)
		unsigned int N = data_plain.size() / 8.;

		uint64_t W[80];

		uint64_t a, b, c, d, e, f, g, h;

		uint64_t T1, T2;

		//On traite chaque bloc de 1024 bits (16x64 bits)
		for (int i = 0; i < N; i += 16) {

			//Initialisation du vecteur W
			for (int t = 0; t < 16; t++)
				W[t] = _byteswap_uint64(data[t + i]);	//Convertit en big endian

			for (int t = 16; t < 80; t++)
				W[t] = Sigm1(W[t - 2]) + W[t - 7] + Sigm0(W[t - 15]) + W[t - 16];
			
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];

			for (int t = 0; t < 80; t++) {
				T1 = h + Summ1(e) + Ch(e, f, g) + K[t] + W[t];
				T2 = Summ0(a) + Maj(a, b, c);
				h = g;
				g = f;
				f = e;
				e = d + T1;
				d = c;
				c = b;
				b = a;
				a = T1 + T2;
			}

			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
			H[5] += f;
			H[6] += g;
			H[7] += h;			
		}
		
		//Création du vecteur de retour (convertit les mots de 64 bits en suite d'octet...)
		vector<uint8_t> ret(64, 0);
		for (int i = 0; i < 64; i++)
			ret[i] = H[i / 8] >> (56 - (8 * (i % 8)));

		return ret;
	}	
}