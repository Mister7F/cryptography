#pragma once

#include <iostream>
#include <vector>

using namespace std;

namespace SHA1 {

	#define ROTL_32(x, n)		( ((x) << (n)) | ((x) >> (32-(n))))


	#define Ch(x, y, z)			(((x) & (y)) | ( (~(x)) & (z)))
	#define Parity(x, y, z)		((x) ^ (y) ^ (z))
	#define Maj(x, y, z)		(((x) & (y)) | ((x) & (z)) | ((y) & (z)))

	uint32_t ft(uint32_t a, uint32_t b, uint32_t c, int t) {
		if (t < 20)
			return Ch(a, b, c);
		if (t < 40)
			return Parity(a, b, c);
		if (t < 60)
			return Maj(a, b, c);

		return Parity(a, b, c);
	}

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
	
	const uint32_t K[80] = {
		0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,
		0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,0x5a827999,
		
		0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,
		0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,


		0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,
		0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,
		
		0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,
		0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
	};

	vector<uint8_t> SHA_1(vector<uint8_t> data_plain) {

		complete(data_plain);

		//Initialisation du vecteur H
		uint32_t H[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

		//Mot de 32 bits
		uint32_t *data = (uint32_t *)data_plain.data();

		//Nombre de mots de 32 bits (4 octets)
		unsigned int N = data_plain.size() / 4.;

		uint32_t W[80];

		uint32_t a, b, c, d, e, f, k;

		uint32_t T;

		//On traite chaque bloc de 512 bits (16x32 bits)
		for (int i = 0; i < N; i += 16) {
			//Initialisation du vecteur W
			for (int t = 0; t < 16; t++)
				W[t] = _byteswap_ulong(data[t + i]);	//Convertit en big endian

			for (int t = 16; t < 80; t++) 
				W[t] = ROTL_32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16] , 1);
			

			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];

			for (int t = 0; t < 80; t++) {

				T = ROTL_32(a, 5) + ft(b, c, d, t) + e + K[t] + W[t];

				e = d;
				d = c;
				c = ROTL_32(b, 30);
				b = a;
				a = T;
			}

			H[0] += a;
			H[1] += b;
			H[2] += c;
			H[3] += d;
			H[4] += e;
		}
			
		//Création du vecteur de retour (convertit les mots de 64 bits en suite d'octet...)
		vector<uint8_t> ret(20, 0);
		for (int i = 0; i < 20; i++)
			ret[i] = H[i / 4] >> (24 - (8 * (i % 4)));

		return ret;
	}
}