#pragma once

#include <vector>

using namespace std;

namespace HashLengthExtension {

	//Fonction de base du SHA-256
	#define Ch(x, y, z)		((x & y) ^ ( (~x) & z))
	#define Maj(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
	#define SHR(x, n)		(x >> n)

	#define ROT32(x, n)		((x >> n) | (x << (32-n)))
	#define Summ0(x)		(ROT32(x, 2) ^ ROT32(x, 13) ^ ROT32(x, 22))
	#define Summ1(x)		(ROT32(x, 6) ^ ROT32(x, 11) ^ ROT32(x, 25))

	#define Sigm0(x)		(ROT32(x, 7) ^ ROT32(x, 18) ^ SHR(x, 3))
	#define Sigm1(x)		(ROT32(x, 17) ^ ROT32(x, 19) ^ SHR(x, 10))
	
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


	void padding(vector<uint8_t> &data, uint64_t totalSize) {

		uint64_t l = totalSize * 8;

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



	vector<uint8_t> addHashLength(vector<uint8_t> initialHash, uint64_t initialDataSize, vector<uint8_t> addedData) {
		
		//La hash doit être un SHA-256...
		if (initialHash.size() != 32)
			throw "Invalid initial hash size";



		/* La taille des données que nous allons hacher correspond
		 *		- Taille des données initiales
		 *		- Taille du padding ajouté lors du 1er hach
		 *		- Taille des données ajoutées							*/
		uint64_t newDataSize = ((initialDataSize + 64)/64)*64 + addedData.size();


		//Ajoute le padding aux données ajoutées
		//Cependant, la taille des données comprend les données initiales, le padding initial et la taille des données ajoutées
		padding(addedData, newDataSize);



		// Nous initialisons notre vacteur H grâce au hash initial
		uint32_t H[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
		
		for (int i = 0; i < 32; i++)
			H[i / 4] ^= initialHash[i] << (24 - (8 * i));

		

		// Ensuite, nous hachons cela, naturellement...





		//Mot de 32 bits
		uint32_t *data = (uint32_t *)addedData.data();

		//Nombre de mots de 32 bits (4 octets)
		unsigned int N = addedData.size() / 4.;

		uint32_t W[64];

		uint32_t a, b, c, d, e, f, g, h;

		uint32_t T1, T2;

		//On traite chaque bloc de 512 bits (16x32 bits)
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

namespace HashLengthExtension_SHA1 {

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


	void padding(vector<uint8_t> &data, uint64_t totalSize) {

		uint64_t l = totalSize * 8;

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

	vector<uint8_t> addHashLength(vector<uint8_t> initialHash, uint64_t initialDataSize, vector<uint8_t> addedData) {

		//La hash doit être un SHA-1...
		if (initialHash.size() != 20)
			throw "Invalid initial hash size";



		/* La taille des données que nous allons hacher correspond
		*		- Taille des données initiales
		*		- Taille du padding ajouté lors du 1er hach
		*		- Taille des données ajoutées							*/
		uint64_t newDataSize = ((initialDataSize + 64) / 64) * 64 + addedData.size();


		//Ajoute le padding aux données ajoutées
		//Cependant, la taille des données comprend les données initiales, le padding initial et la taille des données ajoutées
		padding(addedData, newDataSize);



		// Nous initialisons notre vacteur H grâce au hash initial
		uint32_t H[5] = { 0, 0, 0, 0, 0 };

		for (int i = 0; i < 20; i++)
			H[i / 4] ^= initialHash[i] << (24 - (8 * i));






		//Mot de 32 bits
		uint32_t *data = (uint32_t *)addedData.data();

		//Nombre de mots de 32 bits (4 octets)
		unsigned int N = addedData.size() / 4.;

		uint32_t W[80];

		uint32_t a, b, c, d, e, f, k;

		uint32_t T;

		//On traite chaque bloc de 512 bits (16x32 bits)
		for (int i = 0; i < N; i += 16) {
			//Initialisation du vecteur W
			for (int t = 0; t < 16; t++)
				W[t] = _byteswap_ulong(data[t + i]);	//Convertit en big endian

			for (int t = 16; t < 80; t++)
				W[t] = ROTL_32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);


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