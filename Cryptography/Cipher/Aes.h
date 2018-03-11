#pragma once

#include <iostream>
#include <iomanip>
using namespace std;


#define uchar uint8_t

class AES {

public:

	AES(uchar *key, int version = 128);

	void showInformation();
	
	//Use sub table
	void encrypt(uchar data[16]);	
	void decrypt(uchar data[16]);

	void slowEncrypt(uchar data[16]);

	~AES();
	
private:

	//Version 128 de l'AES
	int version = 128;
	int roundNumber = 10;
	int keySize = 16;

	uchar *expandedKey;

	void addRoundKey(uchar* state, uchar* keyRound);

	static const uchar sbox[256];
	static const uchar sboxinv[256];

	void subByte(uchar* state);

	void subByteInv(uchar* state);


	void shiftRows(uchar* state);

	void shiftRowsInv(uchar* state);


	void mixColumns(uchar* state);

	void mixColumnsInv(uchar* state);

	//Galois Multiplication lookup tables
	//Contient le résultats de la multiplication de [i] par 2,3,9,11,13,14
	//utilisation i = ix13[i]
	static const uchar ix2[256];

	static const uchar ix3[256];

	static const uchar ix9[256];

	static const uchar ix11[256];

	static const uchar ix13[256];

	static const uchar ix14[256];

	//Permet de réaliser la multiplication, et donc de générer les tables ix2, ix3, ix9, ix11...
	uchar mulGaloiField(uchar a, uchar b);
	
	static uint32_t table[4][256];
	uint32_t tableInv[4][256];

	//Génère 4 tables de 256 entrées, de 32 bits permettant de fusionner les fonctions ShiftRows, SubByte et MixColmun en une seule...
	void generateBigTable();
	void generateBigTableInv();

	//keySchedule
	void rotate(uchar state[4]);
	static uchar rcon[256];
	void schedule_core(uchar in[4], int i);
	void keySchedule(uchar *key);


};






