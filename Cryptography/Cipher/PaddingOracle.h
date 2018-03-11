#pragma once

#include <iostream>
#include <vector>
#include <array>
#include <functional>
using namespace std;

#define uchar uint8_t
#define uint unsigned int

void addPaddingPKCS7(vector<uchar> &data, uint blockSize = 16) {
	uint missingSize = blockSize - (data.size() % blockSize);

	for (int i = 0; i < missingSize; i++)
		data.push_back(missingSize);
}

bool removePaddingPKCS7(vector<uchar> &data, uint blockSize = 16) {		//Retourne false si le padding est incorrect
	if (data.size() % blockSize != 0)
		return false;

	uint missingSize = data.back();

	for (int i = 1; i <= missingSize; i++) {
		if (data[data.size() - missingSize] != missingSize)
			return false;
	}
	data.resize(data.size() - missingSize);
	return true;
}

/* Réalise l'attaque "Padding Oracle"
 *		- encrypted: octets chiffrés, comprend l'IV en début si on le connait
 *		- isPaddingValid: fonction retournant "true" si le padding du bloc passé en paramètre est valide une fois déchiffré
*/
vector<uchar> oraclePaddingCBC(vector<uchar> encrypted,
	function<bool(vector<uchar>)> isPaddingValid,
	uint blockSize = 16) {

	if (encrypted.size() % blockSize)
		throw "Error, encrypted size...";

	vector<uchar> plain(encrypted.size(), 0);

	vector<uchar> payload(blockSize * 2, 0);

	for (int iBlock = encrypted.size() - blockSize; iBlock >= blockSize; iBlock -= blockSize) {

		payload = vector<uchar>(blockSize, 0);

		payload.insert(payload.end(), &encrypted[iBlock], &encrypted[iBlock] + blockSize);

		for (int i = blockSize - 1; i >= 0; i--) {

			for (int chr = 0; chr < 256; chr++) {
				payload[i] = chr;
				if (isPaddingValid(payload)) break;
			}

			plain[iBlock + i] = payload[i] ^ (blockSize - i) ^ encrypted[iBlock - blockSize + i];

			// On modifie notre payload...
			for (int j = i; j < blockSize; j++)
				payload[j] = (blockSize - i + 1) ^ encrypted[iBlock - blockSize + j] ^ plain[iBlock + j];
		}
	}

	return plain;
}

