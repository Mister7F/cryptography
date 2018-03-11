#pragma once

#include "..\Cipher\PaddingOracle.h"
#include "..\Cipher\Aes.h"

/* Tente de déchiffrer, retourne true si le padding est valide */
bool decryptCBC(vector<uchar> &data, uint blockSize = 16) {

	if (data.size() % blockSize != 0 || data.size() <= blockSize)
		return false;

	// Déchiffrement en mode CBC
	uint8_t key[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, };
	AES aes(key, 256);

	for (int i = data.size() - blockSize; i >= blockSize; i -= blockSize) {

		aes.decrypt(&data[i]);

		for (int j = 0; j < blockSize; j++)
			data[i + j] ^= data[i + j - blockSize];
	}

	// On check le padding et on l'enlève
	uint missingSize = data.back();

	for (int i = 1; i <= missingSize; i++) {
		if (data[data.size() - i] != missingSize)
			return false;
	}
	data = vector<uchar>(data.begin() + blockSize, data.end() - missingSize);
	return true;
}

vector<uchar> encryptCBC(vector<uchar> &data, vector<uchar> IV = vector<uchar>(16, 0), uint blockSize = 16) {

	uchar key[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, };
	AES aes(key, 256);

	data.insert(data.begin(), IV.begin(), IV.end());

	addPaddingPKCS7(data);
	
	/* CBC cipher mode */
	for (int i = blockSize; i < data.size(); i += blockSize) {
		for (int j = 0; j < blockSize; j++) {
			data[i + j] ^= data[i + j - blockSize];
		}
		aes.encrypt(&data[i]);
	}
	return data;
}



/* Simule la réponse du serveur */
bool oracleCheckPadding(vector<uchar> encryptedData) {
	uint blockSize = 16;

	if (encryptedData.size() % blockSize != 0 || encryptedData.size() <= blockSize)
		return false;

	// Déchiffrement en mode CBC
	uint8_t key[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, };
	AES aes(key, 256);

	for (int i = encryptedData.size() - blockSize; i >= blockSize; i -= blockSize) {

		aes.decrypt(&encryptedData[i]);

		for (int j = 0; j < blockSize; j++)
			encryptedData[i + j] ^= encryptedData[i + j - blockSize];
	}

	// On check le padding et on l'enlève
	uint missingSize = encryptedData.back();

	if (missingSize == 0)
		return false;

	for (int i = 1; i <= missingSize; i++) {
		if (encryptedData[encryptedData.size() - i] != missingSize)
			return false;
	}

	return true;
}


void testPaddingOracle() {
	string str_data = "Newbie contest !";
	vector<uchar> data(str_data.size());
	for (int i = 0; i < str_data.size(); i++)
		data[i] = str_data[i];

	addPaddingPKCS7(data);

	cout << "Initial data with padding" << endl;
	cout << hex(data) << endl;

	cout << "Remove padding: " << removePaddingPKCS7(data) << endl;
	cout << hex(data) << endl;


	encryptCBC(data);
	cout << "Encrypted data" << endl;
	cout << hex(data) << endl;

	decryptCBC(data);
	cout << "Decrypted data" << endl;
	cout << hex(data) << endl;

	cout << "Attaque padding oracle..." << endl;
	system("pause");


	string encrypted_str = "000000000000000000000000000000001b052337065a51ef8509d9951a3972f3606cf6e1af05990570fc775e05e04879";

	vector<uchar> encryptedData = fromHex(encrypted_str);


	vector<uchar> decrypted = oraclePaddingCBC(encryptedData, oracleCheckPadding);

	cout << hex(decrypted) << endl;

	for (int i = 16; i < decrypted.size() - decrypted.back(); i++)
		cout << decrypted[i];
	cout << endl;
}