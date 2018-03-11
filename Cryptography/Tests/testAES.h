#pragma
#include <iostream>
using namespace std;

#include "..\Cipher\Aes.h"
#include "..\Encoding\Encoding.h"


void testAES() {

	cout << endl << "AES 128" << endl;

	uchar key[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	cout << "Key" << endl;
	cout << hex(vector<uchar>(key, key + 16)) << endl;

	AES aes128(key, 128);
	
	uchar data[] = { 0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 5, 6, 7 };

	cout << "Initial data..." << endl;
	cout << hex(vector<uchar>(data, data+16)) << endl;

	aes128.encrypt(data);


	cout << "AES 128 encrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;

	cout << "Expected" << endl;
	cout << "9cd2fb854edc9878179abd53b0cb01c1" << endl;

	aes128.decrypt(data);
	cout << "Decrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;






	cout << endl << "AES 192" << endl;

	uchar key192[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23 };
	cout << "Key" << endl;
	cout << hex(vector<uchar>(key192, key192 + 24)) << endl;

	AES aes192(key192, 192);
	
	cout << "Initial data..." << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;

	aes192.encrypt(data);


	cout << "AES 192 encrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;

	cout << "Expected" << endl;
	cout << "022247982d32563f8165a5a94a7b432b" << endl;

	aes192.decrypt(data);
	cout << "Decrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;





	cout << endl << "AES 256" << endl;

	uchar key256[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	cout << "Key" << endl;
	cout << hex(vector<uchar>(key256, key256 + 32)) << endl;

	AES aes256(key256, 256);
	
	cout << "Initial data..." << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;

	aes256.encrypt(data);


	cout << "AES 256 encrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;

	cout << "Expected" << endl;
	cout << "e0f52cac8d79d8a92a9a2cc432a11d7a" << endl;

	aes256.decrypt(data);
	cout << "Decrypted" << endl;
	cout << hex(vector<uchar>(data, data + 16)) << endl;
}