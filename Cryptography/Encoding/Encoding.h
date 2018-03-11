#pragma once

#include <string>
#include <vector>

using namespace std;

string hex(vector<uint8_t> bytes) {

	static const string not = "0123456789abcdef";

	string hex;
	hex.resize(bytes.size() * 2);

	int i = 0;
	for (uint8_t byte : bytes) {
		hex[i++] = not[byte / 16];
		hex[i++] = not[byte % 16];
	}

	return hex;
}

//A refaire + proprement...
uint8_t letterToHex(uint8_t Letter) {

	if (Letter >= '0' && Letter <= '9') {
		return Letter - '0';
	}
	else if (Letter >= 'a' && Letter <= 'f') {
		return Letter - 'a' + 10;
	}
	else if (Letter >= 'A' && Letter <= 'F') {
		return Letter - 'A' + 10;
	}
	return 0;
}

vector<uint8_t> fromHex(string hex) {

	vector<uint8_t> data(hex.size() / 2, 0);

	for (int i = 0; i < data.size(); i++) {
		data[i] = letterToHex(hex[i * 2]) * 16 + letterToHex(hex[i * 2 + 1]);
	}

	return data;
}


string bin(vector<uint8_t> bytes) {

	string bin;
	bin.resize(bytes.size() * 8);

	int i = 0;
	for (uint8_t byte : bytes)
		for (int j = 0b10000000; j; j >>= 1)
			bin[i++] = ((byte & j) != 0) + '0';

	return bin;
}

string base64(vector<uint8_t> bytes) {

	string not = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	string b64((bytes.size() + 2) / 3 * 4, '=');

	//Une lettre par mot de 6 bits
	int j = 0;

	for (int i = 0; i < bytes.size() * 8; i += 6)
		b64[j++] = not[((uint16_t)((((bytes[i / 8]) << 8) | (((i + 6) / 8) < bytes.size() ? (bytes[((i + 6) / 8)]) : 0)) << (i % 8))) >> 10];

	return b64;
}

string base32(vector<uint8_t> bytes) {

	string not = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	string b32((bytes.size() + 2) / 5 * 8, '=');

	//Une lettre par mot de 5 bits
	int j = 0;

	for (int i = 0; i < bytes.size() * 8; i += 5)
		b32[j++] = not[((uint16_t)((((bytes[i / 8]) << 8) | (((i + 5) / 8) < bytes.size() ? (bytes[((i + 5) / 8)]) : 0)) << (i % 8))) >> 11];

	return b32;
}



