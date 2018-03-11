#pragma once

#include "HMAC.h"
#include "SHA1.h"

#include <time.h>
#include <iomanip>
#include <string>

using namespace std;

#define HEX_2	setfill('0') << setw(2) << hex

string TOTP(vector<uint8_t> secretKey) {
	
	uint64_t t = (time(0)+1) / 30;
	
	vector<uint8_t> encodedTime;

	encodedTime.push_back(t >> 56);
	encodedTime.push_back(t >> 48);
	encodedTime.push_back(t >> 40);
	encodedTime.push_back(t >> 32);
	encodedTime.push_back(t >> 24);
	encodedTime.push_back(t >> 16);
	encodedTime.push_back(t >> 8);
	encodedTime.push_back(t);
	
	vector<uint8_t> hmac = HMAC(encodedTime, SHA1::SHA_1, 64, secretKey);


	int offset = (hmac[hmac.size() - 1] & 0x0f);
	
	int binary =
		((hmac[offset] & 0x7f) << 24)
		| ((hmac[offset + 1]) << 16)
		| ((hmac[offset + 2]) << 8)
		| (hmac[offset + 3]);

	
	binary %= 1000000;



	string r = to_string(binary);

	while (r.size() != 6)
		r.insert(0, "0");
	

	return r;
}
