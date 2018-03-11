# Padding oracle

## Introduction

### Padding PKCS 7
Lorsque nous avons un chiffrement par bloc (AES par exemple), une question se pose lorsque les données à chiffrer ne sont pas un multiple de la taille d'un bloc. 
Le padding répond à cette question, nous allons remplir les données avec des octets...
S'il nous manque 3 octets sur le dernier bloc pour le compléter, nous le remplissons par 0x03... S'il en manque 14, nous le remplissons par 0x0E (14). Si nos données font exactement la taille d'un bloc, nous ajoutons un bloc supplémentaire, qui sera alors composé uniquement de padding.
La taille d'un bloc AES (128, 192, 256) est de 16 octets...
Voici quelques exemples de padding
Donnée| Taille des données | Octets manquants| Bloc avec padding
-|-|-|-
"Mister7F" |8|0x08 - 8 | 4d697374657237460808080808080808
"Great Mister7F"|14|0x02- 2|4772656174204d697374657237460202
"Newbie contest !" | 16 | 0x10 - 16| 4e657762696520636f6e74657374202110101010101010101010101010101010
Voici un exemple d'implémentation du padding PKCS-7 en C++.
```C++
void addPaddingPKCS7(vector<uchar> &data, uint blockSize = 16) {
	uint missingSize = blockSize - (data.size() % blockSize);
 
	for (int i = 0; i < missingSize; i++)
		data.push_back(missingSize);
}
 
bool removePaddingPKCS7(vector<uchar> &data, uint blockSize = 16) {		
	//Retourne false si le padding est incorrect
	if (data.size() % blockSize != 0)
		return false;
 
	uint missingSize = data.back();
 
	for (int i = 1; i <= missingSize; i++) {
		if (data\[data.size() - missingSize\] != missingSize)
			return false;
	}
	data.resize(data.size() - missingSize);
	return true;
}
```
### Chiffrement CBC
Dans le mode d'opération CBC, chaque bloc clair est XORé avec le boc chiffré précédent, avant d'être lui-même chiffré. Pour le tout premier bloc, nous utilisons un vecteur d'initialisation (IV).
```
M1 M2 M3    -- CIPHER -->   C1 C2 C3
C1 = encrypt(M1 ^ IV)
C2 = encrypt(M2 ^ C1)
C3 = encrypt(M3 ^ C2)
```
```C++
vector<uchar> encryptCBC(vector<uchar> &data, vector<uchar> IV = vector<uchar>(16, 0), uint blockSize = 16) { 
	addPaddingPKCS7(data);	
	/* CBC cipher mode */
	for (int i = blockSize; i < data.size(); i += blockSize) {
		for (int j = 0; j < blockSize; j++) {
			data[i + j] ^= data[i + j - blockSize];
		}
		encrypt(&data[i]);
	}
	return data;
}
```
Pour déchiffrer, il suffit de faire le processus inverse.
```
M3 = decrypt(C3) ^ C2
```
```C++
bool decryptCBC(vector<uchar> &data, uint blockSize = 16) {
	for (int i = data.size() - blockSize; i >= blockSize; i -= blockSize) { 
		decrypt(&data[i]);
 
		for (int j = 0; j < blockSize; j++)
			data[i + j] ^= data[i + j - blockSize];
	}
	 return isPaddingValid(data);
}
```
## Attaque
### Situation
Nous avons des données chiffrées, et nous souhaitons les décrypter.  Nous pouvons les envoyer à un serveur, celui-ci les déchiffrera, et nous dira si oui ou non, le padding  est correct.
Dans cette situation, nous sommes en mesure d'effectuer l'attaque "padding oracle".
### Principe
Nous allons commencer par le dernier bloc. Nous allons injecter un bloc avant ce dernier. Nous appellerons ce bloc 'X'. Nous le contrôlons. 
```
Payload = concat(X, C3)
```
Imaginons maintenant le serveur qui déchiffrera notre bloc et vérifiera son padding. Il va donc déchiffrer M3 et vérifier que son padding est correct. Le bloc déchiffré sera différent du bloc original, cependant nous saurons si son padding est correct, donc s'il se termine par "0x01" ou "0x02 0x02",...
Ecrivons quelques équations
```
Chiffrement
C3 = encrypt(M3 xor C2)

Déchiffrement de notre payload
M'3 = decrypt(C3) xor X

Au final, nous avons
M'3 = decrypt(encrypt(M3 xor C2)) xor X
M'3 = M3 xor C2 xor X
```
Donc, si nous brut-forçons le dernier octet du bloc X, jusqu'à obtenir le message "Padding correct" du serveur, nous savons que "M'3" vaut 0x01... (Il y a une chance que M'3 se termine par 0x0202, voir même 0x030303, mais cela est peu probable, si c'est le cas, il faudra alors continuer le brutforce, et nous trouverons une valeur qui fera en sorte d'avoir un padding de 0x01).
Avec cette information, nous pouvons déchiffrer le dernier octet du bloc C3.
```
M3[last] = M'3[last] xor C2[last] xor X[last]
	- M'3[last], vaut 0x01 car le padding est valide
	- C2[last] est connu, il s'agit du bloc chiffré précédent
	- X[last] est connu, nous l'avons brutforcer
```
Sur base de cela, nous pouvons calculer X tel que M'3 se termine par "0x02" et brutforcer 'lavant dernier octet de X pour avoir le message "padding valide", nous saurons alors que M'3 se termine par 0x0202... Et ainsi de suite.

Pour déchiffrer le 1er bloc, il faut donc connaître l'IV, si on ne l'a pas, on peut toujours essayer avec des octets nulls.
```C++
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
```
