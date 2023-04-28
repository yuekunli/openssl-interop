#include "cryptlib.h"
#include "secblock.h"
#include "osrng.h"
#include "files.h"
#include "cmac.h"
#include "aes.h"
#include "hex.h"

using namespace CryptoPP;

#include <iostream>
#include <string>

using namespace std;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	string mac, plain = "CMAC Test";

	HexEncoder encoder(new FileSink(cout));

	cout << "key: ";
	encoder.Put(key, key.size());
	encoder.MessageEnd();
	cout << endl;

	cout << "plain text: ";
	encoder.Put((const byte*)plain.data(), plain.size());
	encoder.MessageEnd();
	cout << endl;

	CMAC<AES> cmac(key.data(), key.size());
	cmac.Update((const byte*)plain.data(), plain.size());
	mac.resize(cmac.DigestSize());
	cmac.Final((byte*)&mac[0]);
	
	cout << "cmac: ";
	encoder.Put((const byte*)mac.data(), mac.size());
	encoder.MessageEnd();
	cout << endl;

	CMAC<AES> cmac2(key.data(), key.size());
	cmac2.Update((const byte*)plain.data(), plain.size());

	bool isMatch = cmac2.Verify((byte*)&mac[0]);
	cout << boolalpha << isMatch << endl;

	return 0;
}