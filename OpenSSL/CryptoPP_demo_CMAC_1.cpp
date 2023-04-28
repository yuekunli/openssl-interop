// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "cmac.h"
using CryptoPP::CMAC;

#include "aes.h"
using CryptoPP::AES;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;

#include "secblock.h"
using CryptoPP::SecByteBlock;

namespace CRYPTOPP_DEMO {

	int demo_CMAC_1()
	{
		AutoSeededRandomPool prng;

		SecByteBlock key(AES::DEFAULT_KEYLENGTH);
		prng.GenerateBlock(key, key.size());

		string plain = "CMAC Test";
		string mac, encoded;

		/*********************************\
		\*********************************/

		// Pretty print key
		encoded.clear();
		StringSource(key, key.size(), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		cout << "key: " << encoded << endl;

		cout << "plain text: " << plain << endl;

		/*********************************\
		\*********************************/

		try
		{
			CMAC< AES > cmac(key, key.size());

			StringSource(plain, true,
				new HashFilter(cmac,
					new StringSink(mac)
				) // HashFilter      
			); // StringSource
		}
		catch (const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		/*********************************\
		\*********************************/

		// Pretty print
		encoded.clear();
		StringSource(mac, true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
		cout << "cmac: " << encoded << endl;

		/*********************************\
		\*********************************/

		// Verify
		try
		{
			CMAC< AES > cmac(key, key.size());
			const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

			// Tamper with message
			plain[0] ^= 0x01;

			StringSource(plain + mac, true,
				new HashVerificationFilter(cmac, NULL, flags)
			); // StringSource

			cout << "Verified message" << endl;
		}
		catch (const CryptoPP::Exception& e)
		{
			cerr << e.what() << endl;
			exit(1);
		}

		return 0;
	}
}