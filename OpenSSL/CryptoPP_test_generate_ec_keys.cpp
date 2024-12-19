
#include "cryptlib.h"
#include "eccrypto.h"
#include "ecp.h"
#include "oids.h"
#include "osrng.h"
#include <stdio.h>

using namespace CryptoPP;

namespace CRYPTOPP_EC_GEN_TEST {

	void ecdsa_generate_and_print_key_pair()
	{
		ECDSA<ECP, SHA512>::PrivateKey privateKey;
		ECDSA<ECP, SHA512>::PublicKey publicKey;
		unsigned char* privateKeyBytes;
		unsigned char* publicKeyBytes;

		int actualSize;
		int allocSize;

		OID curveOID = CryptoPP::ASN1::secp521r1();
		AutoSeededRandomPool rand;
		
		privateKey.Initialize(rand, curveOID);
		ByteQueue privateKeyQueue;
		privateKey.Save(privateKeyQueue);
		allocSize = (int)(privateKeyQueue.MaxRetrievable());
		privateKeyBytes = (unsigned char*)calloc(allocSize, sizeof(unsigned char));
		actualSize = privateKeyQueue.Get(privateKeyBytes, allocSize);
		
		for (int i = 0; i < actualSize; i++)
		{
			if (privateKeyBytes[i] != 0)
			{
				printf("(byte)%#04x, ", privateKeyBytes[i]);
			}
			else
			{
				printf("(byte)0x00, ");
			}
		}

		printf("\n\n");

		privateKey.MakePublicKey(publicKey);
		ByteQueue publicKeyQueue;
		publicKey.Save(publicKeyQueue);
		allocSize = (int)(publicKeyQueue.MaxRetrievable());
		publicKeyBytes = (unsigned char*)calloc(allocSize, sizeof(unsigned char));
		actualSize = publicKeyQueue.Get(publicKeyBytes, allocSize);

		for (int i = 0; i < actualSize; i++)
		{
			if (publicKeyBytes[i] != 0)
			{
				printf("(byte)%#04x, ", publicKeyBytes[i]);
			}
			else
			{
				printf("(byte)0x00, ");
			}
		}

		printf("\n\n");
	}
}
