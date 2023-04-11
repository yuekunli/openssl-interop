#include "adaptiva_cryptopp.h"
#include "adaptiva_openssl.h"

#include <iostream>

namespace INTEROP_TEST_DH {

	void test_DL_cryptopp_init_openssl_respond()
	{
		// '1' means DH 1024, which is deprecated. But we test DH1024 here is because
		// we are having Alice use crypto++ API to initiate DH, which means Alice generates
		// Prime and Geneartor, it's very slow to generate not-well-know prime and generator pair
		// so we use well defined prime and generator, I only found 1014 bits well defined
		// prime and generator.

		ADAPTIVA_CRYPTOPP::DHState* p1 = ADAPTIVA_CRYPTOPP::DhInitialize(1, NULL);

		char* pszDomainParams = ADAPTIVA_CRYPTOPP::DhGetInitializationParameters(p1);

		ADAPTIVA_OPENSSL::DHState* p2 = ADAPTIVA_OPENSSL::DhInitialize(1, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}
	}

	void test_DL_openssl_init_cryptopp_respond()
	{
		ADAPTIVA_OPENSSL::DHState* p1 = ADAPTIVA_OPENSSL::DhInitialize(2, NULL);

		char* pszDomainParams = ADAPTIVA_OPENSSL::DhGetInitializationParameters(p1);

		ADAPTIVA_CRYPTOPP::DHState* p2 = ADAPTIVA_CRYPTOPP::DhInitialize(2, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}
	}

	void test2()
	{
		ADAPTIVA_CRYPTOPP::DHState* p1 = ADAPTIVA_CRYPTOPP::DhInitialize(1, NULL);

		char* pszDomainParams = ADAPTIVA_CRYPTOPP::DhGetInitializationParameters(p1);

		ADAPTIVA_CRYPTOPP::DHState* p2 = ADAPTIVA_CRYPTOPP::DhInitialize(1, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}
	}

	void test3()
	{
		ADAPTIVA_OPENSSL::DHState* p1 = ADAPTIVA_OPENSSL::DhInitialize(2, NULL);

		char* pszDomainParams = ADAPTIVA_OPENSSL::DhGetInitializationParameters(p1);

		ADAPTIVA_OPENSSL::DHState* p2 = ADAPTIVA_OPENSSL::DhInitialize(2, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		free(pszDomainParams);
		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		ADAPTIVA_OPENSSL::DhRelease(p1);
		ADAPTIVA_OPENSSL::DhRelease(p2);
	}


	void test4()
	{
		ADAPTIVA_OPENSSL::DHState* p1 = ADAPTIVA_OPENSSL::DhInitialize(3, NULL);

		//char* pszDomainParams = ADAPTIVA_OPENSSL::DhGetInitializationParameters(p1);

		ADAPTIVA_OPENSSL::DHState* p2 = ADAPTIVA_OPENSSL::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		//free(pszDomainParams);
		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		ADAPTIVA_OPENSSL::DhRelease(p1);
		ADAPTIVA_OPENSSL::DhRelease(p2);
	}

	void test5()
	{
		ADAPTIVA_CRYPTOPP::DHState* p1 = ADAPTIVA_CRYPTOPP::DhInitialize(3, NULL);

		//char* pszDomainParams = ADAPTIVA_OPENSSL::DhGetInitializationParameters(p1);

		ADAPTIVA_OPENSSL::DHState* p2 = ADAPTIVA_OPENSSL::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		//free(pszDomainParams);
		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		ADAPTIVA_CRYPTOPP::DhRelease(p1);
		ADAPTIVA_OPENSSL::DhRelease(p2);
	}


	void test6()
	{
		ADAPTIVA_OPENSSL::DHState* p1 = ADAPTIVA_OPENSSL::DhInitialize(3, NULL);

		//char* pszDomainParams = ADAPTIVA_OPENSSL::DhGetInitializationParameters(p1);

		ADAPTIVA_CRYPTOPP::DHState* p2 = ADAPTIVA_CRYPTOPP::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = ADAPTIVA_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = ADAPTIVA_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		ADAPTIVA_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		ADAPTIVA_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = ADAPTIVA_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = ADAPTIVA_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		//free(pszDomainParams);
		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		ADAPTIVA_OPENSSL::DhRelease(p1);
		ADAPTIVA_CRYPTOPP::DhRelease(p2);
	}
}