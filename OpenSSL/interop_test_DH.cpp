#include "bytebuffer_api_cryptopp.h"
#include "bytebuffer_api_openssl.h"

#include <iostream>
#include <sstream>

namespace INTEROP_TEST_DH {

	enum ALGO
	{
		DLDH1024 = 1,
		DLDH2048 = 2,
		ECDH = 3
	};

	enum LIB
	{
		CRYPTOPP = 0,
		OPENSSL = 1
	};

	char const* lib_names[] = { "Crypto++", "OpenSSL" };
	char const* algo_names[] = { "", "DLDH1024", "DLDH2048", "ECDH" };

	static void test(ALGO algo, LIB alice, LIB bob)
	{
		std::stringstream ss;

		ss << "Diffie-Hellman TEST  " << algo_names[algo] << "   " << lib_names[alice] << "  initiate   " << lib_names[bob] << "   respond\n";

		void* p1 = NULL, * p2 = NULL;
		char* pszDomainParams = NULL;
		byte* pubkey1 = NULL;
		int pubkey1Length;
		byte* pubkey2 = NULL;
		int pubkey2Length;

		byte* symKey1 = NULL;
		int symKey1Length;
		byte* symKey2 = NULL;
		int symKey2Length;


		if (alice == LIB::CRYPTOPP)
			p1 = (void*)BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(algo, NULL);

		else if (alice == LIB::OPENSSL)
			p1 = (void*)BYTE_BUFFERIZED_OPENSSL::DhInitialize(algo, NULL);


		if (algo == ALGO::DLDH1024 || algo == ALGO::DLDH2048)
		{
			if (alice == LIB::CRYPTOPP)
				pszDomainParams = BYTE_BUFFERIZED_CRYPTOPP::DhGetInitializationParameters((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p1);
			else if (alice == LIB::OPENSSL)
				pszDomainParams = BYTE_BUFFERIZED_OPENSSL::DhGetInitializationParameters((BYTE_BUFFERIZED_OPENSSL::DHState*)p1);
		}

		if (algo == ALGO::DLDH1024 || algo == ALGO::DLDH2048)
		{
			if (bob == LIB::CRYPTOPP)
				p2 = (void*)BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(algo, pszDomainParams);
			else if (bob == LIB::OPENSSL)
				p2 = (void*)BYTE_BUFFERIZED_OPENSSL::DhInitialize(algo, pszDomainParams);
		}
		else if (algo == ALGO::ECDH)
		{
			if (bob == LIB::CRYPTOPP)
				p2 = (void*)BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(algo, NULL);
			else if (bob == LIB::OPENSSL)
				p2 = (void*)BYTE_BUFFERIZED_OPENSSL::DhInitialize(algo, NULL);
		}

		if (alice == LIB::CRYPTOPP)
			pubkey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p1, &pubkey1Length);
		else
			pubkey1 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey((BYTE_BUFFERIZED_OPENSSL::DHState*)p1, &pubkey1Length);

		if (bob == LIB::CRYPTOPP)
			pubkey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p2, &pubkey2Length);
		else
			pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey((BYTE_BUFFERIZED_OPENSSL::DHState*)p2, &pubkey2Length);

		if (alice == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p1, pubkey2, pubkey2Length);
		else
			BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake((BYTE_BUFFERIZED_OPENSSL::DHState*)p1, pubkey2, pubkey2Length);

		if (bob == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p2, pubkey1, pubkey1Length);
		else
			BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake((BYTE_BUFFERIZED_OPENSSL::DHState*)p2, pubkey1, pubkey1Length);

		if (alice == LIB::CRYPTOPP)
			symKey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p1, &symKey1Length);
		else
			symKey1 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey((BYTE_BUFFERIZED_OPENSSL::DHState*)p1, &symKey1Length);

		if (bob == LIB::CRYPTOPP)
			symKey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p2, &symKey2Length);
		else
			symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey((BYTE_BUFFERIZED_OPENSSL::DHState*)p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "FAIL  " << ss.str();
			goto cleanup;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "FAIL  " << ss.str();
			goto cleanup;
		}

		std::cout << "SUCCESS  " << ss.str();

	cleanup:
		if (pszDomainParams)
			free(pszDomainParams);
		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		if (alice == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DhRelease((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p1);
		else
			BYTE_BUFFERIZED_OPENSSL::DhRelease((BYTE_BUFFERIZED_OPENSSL::DHState*)p1);

		if (bob == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DhRelease((BYTE_BUFFERIZED_CRYPTOPP::DHState*)p2);
		else
			BYTE_BUFFERIZED_OPENSSL::DhRelease((BYTE_BUFFERIZED_OPENSSL::DHState*)p2);
	}

	void test_Diffie_Hellman()
	{
		//test(ALGO::DLDH1024, LIB::CRYPTOPP, LIB::OPENSSL);   // not supported by FIPS
		//test(ALGO::DLDH2048, LIB::CRYPTOPP, LIB::OPENSSL);   // not supported by FIPS
		test(ALGO::DLDH2048, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::DLDH2048, LIB::OPENSSL, LIB::OPENSSL);
		test(ALGO::ECDH, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::ECDH, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::ECDH, LIB::OPENSSL, LIB::OPENSSL);
	}

	void test_DL1024_cryptopp_init_openssl_respond()
	{
		BYTE_BUFFERIZED_CRYPTOPP::DHState* p1 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(1, NULL);

		char* pszDomainParams = BYTE_BUFFERIZED_CRYPTOPP::DhGetInitializationParameters(p1);

		BYTE_BUFFERIZED_OPENSSL::DHState* p2 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(1, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

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

	void test_DL2048_cryptopp_init_openssl_respond()
	{
		BYTE_BUFFERIZED_CRYPTOPP::DHState* p1 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(2, NULL);

		char* pszDomainParams = BYTE_BUFFERIZED_CRYPTOPP::DhGetInitializationParameters(p1);

		BYTE_BUFFERIZED_OPENSSL::DHState* p2 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(2, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

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

	void test_DL2048_openssl_init_cryptopp_respond()
	{
		BYTE_BUFFERIZED_OPENSSL::DHState* p1 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(2, NULL);

		char* pszDomainParams = BYTE_BUFFERIZED_OPENSSL::DhGetInitializationParameters(p1);

		BYTE_BUFFERIZED_CRYPTOPP::DHState* p2 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(2, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

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

	void test_DL1024_cryptopp_init_cryptopp_respond()
	{
		BYTE_BUFFERIZED_CRYPTOPP::DHState* p1 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(1, NULL);

		char* pszDomainParams = BYTE_BUFFERIZED_CRYPTOPP::DhGetInitializationParameters(p1);

		BYTE_BUFFERIZED_CRYPTOPP::DHState* p2 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(1, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

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

	void test_DL2048_named_group_openssl_init_openssl_respond()
	{
		BYTE_BUFFERIZED_OPENSSL::DHState* p1 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(2, NULL);

		char* pszDomainParams = BYTE_BUFFERIZED_OPENSSL::DhGetInitializationParameters(p1);

		BYTE_BUFFERIZED_OPENSSL::DHState* p2 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(2, pszDomainParams);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

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
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p1);
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p2);
	}

	void test_EC_p256_curve_openssl_init_openssl_respond()
	{
		BYTE_BUFFERIZED_OPENSSL::DHState* p1 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(3, NULL);

		BYTE_BUFFERIZED_OPENSSL::DHState* p2 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p1);
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p2);
	}

	void test_EC_p256_curve_cryptopp_init_openssl_respond()
	{
		BYTE_BUFFERIZED_CRYPTOPP::DHState* p1 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(3, NULL);

		BYTE_BUFFERIZED_OPENSSL::DHState* p2 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		BYTE_BUFFERIZED_CRYPTOPP::DhRelease(p1);
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p2);
	}

	void test_EC_p256_curve_openssl_init_cryptopp_respond()
	{
		BYTE_BUFFERIZED_OPENSSL::DHState* p1 = BYTE_BUFFERIZED_OPENSSL::DhInitialize(3, NULL);

		BYTE_BUFFERIZED_CRYPTOPP::DHState* p2 = BYTE_BUFFERIZED_CRYPTOPP::DhInitialize(3, NULL);

		byte* pubkey1;
		int pubkey1Length;
		byte* pubkey2;
		int pubkey2Length;

		pubkey1 = BYTE_BUFFERIZED_OPENSSL::DhGetPublicKey(p1, &pubkey1Length);
		pubkey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGetPublicKey(p2, &pubkey2Length);

		BYTE_BUFFERIZED_OPENSSL::DhCompleteHandshake(p1, pubkey2, pubkey2Length);
		BYTE_BUFFERIZED_CRYPTOPP::DhCompleteHandshake(p2, pubkey1, pubkey1Length);

		byte* symKey1;
		int symKey1Length;
		byte* symKey2;
		int symKey2Length;

		symKey1 = BYTE_BUFFERIZED_OPENSSL::DhGenerateAESKey(p1, &symKey1Length);
		symKey2 = BYTE_BUFFERIZED_CRYPTOPP::DhGenerateAESKey(p2, &symKey2Length);

		if (symKey1Length != symKey2Length)
		{
			std::cout << "Symmetric key length not equal" << std::endl;
			return;
		}

		if (memcmp(symKey1, symKey2, symKey1Length) != 0)
		{
			std::cout << "Symmetric key value not equal" << std::endl;
		}

		free(pubkey1);
		free(pubkey2);
		free(symKey1);
		free(symKey2);
		BYTE_BUFFERIZED_OPENSSL::DhRelease(p1);
		BYTE_BUFFERIZED_CRYPTOPP::DhRelease(p2);
	}
}