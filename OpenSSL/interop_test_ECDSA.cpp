#include "bytebuffer_api_cryptopp.h"
#include "bytebuffer_api_openssl.h"

#include <iostream>
#include <sstream>

namespace INTEROP_TEST_ECDSA {

	enum LIB
	{
		CRYPTOPP = 0,
		OPENSSL = 1
	};

	char const* lib_names[] = { "Crypto++", "OpenSSL" };

	static void test(LIB keygen, LIB sign, LIB verify)
	{
		char message[] = "It was the best of times";

		std::stringstream ss;
		ss << "ECDSA Test    " << lib_names[keygen] << " generate keys   " << lib_names[sign] << " sign   " << lib_names[verify] << " verify\n";

		byte* pub = NULL, * pri = NULL;
		int pubLen, priLen;

		byte* sig = NULL;
		int sigLen;

		int isMatch = -99;

		if (keygen == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);
		else if (keygen == LIB::OPENSSL)
			BYTE_BUFFERIZED_OPENSSL::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		if (pub == NULL || pri == NULL)
		{
			std::cout << "FAIL   " << ss.str();
			goto cleanup;
		}

		if (sign == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);
		else if (sign == LIB::OPENSSL)
			BYTE_BUFFERIZED_OPENSSL::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		if (verify == LIB::CRYPTOPP)
			isMatch = BYTE_BUFFERIZED_CRYPTOPP::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);
		else if (verify == LIB::OPENSSL)
			isMatch = BYTE_BUFFERIZED_OPENSSL::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		if (isMatch == 0)
			std::cout << "SUCCESS   " << ss.str();
		else
			std::cout << "FAIL   " << ss.str();

	cleanup:

		if (pub)
			free(pub);
		if (pri)
			free(pri);
		if (sig)
			free(sig);
	}

	void test_ECDSA()
	{
		LIB library[2] = { LIB::CRYPTOPP, LIB::OPENSSL };

		for (int i = 0; i < 2; i++)
		{
			for (int j = 0; j < 2; j++)
			{
				for (int k = 0; k < 2; k++)
				{
					test(library[i], library[j], library[k]);
				}
			}
		}
		
	}

	void test_cryptopp_generate_keys_cryptopp_sign_openssl_verify()
	{
		test(LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
	}

	void test_cryptopp_generate_keys_openssl_sign_cryptopp_verify()
	{
		test(LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
	}

	void test_cryptopp_generate_keys_openssl_sign_openssl_verify()
	{
		test(LIB::CRYPTOPP, LIB::OPENSSL, LIB::OPENSSL);
	}

	void test_openssl_generate_keys_cryptopp_sign_openssl_verify()
	{
		test(LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);
	}

	void test_openssl_generate_keys_openssl_sign_cryptopp_verify()
	{
		test(LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
	}

	void test_openssl_generate_keys_openssl_sign_openssl_verify()
	{
		test(LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
	}

	void test_openssl_generate_keys_cryptopp_sign_cryptopp_verify()
	{
		test(LIB::OPENSSL, LIB::CRYPTOPP, LIB::CRYPTOPP);
	}
}