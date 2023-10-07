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

	// the 'r' component of the signature starts with a zero byte, there is complication in DER encoding.
	void test_ECDSA_special_case()
	{
		byte public_key[] = {
			48, -126, 1, 51, 48, -127, -20, 6, 7, 42, -122, 72, -50, 61, 2, 1, 48, -127, -32, 2,
			1, 1, 48, 44, 6, 7, 42, -122, 72, -50, 61, 1, 1, 2, 33, 0, -1, -1, -1, -1,
			0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, 48, 68, 4, 32, -1, -1, -1, -1, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -4, 4, 32, 90, -58, 53, -40, -86, 58, -109, -25, -77, -21, -67, 85, 118, -104,
			-122, -68, 101, 29, 6, -80, -52, 83, -80, -10, 59, -50, 60, 62, 39, -46, 96, 75, 4, 65,
			4, 107, 23, -47, -14, -31, 44, 66, 71, -8, -68, -26, -27, 99, -92, 64, -14, 119, 3, 125,
			-127, 45, -21, 51, -96, -12, -95, 57, 69, -40, -104, -62, -106, 79, -29, 66, -30, -2, 26, 127,
			-101, -114, -25, -21, 74, 124, 15, -98, 22, 43, -50, 51, 87, 107, 49, 94, -50, -53, -74, 64,
			104, 55, -65, 81, -11, 2, 33, 0, -1, -1, -1, -1, 0, 0, 0, 0, -1, -1, -1, -1,
			-1, -1, -1, -1, -68, -26, -6, -83, -89, 23, -98, -124, -13, -71, -54, -62, -4, 99, 37, 81,
			2, 1, 1, 3, 66, 0, 4, -100, -114, -45, 34, -115, -9, -45, 31, 73, 41, 35, 7, 86,
			11, -58, -108, -92, -27, 44, -24, -41, 102, 118, -88, 107, -1, -9, -119, -25, 22, 112, -111, -45,
			-33, -126, 7, 80, 110, -128, 80, -31, -87, -113, -5, -67, -34, 20, 85, -102, 112, 123, 10, -101,
			3, -119, 72, 36, -74, -87, 79, 100, 117, -71, 36
		};

		byte data[] = { 65, 65, 70, 83, 57, 48, 57, 77, 74, 52, 104, 55, 122, 70, 105, 73, 50, 69, 49, 71,
			117, 82, 79, 116, 88, 57, 99, 112, 68, 117, 52, 99, 65, 122, 70, 75, 118, 80, 72, 72,
			106, 73, 84, 117, 71, 73, 51, 74, 68, 97, 72, 90, 74, 52, 88, 69, 45, 51, 108, 89,
			80, 48, 95, 111, 53, 118, 114, 74, 87, 117, 105, 89, 65, 102, 89, 70, 89, 106, 95, 101,
			114, 74, 88, 69, 105, 55, 117, 67, 97, 114, 77, 111, 119, 103, 55, 97, 116, 111, 55, 85,
			108, 101, 88, 112, 76, 116, 115, 86, 113, 73, 109, 55, 107, 57, 65, 61, 77, 65, 61, 61,
			77, 84, 69, 121, 78, 81, 61, 61 };

		byte sig[] = { 0, 43, 107, -59, -85, 20, -111, -75, 127, -66, -53, 95, -52, -53, -4, -5, 105, 91, -52, 19,
			17, -86, 34, 25, -84, -117, 48, 81, 97, 88, 111, 6,
			-106, 80, 30, 7, -42, 27, 90, 21,
			-106, -111, -68, -10, 83, -99, 103, 127, 87, -113, -36, -67, -7, -63, 47, -15, -63, -24, 82, 84,
			26, -53, -13, -71 };


		int isMatch = BYTE_BUFFERIZED_OPENSSL::DsaVerifySignature(data, sizeof(data), public_key, sizeof(public_key), sig, sizeof(sig));		
	}
}