#include "adaptiva_cryptopp.h"
#include "adaptiva_openssl.h"

#include <iostream>

namespace INTEROP_TEST_ECDSA {

	void test1()
	{
		char message[] = "It was the best of times";

		byte* pub, * pri;

		int pubLen, priLen;

		ADAPTIVA_CRYPTOPP::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		byte* sig;
		int sigLen;

		ADAPTIVA_CRYPTOPP::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		int isMatch;

		isMatch = ADAPTIVA_OPENSSL::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		std::cout << std::boolalpha << (isMatch == 0) << std::endl;

		free(pub);
		free(pri);
		free(sig);
	}


	void test2()
	{
		char message[] = "It was the best of times";

		byte* pub, * pri;

		int pubLen, priLen;

		ADAPTIVA_CRYPTOPP::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		byte* sig;
		int sigLen;

		ADAPTIVA_OPENSSL::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		int isMatch;

		isMatch = ADAPTIVA_OPENSSL::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		std::cout << std::boolalpha << (isMatch == 0) << std::endl;
	}


	void test3()
	{
		char message[] = "It was the best of times";

		byte* pub, * pri;

		int pubLen, priLen;

		ADAPTIVA_CRYPTOPP::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		byte* sig;
		int sigLen;

		ADAPTIVA_OPENSSL::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		int isMatch;

		isMatch = ADAPTIVA_CRYPTOPP::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		std::cout << std::boolalpha << (isMatch == 0) << std::endl;

		free(pub);
		free(pri);
		free(sig);
	}

	void test4()
	{
		char message[] = "It was the best of times";

		byte* pub = NULL, * pri = NULL;

		int pubLen, priLen;

		ADAPTIVA_OPENSSL::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		byte* sig;
		int sigLen;

		ADAPTIVA_CRYPTOPP::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		int isMatch;

		isMatch = ADAPTIVA_OPENSSL::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		std::cout << std::boolalpha << (isMatch == 0) << std::endl;

		free(pub);
		free(pri);
		free(sig);
	}

	void test5()
	{
		char message[] = "It was the best of times";

		byte* pub = NULL, * pri = NULL;

		int pubLen, priLen;

		ADAPTIVA_OPENSSL::DsaGenerateKeyPair(&pri, &priLen, &pub, &pubLen);

		byte* sig;
		int sigLen;

		ADAPTIVA_OPENSSL::DsaGenerateSignature((byte*)message, sizeof(message), pri, priLen, &sig, &sigLen);

		int isMatch;

		isMatch = ADAPTIVA_CRYPTOPP::DsaVerifySignature((byte*)message, sizeof(message), pub, pubLen, sig, sigLen);

		std::cout << std::boolalpha << (isMatch == 0) << std::endl;

		free(pub);
		free(pri);
		free(sig);
	}

}