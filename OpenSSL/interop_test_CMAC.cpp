#include "adaptiva_cryptopp.h"
#include "adaptiva_openssl.h"

#include <iostream>
#include <sstream>


namespace INTEROP_TEST_CMAC {

	void test1()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		ADAPTIVA_CRYPTOPP::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = ADAPTIVA_CRYPTOPP::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);
	
		bool isMatch = ADAPTIVA_CRYPTOPP::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);
	
		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


	void test2()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		ADAPTIVA_OPENSSL::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = ADAPTIVA_OPENSSL::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = ADAPTIVA_OPENSSL::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}

	void test3()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		ADAPTIVA_OPENSSL::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = ADAPTIVA_OPENSSL::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = ADAPTIVA_CRYPTOPP::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


	void test4()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		ADAPTIVA_CRYPTOPP::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = ADAPTIVA_CRYPTOPP::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = ADAPTIVA_OPENSSL::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


}