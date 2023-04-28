#include "bytebuffer_api_cryptopp.h"

#include <iostream>
#include <sstream>


namespace BYTE_BUFFERIZED_OPENSSL {

	void RngFillByteArrayRegion(byte* pArray, int nStartingOffset, int nBytes);

	byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size);

	bool verifyCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, byte* tag, int tag_size);

}


namespace INTEROP_TEST_CMAC {

	void test1()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = BYTE_BUFFERIZED_CRYPTOPP::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);
	
		bool isMatch = BYTE_BUFFERIZED_CRYPTOPP::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);
	
		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


	void test2()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = BYTE_BUFFERIZED_OPENSSL::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = BYTE_BUFFERIZED_OPENSSL::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}

	void test3()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = BYTE_BUFFERIZED_OPENSSL::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = BYTE_BUFFERIZED_CRYPTOPP::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


	void test4()
	{
		char const* plaintext = "It was the best of times.";
		byte key[16];
		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, 16);
		int tag_size;
		byte* tag = BYTE_BUFFERIZED_CRYPTOPP::generateCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, &tag_size);

		bool isMatch = BYTE_BUFFERIZED_OPENSSL::verifyCMAC_3((byte*)plaintext, strlen(plaintext) + 1, key, 16, tag, tag_size);

		std::cout << std::boolalpha << isMatch << std::endl;
		free(tag);
	}


}