#include "bytebuffer_api_cryptopp.h"
#include "bytebuffer_api_openssl.h"

#include <iostream>
#include <sstream>

namespace INTEROP_TEST_SYMMETRICCRYPT {
	char const* clearText = 
		"Kirkland is a city in King County, Washington, United States. "
		"A suburb east of Seattle, its population was 92,175 in the 2020 U.S. census "
		"which made it the sixth largest city in the county and "
		"the twelfth largest in the state.\n"
		"The city\'s downtown waterfront has restaurants, art galleries, "
		"a performing arts center, public parks, beaches, and a collection "
		"of public art, primarily bronze sculptures.\n"
		"Kirkland was the original home of the Seattle Seahawks; "
		"the NFL team\'s headquarters and training facility were located "
		"at the Lake Washington Shipyard (now Carillon Point) along Lake Washington "
		"for their first ten seasons (1976–85), then at nearby Northwest University "
		"through 2007. Warehouse chain Costco previously had its headquarters in Kirkland. "
		"While Costco is now headquartered in Issaquah, the city is the namesake of "
		"its \"Kirkland Signature\" store brand.";

	char const* clearText2 = "Kirkland is a city";  // 19 characters long including the terminating '\0'

	enum ALGO
	{
		AES_CBC = 1,
		AES_EAX = 2,
		AES_GCM = 3,
		DES3_CBC = 4
	};

	enum LIB
	{
		CRYPTOPP = 0,
		OPENSSL =1
	};

	const int key_length[5] = { 0, 16, 16, 16, 24 };
	char const* lib_names[2] = { "Crypto++", "OpenSSL" };
	char const* algo_names[5] = { "", "AES_CBC", "AES_EAX", "AES_GCM", "DES3_CSC" };

	static void test(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;
		ss << "Symmetric Cipher Test    " << algo_names[algo]
			<< "    " << lib_names[keygen] << " generate keys   "
			<< lib_names[encrypt_lib] << " encrypt   "
			<< lib_names[decrypt_lib] << " decrypt\n";

		byte* key = NULL;
		int keyLen;

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize;

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;

		keyLen = key_length[algo];
		key = (byte*)malloc(keyLen);

		if (keygen == LIB::CRYPTOPP)
			BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);
		else if (keygen == LIB::OPENSSL)
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);

		if (encrypt_lib == LIB::CRYPTOPP)
			encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(algo, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);
		else if (encrypt_lib == LIB::OPENSSL)
			encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(algo, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);

		if (decrypt_lib == LIB::CRYPTOPP)
			decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(algo, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);
		else if (decrypt_lib == LIB::OPENSSL)
			decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(algo, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		if (strcmp(clearText, (char*)decryptedBuffer) == 0)
		{
			std::cout << "SUCCESS   " << ss.str();
		}
		else
		{
			std::cout << "FAIL   " << ss.str();
		}

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test_Symmetric_Cipher()
	{
		test(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		

		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_EAX, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);


		test(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);


		test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);

	}


	void test12()
	{
		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
	}
	void test13()
	{
		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
	}

	void test1()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test2()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test3()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test4()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(3, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(3, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test5()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(3, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(3, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test6()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(3, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(3, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test7()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(3, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(3, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test8()
	{
		byte* key = NULL;
		int keyLen = 24;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(4, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(4, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test9()
	{
		byte* key = NULL;
		int keyLen = 24;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(4, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(4, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test10()
	{
		byte* key = NULL;
		int keyLen = 24;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_OPENSSL::encryptBufferUsingJavaformat(4, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::decryptBufferUsingJavaformat(4, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test11()
	{
		byte* key = NULL;
		int keyLen = 24;
		key = (byte*)malloc(keyLen);

		BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = BYTE_BUFFERIZED_CRYPTOPP::encryptBufferUsingJavaformat(4, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = BYTE_BUFFERIZED_OPENSSL::decryptBufferUsingJavaformat(4, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}
}