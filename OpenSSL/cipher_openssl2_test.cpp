#include "cipher_openssl2.h"
#include "bytebuffer_api_openssl.h"
#include "bytebuffer_api_CryptoPP.h"

#include <sstream>
#include <iostream>

namespace CIPHER_OPENSSL2_TEST {

	char const* clearText2 = "Kirkland is a city";  // 19 characters long including the terminating '\0'

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
		OPENSSL = 1,
		OPENSSL_BIO = 2
	};

	const int key_length[5] = { 0, 16, 16, 16, 24 };
	const int iv_length[5] = { 0, 16, 256, 128, 8 };
	char const* lib_names[3] = { "Crypto++", "OpenSSL", "OpenSSL BIO"};
	char const* algo_names[5] = { "", "AES_CBC", "AES_EAX", "AES_GCM", "DES3_CSC" };


	static int get_encryption_output_size(ALGO algo, int cleartext_size)
	{
		switch (algo)
		{
		case AES_CBC:
			return cleartext_size + (16 - cleartext_size % 16);
		case AES_EAX:
			return cleartext_size + 16;
		case AES_GCM:
			return cleartext_size + 16;
		case DES3_CBC:
			return cleartext_size + (8 - cleartext_size % 8);
		}
	}


	static void test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;
		ss << "Symmetric Cipher buffered gradual I/O using Cipher as BIO filter  " << algo_names[algo]
			<< "    " << lib_names[keygen] << " generate keys and IV  "
			<< lib_names[encrypt_lib] << " encrypt   "
			<< lib_names[decrypt_lib] << " decrypt\n";

		char const* ptr_clear_text = clearText;
		int clear_text_length = strlen(ptr_clear_text) + 1;
		// Attention! if not doing strlen() + 1, clear text doesn't have the '\0'. if running GCM, cipher text will be text + tag, no '\0' in between.
		// Running decryption, the cipher BIO indiscriminately decrypt entire input. So that I can see the "tag" being treated as cipher text in the debugger.
		// If there is a '\0' in the clear text, decrypto will correctly decrypt that '\0', the debugger variable window only shows a string up to the '\0'
		// In real test, I should do strlen() + 1

		int encryptedBufferSize = get_encryption_output_size(algo, clear_text_length);
		byte* encryptedBuffer = (byte*)malloc(encryptedBufferSize);

		int decryptedBufferSize = 1000;
		byte* decryptedBuffer = (byte*)malloc(decryptedBufferSize);

		int keyLen = key_length[algo];
		byte* key = (byte*)malloc(keyLen);
		//byte key[16] = {
		//	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		//	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8
		//};


		//const int regular_iv_length[5] = { 0, 16, 256, 12, 8 };
		int ivLen = iv_length[algo];
		//int ivLen = 20;
		byte* iv = (byte*)malloc(ivLen);
		//byte iv[20] = {
		//	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		//	0x29, 0x2a, 0x2b, 0x2c, 0x31, 0x32, 0x33, 0x34,
		//	0x51, 0x52, 0x53, 0x54
		//};

		/*
		if (keygen == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(iv, 0, ivLen);
		}
		*/
		if (encrypt_lib == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::SymmetricCipher* pSymCipher = BYTE_BUFFERIZED_OPENSSL::CipherInitialize(algo, true);
			byte* keyDup = (byte*)malloc(keyLen);
			byte* ivDup = (byte*)malloc(ivLen);
			memcpy(keyDup, key, keyLen);
			memcpy(ivDup, iv, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSetKeyAndInitialVector(pSymCipher, keyDup, keyLen, ivDup, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, clear_text_length / 4);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, clear_text_length / 4, clear_text_length / 4);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, clear_text_length / 4 * 2, clear_text_length - clear_text_length / 4 * 2);
			BYTE_BUFFERIZED_OPENSSL::CipherEndInput(pSymCipher);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher, encryptedBuffer, 0, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher, encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher, encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			BYTE_BUFFERIZED_OPENSSL::CipherRelease(pSymCipher);
		}
		else if (encrypt_lib == LIB::OPENSSL_BIO)
		{
			
			byte* keyDup2 = (byte*)malloc(keyLen);
			byte* ivDup2 = (byte*)malloc(ivLen);
			memcpy(keyDup2, key, keyLen);
			memcpy(ivDup2, iv, ivLen);

			CO2::AESGCM* gcm = new CO2::AESGCM(true);
			gcm->setKeyAndIV(keyDup2, keyLen, ivDup2, ivLen);

			gcm->submitInput((byte*)ptr_clear_text, 0, clear_text_length / 4);
			gcm->submitInput((byte*)ptr_clear_text, clear_text_length / 4, clear_text_length / 4);
			gcm->submitInput((byte*)ptr_clear_text, clear_text_length / 4 * 2, clear_text_length - clear_text_length / 4 * 2);
			gcm->endInput();
			gcm->retrieveOutput(encryptedBuffer, 0, encryptedBufferSize / 5);
			gcm->retrieveOutput(encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			gcm->retrieveOutput(encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			delete gcm;
		}

		if (decrypt_lib == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher3 = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, false);
			byte* keyDup3 = (byte*)malloc(keyLen);
			byte* ivDup3 = (byte*)malloc(ivLen);
			memcpy(keyDup3, key, keyLen);
			memcpy(ivDup3, iv, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher3, keyDup3, keyLen, ivDup3, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, 0, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher3);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, 0, decryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, decryptedBufferSize / 5, decryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, decryptedBufferSize / 5 * 2, decryptedBufferSize - decryptedBufferSize / 5 * 2);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher3);
		}
		else if (decrypt_lib == LIB::OPENSSL_BIO)
		{
			byte* keyDup4 = (byte*)malloc(keyLen);
			byte* ivDup4 = (byte*)malloc(ivLen);
			memcpy(keyDup4, key, keyLen);
			memcpy(ivDup4, iv, ivLen);

			CO2::AESGCM* gcm = new CO2::AESGCM(false);
			gcm->setKeyAndIV(keyDup4, keyLen, ivDup4, ivLen);
			gcm->submitInput(encryptedBuffer, 0, encryptedBufferSize / 5);
			gcm->submitInput(encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			gcm->submitInput(encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			gcm->endInput();
			gcm->retrieveOutput(decryptedBuffer, 0, decryptedBufferSize / 5);
			gcm->retrieveOutput(decryptedBuffer, decryptedBufferSize / 5, decryptedBufferSize / 5);
			gcm->retrieveOutput(decryptedBuffer, decryptedBufferSize / 5 * 2, decryptedBufferSize - decryptedBufferSize / 5 * 2);
			delete gcm;
		}

		if (strcmp(ptr_clear_text, (char*)decryptedBuffer) == 0)
		{
			std::cout << "SUCCESS   " << ss.str();
		}
		else
		{
			std::cout << "FAIL   " << ss.str();
		}

		//if (key)
			//free(key);
		//if (iv)
			//free(iv);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}


	void test()
	{
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL_BIO);
	}


	void test2()
	{
		byte data[19] = {
			0x23, 0x44, 0xa1, 0x93,
			0x2e, 0xcf, 0x19, 0xff,
			0xf1, 0x2a, 0x17, 0xec,
			0x66, 0x62, 0xa3, 0xaa,
			0x71, 0x78, 0xb2 };

		byte key[16] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8
		};


		byte iv[20] = {
			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x31, 0x32, 0x33, 0x34,
			0x51, 0x52, 0x53, 0x54
		};

		byte* out = CO2::eax_encrypt(data, sizeof(data), key, sizeof(key), iv, sizeof(iv));

		OPENSSL_free(out);
	}
}