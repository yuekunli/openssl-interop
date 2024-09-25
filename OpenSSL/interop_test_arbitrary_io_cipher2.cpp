#include "arbitrary_io_cipher_OpenSSL2.h"
#include "bytebuffer_api_CryptoPP.h"

#include <sstream>
#include <iostream>
#include <iomanip>

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER2 {

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
		OPENSSL_ARBITRARY_IO = 1
	};

	const int key_length[5] = { 0, 16, 16, 16, 24 };
	const int iv_length[5] = { 0, 16, 256, 128, 8 };
	char const* lib_names[3] = { "Crypto++", "OpenSSL with Arbitrary I/O" };
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

	static void test_Cipher_Arbitrary_IO2(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;

		ss << "Symmetric Cipher arbitrary I/O  " << std::setw(9) << algo_names[algo]
			<< ",  " << lib_names[keygen] << " generate keys and IV,  "
			<< std::setw(30) << lib_names[encrypt_lib] << " encrypt,  "
			<< std::setw(30) << lib_names[decrypt_lib] << " decrypt\n";

		char const* ptr_clear_text = clearText2;
		int clear_text_length = strlen(ptr_clear_text) + 1;

		int encryptedBufferSize = get_encryption_output_size(algo, clear_text_length);
		byte* encryptedBuffer = (byte*)malloc(encryptedBufferSize);

		int decryptedBufferSize = 40;
		byte* decryptedBuffer = (byte*)malloc(decryptedBufferSize);

		int keyLen = key_length[algo];
		byte* key = (byte*)malloc(keyLen);

		//byte key[16] = {
		//	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		//	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8
		//};


		//const int regular_iv_length[5] = { 0, 16, 256, 12, 8 };
		int ivLen = iv_length[algo];
		//int ivLen = 16;
		byte* iv = (byte*)malloc(ivLen);
		//byte iv[16] = {
		//	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		//	0x29, 0x2a, 0x2b, 0x2c, 0x31, 0x32, 0x33, 0x34//,
			//0x51, 0x52, 0x53, 0x54
		//};


		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);
		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(iv, 0, ivLen);

		if (encrypt_lib == LIB::CRYPTOPP)
		{
			byte* keyDup = (byte*)malloc(keyLen);
			byte* ivDup = (byte*)malloc(ivLen);
			memcpy(keyDup, key, keyLen);
			memcpy(ivDup, iv, ivLen);

			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, true);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup, keyLen, ivDup, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 7);


			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 7, 6);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 4);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 13, clear_text_length - 13);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, encryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (encrypt_lib == LIB::OPENSSL_ARBITRARY_IO)
		{
			byte* keyDup2 = (byte*)malloc(keyLen);
			byte* ivDup2 = (byte*)malloc(ivLen);
			memcpy(keyDup2, key, keyLen);
			memcpy(ivDup2, iv, ivLen);

			AIO_CIPHER_OPENSSL2::Cipher* pSymCipher = AIO_CIPHER_OPENSSL2::CipherInitialize(algo, true);
			AIO_CIPHER_OPENSSL2::CipherSetKeyAndInitialVector(pSymCipher, keyDup2, keyLen, ivDup2, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 7);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 7, 6);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 4);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 13, clear_text_length - 13);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherEndInput(pSymCipher);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, encryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherRelease(pSymCipher);
		}

		if (decrypt_lib == LIB::CRYPTOPP)
		{
			byte* keyDup3 = (byte*)malloc(keyLen);
			byte* ivDup3 = (byte*)malloc(ivLen);
			memcpy(keyDup3, key, keyLen);
			memcpy(ivDup3, iv, ivLen);

			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, false);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup3, keyLen, ivDup3, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 0, 7);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 7, 10);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 6);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 17, encryptedBufferSize - 17);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (decrypt_lib == LIB::OPENSSL_ARBITRARY_IO)
		{
			byte* keyDup4 = (byte*)malloc(keyLen);
			byte* ivDup4 = (byte*)malloc(ivLen);
			memcpy(keyDup4, key, keyLen);
			memcpy(ivDup4, iv, ivLen);

			AIO_CIPHER_OPENSSL2::Cipher* pSymCipher = AIO_CIPHER_OPENSSL2::CipherInitialize(algo, false);
			AIO_CIPHER_OPENSSL2::CipherSetKeyAndInitialVector(pSymCipher, keyDup4, keyLen, ivDup4, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 0, 7);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 7, 10);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 6);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 17, encryptedBufferSize - 17);

			AIO_CIPHER_OPENSSL2::CipherEndInput(pSymCipher);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherRelease(pSymCipher);
		}

		if (strcmp(ptr_clear_text, (char*)decryptedBuffer) == 0)
		{
			std::cout << "SUCCESS   " << ss.str();
		}
		else
		{
			std::cout << "FAIL   " << ss.str();
		}

		if (key)
			free(key);
		if (iv)
			free(iv);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}



	static void test_reset(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;

		ss << "Symmetric Cipher arbitrary I/O with reset " << std::setw(9) << algo_names[algo]
			<< ",  " << lib_names[keygen] << " generate keys and IV,  "
			<< std::setw(30) << lib_names[encrypt_lib] << " encrypt,  "
			<< std::setw(30) << lib_names[decrypt_lib] << " decrypt\n";

		char const* ptr_clear_text = clearText2;
		int clear_text_length = strlen(ptr_clear_text) + 1;

		int encryptedBufferSize = get_encryption_output_size(algo, clear_text_length);
		byte* encryptedBuffer = (byte*)malloc(encryptedBufferSize);

		int decryptedBufferSize = 40;
		byte* decryptedBuffer = (byte*)malloc(decryptedBufferSize);

		int keyLen = key_length[algo];
		byte* key = (byte*)malloc(keyLen);

		//byte key[16] = {
		//	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		//	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8
		//};


		//const int regular_iv_length[5] = { 0, 16, 256, 12, 8 };
		int ivLen = iv_length[algo];
		//int ivLen = 16;
		byte* iv = (byte*)malloc(ivLen);
		//byte iv[16] = {
		//	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		//	0x29, 0x2a, 0x2b, 0x2c, 0x31, 0x32, 0x33, 0x34//,
			//0x51, 0x52, 0x53, 0x54
		//};


		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);
		BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(iv, 0, ivLen);

		if (encrypt_lib == LIB::CRYPTOPP)
		{
			byte* keyDup = (byte*)malloc(keyLen);
			byte* ivDup = (byte*)malloc(ivLen);
			memcpy(keyDup, key, keyLen);
			memcpy(ivDup, iv, ivLen);

			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, true);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup, keyLen, ivDup, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 7);


			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 7, 6);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 4);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 13, clear_text_length - 13);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, encryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (encrypt_lib == LIB::OPENSSL_ARBITRARY_IO)
		{
			byte* keyDup2 = (byte*)malloc(keyLen);
			byte* ivDup2 = (byte*)malloc(ivLen);
			memcpy(keyDup2, key, keyLen);
			memcpy(ivDup2, iv, ivLen);

			AIO_CIPHER_OPENSSL2::Cipher* pSymCipher = AIO_CIPHER_OPENSSL2::CipherInitialize(algo, true);
			AIO_CIPHER_OPENSSL2::CipherSetKeyAndInitialVector(pSymCipher, keyDup2, keyLen, ivDup2, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 7);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 7, 6);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 4);
			bytesRetrievedTotal += bytesRetrieved;


			{
				AIO_CIPHER_OPENSSL2::CipherReset(pSymCipher);

				bytesRetrieved = bytesRetrievedTotal = 0;

				AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 7);

				bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 5);
				bytesRetrievedTotal += bytesRetrieved;

				AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 7, 6);

				bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 4);
				bytesRetrievedTotal += bytesRetrieved;

			}


			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 13, clear_text_length - 13);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherEndInput(pSymCipher);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, encryptedBuffer, bytesRetrievedTotal, encryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherRelease(pSymCipher);
		}

		if (decrypt_lib == LIB::CRYPTOPP)
		{
			byte* keyDup3 = (byte*)malloc(keyLen);
			byte* ivDup3 = (byte*)malloc(ivLen);
			memcpy(keyDup3, key, keyLen);
			memcpy(ivDup3, iv, ivLen);

			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, false);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup3, keyLen, ivDup3, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 0, 7);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 7, 10);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 6);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, encryptedBuffer, 17, encryptedBufferSize - 17);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (decrypt_lib == LIB::OPENSSL_ARBITRARY_IO)
		{
			byte* keyDup4 = (byte*)malloc(keyLen);
			byte* ivDup4 = (byte*)malloc(ivLen);
			memcpy(keyDup4, key, keyLen);
			memcpy(ivDup4, iv, ivLen);

			AIO_CIPHER_OPENSSL2::Cipher* pSymCipher = AIO_CIPHER_OPENSSL2::CipherInitialize(algo, false);
			AIO_CIPHER_OPENSSL2::CipherSetKeyAndInitialVector(pSymCipher, keyDup4, keyLen, ivDup4, ivLen);

			int bytesRetrieved, bytesRetrievedTotal = 0;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 0, 7);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 5);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 7, 10);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 6);
			bytesRetrievedTotal += bytesRetrieved;

			{
				AIO_CIPHER_OPENSSL2::CipherReset(pSymCipher);

				bytesRetrieved = bytesRetrievedTotal = 0;

				AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 0, 7);

				bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 5);
				bytesRetrievedTotal += bytesRetrieved;

				AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 7, 10);

				bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 6);
				bytesRetrievedTotal += bytesRetrieved;
			}

			AIO_CIPHER_OPENSSL2::CipherSubmitInput(pSymCipher, encryptedBuffer, 17, encryptedBufferSize - 17);

			AIO_CIPHER_OPENSSL2::CipherEndInput(pSymCipher);

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, 1);
			bytesRetrievedTotal += bytesRetrieved;

			bytesRetrieved = AIO_CIPHER_OPENSSL2::CipherRetrieveOutput(pSymCipher, decryptedBuffer, bytesRetrievedTotal, decryptedBufferSize - bytesRetrievedTotal);
			bytesRetrievedTotal += bytesRetrieved;

			AIO_CIPHER_OPENSSL2::CipherRelease(pSymCipher);
		}

		if (strcmp(ptr_clear_text, (char*)decryptedBuffer) == 0)
		{
			std::cout << "SUCCESS   " << ss.str();
		}
		else
		{
			std::cout << "FAIL   " << ss.str();
		}

		if (key)
			free(key);
		if (iv)
			free(iv);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}


	void test()
	{
		
		test_Cipher_Arbitrary_IO2(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_Cipher_Arbitrary_IO2(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_Cipher_Arbitrary_IO2(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_Cipher_Arbitrary_IO2(ALGO::DES3_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);


		test_Cipher_Arbitrary_IO2(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_Cipher_Arbitrary_IO2(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_Cipher_Arbitrary_IO2(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_Cipher_Arbitrary_IO2(ALGO::DES3_CBC, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);
		

		test_reset(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_reset(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_reset(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);

		test_reset(ALGO::DES3_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO);


		test_reset(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_reset(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_reset(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);

		test_reset(ALGO::DES3_CBC, LIB::CRYPTOPP, LIB::OPENSSL_ARBITRARY_IO, LIB::CRYPTOPP);
	}
}