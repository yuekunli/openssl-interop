#include "bytebuffer_api_cryptopp.h"
#include "bytebuffer_api_openssl.h"
#include "BIO_cipher_OpenSSL.h"

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

	// this paragraph text is 863 bytes long (not including the terminating null). 
	// So there are 864 bytes in memory pointed at by "clearText".
	// 864 / 16 = 54 no residual. When CBC mode encrypts this paragraph, it still pads 1 full block. This is PKCS#7 padding.
	// hoverring mouse pointer over this paragraph may show a tool tip that suggests "const char[xxx]". 
	// The size shown this way is inaccurate when there are multiple lines.


	char const* clearText2 =
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
		"its \"Kirkland Signature\" store brand.abcd";

	// The difference between this paragraph and the last paragraph is only the addition of the last 4 characters. i.e. "abcd"
	// The total length (include terminating null) of this paragraph is 868, which is 15 * 54 + 4
	// So there is residual, and definitely should be padded.

	char const* clearText3 = "Kirkland is a city";  // 19 characters long including the terminating '\0'

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
	const int iv_length[5] = { 0, 16, 256, 128, 8 };
	char const* lib_names[2] = { "Crypto++", "OpenSSL" };
	char const* algo_names[5] = { "", "AES_CBC", "AES_EAX", "AES_GCM", "DES3_CSC" };

	static void test(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;
		ss << "Symmetric Cipher Test using java format (single call)   " << algo_names[algo]
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
		
	static void test_buffered_gradual_io(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;
		ss << "Symmetric Cipher buffered gradual I/O   " << algo_names[algo]
			<< "    " << lib_names[keygen] << " generate keys and IV  "
			<< lib_names[encrypt_lib] << " encrypt   "
			<< lib_names[decrypt_lib] << " decrypt\n";

		char const* ptr_clear_text = clearText;

		int encryptedBufferSize = get_encryption_output_size(algo, strlen(ptr_clear_text) + 1);
		byte* encryptedBuffer = (byte*)malloc(encryptedBufferSize);

		//int decryptedBufferSize = strlen(ptr_clear_text) + 1;
		int decryptedBufferSize = 1000;
		byte* decryptedBuffer = (byte*)malloc(decryptedBufferSize);

		int keyLen = key_length[algo];
		byte* key = (byte*)malloc(keyLen);

		int ivLen = iv_length[algo];
		byte* iv = (byte*)malloc(ivLen);

		if (keygen == LIB::CRYPTOPP)
		{
			BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);
			BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(iv, 0, ivLen);
		}
		else if (keygen == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(iv, 0, ivLen);
		}

		if (encrypt_lib == LIB::CRYPTOPP)
		{
			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, true);
			byte* keyDup = (byte*)malloc(keyLen);
			byte* ivDup = (byte*)malloc(ivLen);
			memcpy(keyDup, key, keyLen);
			memcpy(ivDup, iv, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup, keyLen, ivDup, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, 100);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 100, 100);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 200, strlen(ptr_clear_text) + 1 - 200);
			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, 0, 130);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, 130, 130);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, 260, encryptedBufferSize-260);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (encrypt_lib == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::SymmetricCipher* pSymCipher2 = BYTE_BUFFERIZED_OPENSSL::CipherInitialize(algo, true);
			byte* keyDup2 = (byte*)malloc(keyLen);
			byte* ivDup2 = (byte*)malloc(ivLen);
			memcpy(keyDup2, key, keyLen);
			memcpy(ivDup2, iv, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSetKeyAndInitialVector(pSymCipher2, keyDup2, keyLen, ivDup2, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, 0, 100);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, 100, 100);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, 200, strlen(ptr_clear_text) + 1 - 200);
			BYTE_BUFFERIZED_OPENSSL::CipherEndInput(pSymCipher2);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, 0, 130);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, 130, 130);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, 260, encryptedBufferSize - 260);
			BYTE_BUFFERIZED_OPENSSL::CipherRelease(pSymCipher2);
		}

		if (decrypt_lib == LIB::CRYPTOPP)
		{
			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher3 = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, false);
			byte* keyDup3 = (byte*)malloc(keyLen);
			byte* ivDup3 = (byte*)malloc(ivLen);
			memcpy(keyDup3, key, keyLen);
			memcpy(ivDup3, iv, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher3, keyDup3, keyLen, ivDup3, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, 0, 100);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, 100, 100);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher3, encryptedBuffer, 200, encryptedBufferSize - 200);
			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher3);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, 0, 130);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, 130, 130);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, 260, decryptedBufferSize - 260);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher3);
		}
		else if (decrypt_lib == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::SymmetricCipher* pSymCipher4 = BYTE_BUFFERIZED_OPENSSL::CipherInitialize(algo, false);
			byte* keyDup4 = (byte*)malloc(keyLen);
			byte* ivDup4 = (byte*)malloc(ivLen);
			memcpy(keyDup4, key, keyLen);
			memcpy(ivDup4, iv, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSetKeyAndInitialVector(pSymCipher4, keyDup4, keyLen, ivDup4, ivLen);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, 0, 100);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, 100, 100);
			BYTE_BUFFERIZED_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, 200, encryptedBufferSize - 200);
			BYTE_BUFFERIZED_OPENSSL::CipherEndInput(pSymCipher4);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, 0, 130);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, 130, 130);
			BYTE_BUFFERIZED_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, 260, decryptedBufferSize - 260);
			BYTE_BUFFERIZED_OPENSSL::CipherRelease(pSymCipher4);
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
	


	static void test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
	{
		std::stringstream ss;
		ss << "Symmetric Cipher buffered gradual I/O using Cipher as BIO filter  " << algo_names[algo]
			<< "    " << lib_names[keygen] << " generate keys and IV  "
			<< lib_names[encrypt_lib] << " encrypt   "
			<< lib_names[decrypt_lib] << " decrypt\n";

		char const* ptr_clear_text = clearText3;
		int clear_text_length = strlen(ptr_clear_text) + 1;
		// Attention! if not doing strlen() + 1, clear text doesn't have the '\0'. if running GCM, cipher text will be text + tag, no '\0' in between.
		// Running decryption, the cipher BIO indiscriminately decrypt entire input. So that I can see the "tag" being treated as cipher text in the debugger.
		// If there is a '\0' in the clear text, decrypto will correctly decrypt that '\0', the debugger variable window only shows a string up to the '\0'
		// In real test, I should do strlen() + 1

		int encryptedBufferSize = get_encryption_output_size(algo, clear_text_length);
		byte* encryptedBuffer = (byte*)malloc(encryptedBufferSize);

		int decryptedBufferSize = 40;
		byte* decryptedBuffer = (byte*)malloc(decryptedBufferSize);

		int keyLen = key_length[algo];
		byte* key = (byte*)malloc(keyLen);

		const int regular_iv_length[5] = { 0, 16, 256, 12, 8 };
		int ivLen = regular_iv_length[algo];
		byte* iv = (byte*)malloc(ivLen);

		if (keygen == LIB::CRYPTOPP)
		{
			BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);
			BYTE_BUFFERIZED_CRYPTOPP::RngFillByteArrayRegion(iv, 0, ivLen);
		}
		else if (keygen == LIB::OPENSSL)
		{
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(key, 0, keyLen);
			BYTE_BUFFERIZED_OPENSSL::RngFillByteArrayRegion(iv, 0, ivLen);
		}
		
		

		if (encrypt_lib == LIB::CRYPTOPP)
		{
			BYTE_BUFFERIZED_CRYPTOPP::Cipher* pSymCipher = BYTE_BUFFERIZED_CRYPTOPP::CipherInitialize(algo, true);
			byte* keyDup = (byte*)malloc(keyLen);
			byte* ivDup = (byte*)malloc(ivLen);
			memcpy(keyDup, key, keyLen);
			memcpy(ivDup, iv, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSetKeyAndInitialVector(pSymCipher, keyDup, keyLen, ivDup, ivLen);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, 0, clear_text_length/4);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, clear_text_length / 4, clear_text_length / 4);
			BYTE_BUFFERIZED_CRYPTOPP::CipherSubmitInput(pSymCipher, (byte*)ptr_clear_text, clear_text_length / 4 * 2, clear_text_length - clear_text_length / 4 * 2);
			BYTE_BUFFERIZED_CRYPTOPP::CipherEndInput(pSymCipher);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, 0, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher, encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher);
		}
		else if (encrypt_lib == LIB::OPENSSL)
		{
			BIO_CIPHER_OPENSSL::SymmetricCipher* pSymCipher2 = BIO_CIPHER_OPENSSL::CipherInitialize(algo, true);
			byte* keyDup2 = (byte*)malloc(keyLen);
			byte* ivDup2 = (byte*)malloc(ivLen);
			memcpy(keyDup2, key, keyLen);
			memcpy(ivDup2, iv, ivLen);
			BIO_CIPHER_OPENSSL::CipherSetKeyAndInitialVector(pSymCipher2, keyDup2, keyLen, ivDup2, ivLen);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, 0, clear_text_length / 4);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, clear_text_length / 4, clear_text_length / 4);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher2, (byte*)ptr_clear_text, clear_text_length / 4 * 2, clear_text_length - clear_text_length / 4 * 2);
			BIO_CIPHER_OPENSSL::CipherEndInput(pSymCipher2);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, 0, encryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher2, encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			BIO_CIPHER_OPENSSL::CipherRelease(pSymCipher2);
		}

		if (decrypt_lib == LIB::CRYPTOPP)
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
			BYTE_BUFFERIZED_CRYPTOPP::CipherRetrieveOutput(pSymCipher3, decryptedBuffer, decryptedBufferSize / 5, decryptedBufferSize - decryptedBufferSize / 5 * 2);
			BYTE_BUFFERIZED_CRYPTOPP::CipherRelease(pSymCipher3);
		}
		else if (decrypt_lib == LIB::OPENSSL)
		{
			BIO_CIPHER_OPENSSL::SymmetricCipher* pSymCipher4 = BIO_CIPHER_OPENSSL::CipherInitialize(algo, false);
			byte* keyDup4 = (byte*)malloc(keyLen);
			byte* ivDup4 = (byte*)malloc(ivLen);
			memcpy(keyDup4, key, keyLen);
			memcpy(ivDup4, iv, ivLen);
			BIO_CIPHER_OPENSSL::CipherSetKeyAndInitialVector(pSymCipher4, keyDup4, keyLen, ivDup4, ivLen);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, 0, encryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, encryptedBufferSize / 5, encryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherSubmitInput(pSymCipher4, encryptedBuffer, encryptedBufferSize / 5 * 2, encryptedBufferSize - encryptedBufferSize / 5 * 2);
			BIO_CIPHER_OPENSSL::CipherEndInput(pSymCipher4);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, 0, decryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, decryptedBufferSize / 5, decryptedBufferSize / 5);
			BIO_CIPHER_OPENSSL::CipherRetrieveOutput(pSymCipher4, decryptedBuffer, decryptedBufferSize / 5 * 2, decryptedBufferSize - decryptedBufferSize / 5 * 2);
			BIO_CIPHER_OPENSSL::CipherRelease(pSymCipher4);
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


	void test_Symmetric_Cipher()
	{
		/*
		test(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		

		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_EAX, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		

		test(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		*/

		// https://docs.openssl.org/3.3/man7/EVP_CIPHER-DES/
		// DES-EDE3-CBC is available in FIPS provider
		//test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		//test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		//test(ALGO::DES3_CBC, LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);


		//test_buffered_gradual_io(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		//test_buffered_gradual_io(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		//test_buffered_gradual_io(ALGO::AES_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		//test_buffered_gradual_io(ALGO::AES_CBC, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::CRYPTOPP);

		/*
		test_buffered_gradual_io(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test_buffered_gradual_io(ALGO::AES_EAX, LIB::CRYPTOPP, LIB::OPENSSL, LIB::CRYPTOPP);
		test_buffered_gradual_io(ALGO::AES_EAX, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);

		test_buffered_gradual_io(ALGO::AES_GCM, LIB::CRYPTOPP, LIB::CRYPTOPP, LIB::OPENSSL);
		test_buffered_gradual_io(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test_buffered_gradual_io(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		*/

		
		
		
		/*
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_CBC, LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);


		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::DES3_CBC, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);
		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::DES3_CBC, LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);
		*/


		//test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::CRYPTOPP);

		
		// This implementation currently doesn't support OpenSSL being the decryptor of a cipher that comes with a mac tag.
		// OpenSSl <--> OpenSSL can pass the test because the original clear text will be decrypted correctly and the tag will be mistreated as cipher text.
		// but strcmp only compares up to whichever one has a '\0'
		// Essentially I'll be comparing these two:
		// something something\0
		// something something\0xxxxx
		// the "xxxxx" is the output of decrypting the tag.
		// strcmp only compares two strings up to the '\0', so they are equal.

		test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_GCM, LIB::OPENSSL, LIB::OPENSSL, LIB::OPENSSL);
		//test_buffered_gradual_io_Cipher_as_BIO_filter(ALGO::AES_GCM, LIB::OPENSSL, LIB::CRYPTOPP, LIB::OPENSSL);

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