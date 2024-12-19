#include "arbitrary_io_cipher_OpenSSL2.h"
#include "bytebuffer_api_CryptoPP.h"

#include <sstream>
#include <iostream>
#include <iomanip>



namespace INTEROP_TEST_ARBITRARY_IO_CIPHER3 {
	
	using namespace AIO_CIPHER_OPENSSL2;
	
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

	static void test1(ALGO algo, LIB keygen, LIB encrypt_lib, LIB decrypt_lib)
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


		CBC<AES>* p = new CBC<AES>(true);
		p->setKeyAndIV(key, keyLen, iv, ivLen);

		p->submitInput((byte*)(ptr_clear_text), 0, strlen(ptr_clear_text));

		p->endInput();

		byte* a = (byte*)OPENSSL_malloc(70);
		p->retrieveOutput(a, 0, 70);

		OPENSSL_free(a);
		OPENSSL_free(key);
		OPENSSL_free(iv);
		delete p;
	}

	void test2()
	{
		ALGO algo = ALGO::AES_CBC;
		LIB keygen = LIB::CRYPTOPP;
		LIB encrypt_lib = LIB::OPENSSL_ARBITRARY_IO;
		LIB decrypt_lib = LIB::OPENSSL_ARBITRARY_IO;
		
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


		byte* keyDup2 = (byte*)malloc(keyLen);
		byte* ivDup2 = (byte*)malloc(ivLen);
		memcpy(keyDup2, key, keyLen);
		memcpy(ivDup2, iv, ivLen);

		Cipher* p = new CBC<AES>(true);
		p->setKeyAndIV(key, keyLen, iv, ivLen);

		p->submitInput((byte*)(ptr_clear_text), 0, strlen(ptr_clear_text));

		p->endInput();

		byte* a = (byte*)OPENSSL_malloc(70);
		p->retrieveOutput(a, 0, 70);

		Cipher* p2 = new CBC<AES>(false);

		p2->setKeyAndIV(keyDup2, keyLen, ivDup2, ivLen);

		p2->submitInput(a, 0, 32);

		p2->endInput();

		byte* b = (byte*)OPENSSL_malloc(19);

		p2->retrieveOutput(b, 0, 19);

		OPENSSL_free(a);
		OPENSSL_free(b);
		/*
		OPENSSL_free(key);
		OPENSSL_free(iv);
		free(keyDup2);
		free(ivDup2);
		*/
		delete p;
		delete p2;
	}
}