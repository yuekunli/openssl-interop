#include<iostream>

typedef unsigned char byte;

namespace BYTE_BUFFERIZED_OPENSSL {
	byte* aes128_block_encrypt(byte* data, int data_len, byte* key);
	byte* aes128_block_decrypt(byte* data, int data_len, byte* key);
	byte* aes128_block_encrypt_incremental(byte* data, int data_len, byte* key);
	byte* aes128_block_decrypt_incremental(byte* data, int data_len, byte* key);
}


namespace OPENSSL_AES_ECB_TEST {

	void test1()
	{
		char plaintext[] = "BothellSaturday";

		byte* ciphertext = NULL, *recovered_plaintext = NULL;
		byte key[16] = {
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87
		};
		ciphertext = BYTE_BUFFERIZED_OPENSSL::aes128_block_encrypt((byte*)plaintext, 16, key);

		recovered_plaintext = BYTE_BUFFERIZED_OPENSSL::aes128_block_decrypt(ciphertext, 16, key);

		std::cout << (char*)recovered_plaintext << std::endl;

		free(ciphertext);
		free(recovered_plaintext);
	}


	void test2()
	{
		char plaintext[] = "abcdefghijklmnopqrstuvwxyzabcde";

		byte* ciphertext = NULL, * recovered_plaintext = NULL;
		byte key[16] = {
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87
		};
		ciphertext = BYTE_BUFFERIZED_OPENSSL::aes128_block_encrypt((byte*)plaintext, 32, key);

		recovered_plaintext = BYTE_BUFFERIZED_OPENSSL::aes128_block_decrypt(ciphertext, 32, key);

		std::cout << (char*)recovered_plaintext << std::endl;

		free(ciphertext);
		free(recovered_plaintext);
	}

	void test3()
	{
		char plaintext[] = "abcdefghijklmnopqrstuvwxyzabcde";

		byte* ciphertext = NULL, * recovered_plaintext = NULL;
		byte key[16] = {
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87
		};
		ciphertext = BYTE_BUFFERIZED_OPENSSL::aes128_block_encrypt((byte*)plaintext, 32, key);

		recovered_plaintext = BYTE_BUFFERIZED_OPENSSL::aes128_block_decrypt(ciphertext, 16, key);

		char recovered_text_with_termination[17];
		memset(recovered_text_with_termination, 0, 17);
		memcpy(recovered_text_with_termination, recovered_plaintext, 16);

		std::cout << (char*)recovered_text_with_termination << std::endl;

		free(ciphertext);
		free(recovered_plaintext);
	}


	void test4()
	{
		char plaintext[] = "abcdefghijklmnopqrstuvwxyzabcde";

		byte* ciphertext = NULL, * recovered_plaintext = NULL;
		byte key[16] = {
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87
		};
		ciphertext = BYTE_BUFFERIZED_OPENSSL::aes128_block_encrypt((byte*)plaintext, 32, key);

		recovered_plaintext = BYTE_BUFFERIZED_OPENSSL::aes128_block_decrypt(ciphertext+16, 16, key);

		std::cout << (char*)recovered_plaintext << std::endl;

		free(ciphertext);
		free(recovered_plaintext);
	}

	void test5()
	{
		char plaintext[] = "abcdefghijklmnopqrstuvwxyzabcde";

		byte* ciphertext = NULL, * recovered_plaintext = NULL;
		byte key[16] = {
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87
		};
		ciphertext = BYTE_BUFFERIZED_OPENSSL::aes128_block_encrypt_incremental((byte*)plaintext, 32, key);

		recovered_plaintext = BYTE_BUFFERIZED_OPENSSL::aes128_block_decrypt_incremental(ciphertext, 32, key);

		std::cout << (char*)recovered_plaintext << std::endl;

		free(ciphertext);
		free(recovered_plaintext);
	}
}