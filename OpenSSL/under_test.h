#pragma once

namespace Test_ECIES_1 {
	void Test_ECIES_encrypt1();
	void Test_ECIES_encrypt2();
}

namespace Test_ECIES_2 {
	void Run_Test_ECIES_2();
}

namespace INTEROP_TEST_ECIES {
	void test_static_keys_cryptopp_encrypt_openssl_decrypt();
	void test_static_keys_openssl_encrypt_cryptopp_decrypt();
	void test_cryptopp_generate_keys_cryptopp_encrypt_openssl_decrypt();
	void test_cryptopp_generate_keys_openssl_encrypt_cryptopp_decrypt();
	void test_cryptopp_generate_keys_openssl_encrypt_openssl_decrypt();
	void test_openssl_generate_keys_cryptopp_encrypt_openssl_decrypt();
	void test_openssl_generate_keys_openssl_encrypt_cryptopp_decrypt();
	void test_openssl_generate_keys_openssl_encrypt_openssl_decrypt();
	void test_openssl_generate_keys_cryptopp_encrypt_cryptopp_decrypt();
}

namespace INTEROP_TEST_ECDSA {
	void test_ECDSA();
}

namespace INTEROP_TEST_DH {
	void test_DL1024_cryptopp_init_openssl_respond();
	void test_DL2048_cryptopp_init_openssl_respond();
	void test_DL2048_openssl_init_cryptopp_respond();
	void test_DL1024_cryptopp_init_cryptopp_respond();
	void test_DL2048_named_group_openssl_init_openssl_respond();
	void test_EC_p256_curve_openssl_init_openssl_respond();
	void test_EC_p256_curve_cryptopp_init_openssl_respond();
	void test_EC_p256_curve_openssl_init_cryptopp_respond();
}

namespace INTEROP_TEST_SYMMETRICCRYPT {
	void test_Symmetric_Cipher();
}

namespace AUX_TEST {
	void test1();
	void test2();
}