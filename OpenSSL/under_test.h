#pragma once

namespace AUX_TEST {
	void test1();
	void test2();
}

namespace CRYPTOPP_DEMO {
	void demo_ECIES_encrypt1();
	void demo_ECIES_encrypt2();
	void demo_ECIES_2();
}

namespace CRYPTOPP_EC_GEN_TEST {
	void ecdsa_generate_and_print_key_pair();
}

namespace INTEROP_TEST_ECIES {
	void test_ECIES();
}

namespace INTEROP_TEST_ECDSA {
	void test_ECDSA();
	void test_ECDSA_special_case();
}

namespace INTEROP_TEST_DH {
	void test_Diffie_Hellman();
}

namespace INTEROP_TEST_SYMMETRICCRYPT {
	void test_Symmetric_Cipher();
}

namespace INTEROP_TEST_CMAC {
	void test1();
	void test2();
	void test3();
	void test4();
}

namespace OPENSSL_AES_ECB_TEST {
	void test1();
	void test2();
	void test3();
	void test4();
	void test5();
}

namespace INTEROP_TEST_EAX {
	void test1();
	void test2();
	void test3();
	void test4();
}

namespace OPENSSL_ASN1_TEST {
	void numeric_dot_to_long_name();
	void encoded_oid_to_numeric_dot_to_long_name();
}

namespace OPENSSL_LIBCTX_PROVIDER_TEST {
	void initialize_fips_libctx();
	void cleanup_fips_libctx();
}

namespace OPENSSL_BIO_TEST {
	void read_from_BIO();
	void set_BIO_position();
}


namespace OPENSSL_ECDSA_SIG_CONVERT {
	void ecdsa_sig_generate_and_verify_keep_DER_format();
	void ecdsa_sig_generate_and_verify_makeshift_convert();
	void ecdsa_sig_generate_and_verify__makeshift_der2raw__openssl_raw2der();
	void ecdsa_sig_generate_and_verify__openssl_der2raw__makeshift_raw2der();
	void ecdsa_signature__convert_key_to_der__openssl_convert_sig();
}

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER {
	void test();
}

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER2 {
	void test();
}

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER3 {
	void test2();
}