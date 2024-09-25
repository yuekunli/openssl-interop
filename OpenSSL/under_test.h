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

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER {
	void test();
}

namespace INTEROP_TEST_ARBITRARY_IO_CIPHER2 {
	void test();
}