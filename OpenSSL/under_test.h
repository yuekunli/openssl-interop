#pragma once

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
	void test12();
	void test13();
}

namespace AUX_TEST {
	void test1();
	void test2();
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
	void openssl_asn1_test1();
	void openssl_asn1_test2();
}

namespace OPENSSL_TEST_LIBCTX_PROVIDER {
	void test();
}

namespace OPENSSL_TEST_BIO {
	void test1();
}