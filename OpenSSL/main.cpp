#include "under_test.h"
#include <iostream>
#include <string>


namespace BASIC_TEST {
	void test1()
	{
		char b[] = "breakfast"; // 9 characters + '\0'

		std::string a(b, 10);  // using 10 bytes to initialize std::string
		// the '\0' will be included in 'a'. 

		std::cout << a.size() << "   " << a << std::endl;  // I won't see the '\0' when printing 'a'
		// If I use 5 bytes to initialize 'a', when I print 'a', it won't run over 5 bytes.
		// Therefore std::string knows the "content" of itself, even if there is '\0' in its content.
	}
}

int main()
{
	//INTEROP_TEST_ECIES::test_ECIES();

	//INTEROP_TEST_ECDSA::test_ECDSA();

	//INTEROP_TEST_DH::test_Diffie_Hellman();

	//INTEROP_TEST_SYMMETRICCRYPT::test_Symmetric_Cipher();

	//INTEROP_TEST_CMAC::test1();
	//INTEROP_TEST_CMAC::test2();
	//INTEROP_TEST_CMAC::test3();
	//INTEROP_TEST_CMAC::test4();

	//OPENSSL_AES_ECB_TEST::test1();
	//OPENSSL_AES_ECB_TEST::test2();
	//OPENSSL_AES_ECB_TEST::test3();
	//OPENSSL_AES_ECB_TEST::test4();
	//OPENSSL_AES_ECB_TEST::test5();

	//INTEROP_TEST_EAX::test3();
	//INTEROP_TEST_EAX::test4();

	//OPENSSL_ASN1_TEST::numeric_dot_to_long_name();
	//OPENSSL_ASN1_TEST::encoded_oid_to_numeric_dot_to_long_name();

	//OPENSSL_LIBCTX_PROVIDER_TEST::initialize_fips_libctx();
	//OPENSSL_LIBCTX_PROVIDER_TEST::cleanup_fips_libctx();

	//OPENSSL_BIO_TEST::read_from_BIO();
	//OPENSSL_BIO_TEST::set_BIO_position();

	//INTEROP_TEST_ARBITRARY_IO_CIPHER::test();

	INTEROP_TEST_ARBITRARY_IO_CIPHER2::test();
}
