
namespace BYTE_BUFFERIZED_OPENSSL {
	void initialize_fips_libctx();
	void cleanup_fips_libctx();
}

namespace OPENSSL_TEST_LIBCTX_PROVIDER {

	void test()
	{
		BYTE_BUFFERIZED_OPENSSL::initialize_fips_libctx();
		BYTE_BUFFERIZED_OPENSSL::cleanup_fips_libctx();
	}

}