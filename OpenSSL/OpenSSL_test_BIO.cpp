namespace BYTE_BUFFERIZED_OPENSSL {
	void read_from_BIO();
	void set_BIO_position();
}

namespace OPENSSL_TEST_BIO {
	void test1()
	{
		//BYTE_BUFFERIZED_OPENSSL::read_from_BIO();
		BYTE_BUFFERIZED_OPENSSL::set_BIO_position();
	}
}