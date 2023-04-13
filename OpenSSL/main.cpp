#include "under_test.h"

int main()
{
	INTEROP_TEST_ECIES::test_ECIES();

	INTEROP_TEST_ECDSA::test_ECDSA();	

	INTEROP_TEST_DH::test_Diffie_Hellman();

	INTEROP_TEST_SYMMETRICCRYPT::test_Symmetric_Cipher();
}
