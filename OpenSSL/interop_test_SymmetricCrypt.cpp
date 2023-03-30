#include "adaptiva_cryptopp.h"
#include "adaptiva_openssl.h"

#include <iostream>

namespace INTEROP_TEST_SYMMETRICCRYPT {
	char const* clearText = 
		"Kirkland is a city in King County, Washington, United States. "
		"A suburb east of Seattle, its population was 92,175 in the 2020 U.S. census "
		"which made it the sixth largest city in the county and "
		"the twelfth largest in the state.\n"
		"The city\'s downtown waterfront has restaurants, art galleries, "
		"a performing arts center, public parks, beaches, and a collection "
		"of public art, primarily bronze sculptures.\n"
		"Kirkland was the original home of the Seattle Seahawks; "
		"the NFL team\'s headquarters and training facility were located "
		"at the Lake Washington Shipyard (now Carillon Point) along Lake Washington "
		"for their first ten seasons (1976–85), then at nearby Northwest University "
		"through 2007. Warehouse chain Costco previously had its headquarters in Kirkland. "
		"While Costco is now headquartered in Issaquah, the city is the namesake of "
		"its \"Kirkland Signature\" store brand.";

	char const* clearText2 = "Kirkland is a city";

	void test1()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		ADAPTIVA_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = ADAPTIVA_CRYPTOPP::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = ADAPTIVA_OPENSSL::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

	void test2()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		ADAPTIVA_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = ADAPTIVA_OPENSSL::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText, strlen(clearText) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = ADAPTIVA_OPENSSL::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}


	void test3()
	{
		byte* key = NULL;
		int keyLen = 16;
		key = (byte*)malloc(keyLen);

		ADAPTIVA_CRYPTOPP::RngFillByteArrayRegion(key, 0, keyLen);

		byte* encryptedBuffer = NULL;
		int encryptedBufferSize = 0;
		encryptedBuffer = ADAPTIVA_OPENSSL::encryptBufferUsingJavaformat(1, key, keyLen, (byte*)clearText2, strlen(clearText2) + 1, &encryptedBufferSize);

		byte* decryptedBuffer = NULL;
		int decryptedBufferSize;
		decryptedBuffer = ADAPTIVA_CRYPTOPP::decryptBufferUsingJavaformat(1, key, keyLen, encryptedBuffer, encryptedBufferSize, &decryptedBufferSize);

		std::cout << decryptedBuffer << std::endl;

		if (key)
			free(key);
		if (encryptedBuffer)
			free(encryptedBuffer);
		if (decryptedBuffer)
			free(decryptedBuffer);
	}

}