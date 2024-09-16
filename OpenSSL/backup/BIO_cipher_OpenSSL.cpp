#include <stdint.h>
#include <cstring>
#include <string.h>
#include <iostream>



// OpenSSL headers
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/provider.h>



// Windows hearder
#include <Windows.h>
#include <winsock.h>


typedef unsigned char byte;


#define ___ENCRYPTION_ALGORITHM_AES256_CBC 1
#define ___ENCRYPTION_ALGORITHM_AES256_EAX 2
#define ___ENCRYPTION_ALGORITHM_AES256_GCM 3
#define ___ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC 4


#define ___BLOCK_SIZE_AES256_CBC  16
#define ___BLOCK_SIZE_AES256_EAX  16
#define ___BLOCK_SIZE_AES256_GCM  16
#define ___BLOCK_SIZE_TRIPLE_DES_CBC 8


#define ___IV_LENGTH_AES256_CBC 16
#define ___IV_LENGTH_AES256_EAX 256
#define ___IV_LENGTH_AES256_GCM 128
#define ___IV_LENGTH_TRIPLE_DES_CBC 8


#define ___KEY_TYPE_NONE 75


namespace BIO_CIPHER_OPENSSL {


	struct SymmetricCipher_t
	{
		int nAlgorithm;
		bool fEncrypt;

		int nBlockSize;

		BIO* pBIOOutput;
		BIO* pBIOCipher;
		bool fBioConnected;
	};

	typedef struct SymmetricCipher_t SymmetricCipher;
	typedef struct SymmetricCipher_t Cipher;

	bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pOut, int nBytesWanted)
	{
		int nBytesFilled = 0;

		EVP_MD* md = EVP_MD_fetch(NULL/*lib context*/, "SHA512", NULL/*prop queue*/);
		EVP_MD_CTX* ctx = EVP_MD_CTX_new();

		int nHashOutputSize = EVP_MD_get_size(md);
		byte* pHashOutput = (byte*)OPENSSL_zalloc(nHashOutputSize);
		EVP_DigestInit(ctx, md);
		EVP_DigestUpdate(ctx, pKeyMaterial, nKeyMaterialLength);
		unsigned int nLen;
		EVP_DigestFinal(ctx, pHashOutput, &nLen);
		while (nBytesFilled < nBytesWanted)
		{
			int canFill = min(nHashOutputSize, (nBytesWanted - nBytesFilled));
			memcpy(pOut + nBytesFilled, pHashOutput, canFill);
			nBytesFilled += canFill;
		}

		OPENSSL_free(pHashOutput);

		EVP_MD_free(md);
		EVP_MD_CTX_free(ctx);
		return true;
	}

	SymmetricCipher* CipherInitialize(int nAlgo, bool fEncrypt)
	{
		SymmetricCipher* pSymCipher = (SymmetricCipher*)OPENSSL_zalloc(sizeof(SymmetricCipher));
		pSymCipher->fEncrypt = fEncrypt;
		pSymCipher->nAlgorithm = nAlgo;
		pSymCipher->pBIOOutput = BIO_new(BIO_s_mem());
		pSymCipher->fBioConnected = false;
		pSymCipher->pBIOCipher = NULL;
		return pSymCipher;
	}

	bool CipherSetKeyAndInitialVector(SymmetricCipher* pSymCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
	{
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

		char const* pCipherName[] = {"", "AES-128-CBC", "AES-128-EAX", "AES-128-GCM", "DES-EDE3-CBC" };

		char const* pChosen = pCipherName[pSymCipher->nAlgorithm];

		int const blockSize[] = {0, 16, 16, 16, 8};

		pSymCipher->nBlockSize = blockSize[pSymCipher->nAlgorithm];

		EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, pChosen, NULL/*prop queue*/);

		BIO* b = BIO_new(BIO_f_cipher());

		BIO_set_cipher(b, evp_cipher, pKey, pIV, (int)(pSymCipher->fEncrypt));

		BIO_push(b, pSymCipher->pBIOOutput);
		pSymCipher->fBioConnected = true;
		pSymCipher->pBIOCipher = b;
		return true;
	}

	bool CipherRelease(SymmetricCipher* pSymCipher)
	{
		if (pSymCipher->fBioConnected)
		{
			BIO_free_all(pSymCipher->pBIOCipher);
		}
		else
		{
			if (pSymCipher->pBIOOutput != NULL)
			{
				BIO_set_flags(pSymCipher->pBIOOutput, BIO_FLAGS_MEM_RDONLY); // very necessary
				BIO_free(pSymCipher->pBIOOutput);
			}
			if (pSymCipher->pBIOCipher != NULL)
			{
				BIO_free(pSymCipher->pBIOCipher);
			}
		}
		OPENSSL_free(pSymCipher);
		return true;
	}

	bool CipherSubmitInput(SymmetricCipher* pSymCipher, byte* pInput, int nOffset, int nLength)
	{
		BIO_write(pSymCipher->pBIOCipher, pInput + nOffset, nLength);
		return true;
	}

	bool CipherEndInput(SymmetricCipher* pSymCipher)
	{
		BIO_flush(pSymCipher->pBIOCipher);
		if (pSymCipher->fEncrypt && pSymCipher->nAlgorithm == ___ENCRYPTION_ALGORITHM_AES256_GCM)
		{
			EVP_CIPHER_CTX* ctx;
			BIO_get_cipher_ctx(pSymCipher->pBIOCipher, &ctx);
			byte tag[16];
			OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
			params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
			EVP_CIPHER_CTX_get_params(ctx, params);
			BIO_write(pSymCipher->pBIOOutput, tag, 16);
		}
		return true;
	}

	static bool CipherRetrieveEncryptionOutput_AES_GCM(SymmetricCipher* pSymCipher)
	{
		return true;
	}

	int CipherRetrieveOutput(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength)
	{
		int bytesRead = BIO_read(pSymCipher->pBIOOutput, pOutput + nOffset, nLength);
		return bytesRead;
	}
}