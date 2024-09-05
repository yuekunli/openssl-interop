#pragma once

#include <Windows.h>

namespace BIO_CIPHER_OPENSSL {
	typedef struct SymmetricCipher_t SymmetricCipher;
	typedef struct SymmetricCipher_t Cipher;

	bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pOut, int nBytesWanted);

	SymmetricCipher* CipherInitialize(int nAlgo, bool fEncrypt);

	bool CipherSetKeyAndInitialVector(SymmetricCipher* pSymCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

	bool CipherRelease(SymmetricCipher* pSymCipher);

	bool CipherSubmitInput(SymmetricCipher* pSymCipher, byte* pInput, int nOffset, int nLength);

	bool CipherEndInput(SymmetricCipher* pSymCipher);

	static bool CipherRetrieveEncryptionOutput_AES_GCM(SymmetricCipher* pSymCipher);

	int CipherRetrieveOutput(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength);
}