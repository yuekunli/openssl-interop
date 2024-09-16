#pragma once

#include <Windows.h>

namespace BYTE_BUFFERIZED_OPENSSL {

	// ===================
	//  lib context
	// ===================

	void initialize_fips_libctx();
	void cleanup_fips_libctx();


	// =========================
	// Random Number Generation
	// =========================

	byte RngGenerateByte();
	DWORD RngGenerateDword();
	LONGLONG RngGenerateQword();
	void RngFillByteArrayRegion(byte* pArray, int nStartingOffset, int nBytes);


	// ===========================
	// Secure Hash  (SHA-2)
	// ===========================

	struct SecureHashState_t;

	typedef struct SecureHashState_t SecureHashState;

	SecureHashState* SHInitialize(int hashingAlgorithm);

	int SHGetDigestLength(SecureHashState* pState);

	bool SHUpdate(SecureHashState* pState, byte input);

	bool SHUpdate(SecureHashState* pState, byte* input, int nOffset, int nLen);

	byte* SHDigest(SecureHashState* pState, int* pnByteArraySize);

	bool SHReset(SecureHashState* pState);

	bool SHCleanUp(SecureHashState* pState);

	byte* getSecureHash(int hashingAlgorithm, byte* pDataBuffer, int nDataBufferLength, int* pnSecureHashSize);




	// =====================================
	// Symmetric Encryption (AES) or DES3
	// =====================================

	struct SymmetricCipher_t;

	typedef struct SymmetricCipher_t SymmetricCipher;

	SymmetricCipher* CipherInitialize(int nAlgo, bool fEncrypt);

	bool CipherSetKeyAndInitialVector(SymmetricCipher* pSymCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

	bool CipherRelease(SymmetricCipher* pSymCipher);

	bool CipherReset(SymmetricCipher* pSymCipher);

	bool CipherSubmitInput(SymmetricCipher* pSymCipher, byte* pInput, int nOffset, int nLength);

	int CipherRetrieveOutput(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength);

	int CipherSkipBytes(SymmetricCipher* pSymCipher, int nToBeSkippedByteCount);

	int CipherInjectBytes(SymmetricCipher* pSymCipher, byte* pInjectBytes, int nOffset, int nInjectByteCount);

	bool CipherEndInput(SymmetricCipher* pSymCipher);

	bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pByteGenerationBuffer, int nBytesWanted);

	int getInitialVectorLength(int encryptionAlgo);

	int getEncryptedBufferSizeUsingJavaformat(int nEncrypAlog, int nInputSize);

	int getDecryptedBufferSizeUsingJavaformat(int nInputSize);

	byte* encryptBufferUsingJavaformat(int encrypAlgo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize);

	byte* decryptBufferUsingJavaformat(int algo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize);




	// ==================================
	// Diffie-Hellman Key Exchange
	// ==================================

	struct DHState_t;

	typedef struct DHState_t DHState;

	DHState* DhInitialize(int dhtype, char* pszRemotePartyParams);

	char* DhGetInitializationParameters(DHState* pState);

	byte* DhGetPublicKey(DHState* pState, int* pnPublicKeyLength);

	int DhCompleteHandshake(DHState* pState, byte* pRemotePublicKey, int nRemotePublicKeyLength);

	int DhRelease(DHState* pState);

	byte* DhGenerateAESKey(DHState* pState, int* pnAESKeyLength);




	// ============================
	//  ECDSA
	// ============================

	int DsaGenerateKeyPair(byte** ppPriKey, int* pnPriKeyLen, byte** ppPubKey, int* pnPubKeyLen);

	int DsaGenerateSignature(byte* pDataBuffer, int nDataBufferLength, byte* pPrivateKey, int nPrivateKeyLength, byte** ppSignature, int* pnSignatureLength);

	int DsaVerifySignature(byte* pDataBuffer, int nDataBufferLength, byte* pPublicKey, int nPublicKeyLength, byte* pSignature, int nSignatureLenght);



	// =======================
	// ECIES
	// =======================

	byte* DsaEncryptBuffer(byte* pPublicKey, int nPublicKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize);

	byte* DsaDecryptBuffer(byte* pPrivateKey, int nPrivateKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize);

}