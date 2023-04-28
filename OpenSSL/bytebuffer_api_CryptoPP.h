#pragma once

#include <Windows.h>

#include "config.h" // from Crypto++

namespace BYTE_BUFFERIZED_CRYPTOPP {


	// =========================
	//  Random number
	// =========================

	byte RngGenerateByte();
	DWORD RngGenerateDword();
	LONGLONG RngGenerateQword();
	void RngFillByteArrayRegion(byte* pArray, int nStartingOffset, int nBytes);
	bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pByteGenerationBuffer, int nByteGenerationLength);


	// =======================
	//  Secure Hash
	// =======================

	typedef struct SecureHashState_t SecureHashState;

	SecureHashState* SHInitialize(int algo);

	int SHGetDigestLength(SecureHashState* pState);

	bool SHUpdate(SecureHashState* pState, byte input);

	bool SHUpdate(SecureHashState* pState, byte* input, int nOffset, int nLen);

	byte* SHDigest(SecureHashState* pState, int* pnByteArraySize);

	bool SHReset(SecureHashState* pState);

	bool SHCleanUp(SecureHashState* pState);

	byte* getSecureHash(int algo, byte* pDataBuffer, int nDataBufferLength, int* pnSecureHashSize);



	// =======================
	//  Diffie-Hellman
	// =======================

	typedef struct DHState_t DHState;

	DHState* DhInitialize(int dhtype, char* pszRemotePartyParams);
	char* DhGetInitializationParameters(DHState* pState);
	byte* DhGetPublicKey(DHState* pState, int* pnPublicKeyLength);
	int DhCompleteHandshake(DHState* pState, byte* pRemotePublicKey, int nRemotePublicKeyLength);
	byte* DhGenerateAESKey(DHState* pState, int* pnAESKeyLength);
	int DhRelease(DHState* pState);


	// ====================
	//  Symmetric Cipher
	// ====================

	typedef struct Cipher_t Cipher;

	Cipher* CipherInitialize(int nAlgo, bool fEn);

	bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

	bool CipherRelease(Cipher* pCipher);

	bool CipherReset(Cipher* pCipher);

	bool CipherSubmitInput(Cipher* pC, byte* pIn, int nOffset, int nLength);

	int CipherRetrieveOutput(Cipher* pC, byte* pOut, int nOffset, int nLength);

	int CipherSkipBytes(Cipher* pCipher, int nSkippedByteCount);

	int CipherInjectBytes(Cipher* pC, byte* pInject, int nOffset, int nCount);

	bool CipherEndInput(Cipher* pC);

	byte* encryptBufferUsingJavaformat(int algo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize);

	byte* decryptBufferUsingJavaformat(int algo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize);

	int getDecryptedBufferSizeUsingJavaformat(int nInputSize);

	int getEncryptedBufferSizeUsingJavaformat(int algo, int nInputSize);

	int getInitialVectorLength(int algo);

	byte* generateEncryptionKey(int algo, int* pnEncryptionKeyLength);




	// ======================================
	//  Elliptic Curve Public/Private Key
	// ======================================

	int DsaGenerateKeyPair(byte** pri, int* priLen, byte** pub, int* pubLen);



	// ==============
	//  ECDSA
	// ==============

	int DsaGenerateSignature(byte* pDataBuffer, int nDataBufferLength, byte* pPrivateKey, int nPrivateKeyLength, byte** ppSignature, int* pnSignatureLength);

	int DsaVerifySignature(byte* pDataBuffer, int nDataBufferLength, byte* pPublicKey, int nPublicKeyLength, byte* pSignature, int nSignatureLength);




	// =============
	//  ECIES
	// =============

	byte* DsaEncryptBuffer(byte* pub, int pubLen, byte* data, int dataLen, int* encryptedBufferSize);

	byte* DsaDecryptBuffer(byte* pri, int priLen, byte* data, int dataLen, int* decryptedBufferSize);



	// ==============
	//  CMAC
	// ==============

	byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size);

	bool verifyCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, byte* tag, int tag_size);

}