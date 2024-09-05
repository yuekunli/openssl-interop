#include <Windows.h>

#include "osrng.h"
#include "integer.h"
#include "nbtheory.h"
#include "dh.h"
#include "secblock.h"
#include "asn.h"
#include "oids.h"
#include "eccrypto.h"
#include "ecp.h"
#include "modes.h"
#include "des.h"
#include "eax.h"
#include "gcm.h"
#include "filters.h"
#include "files.h"
#include "cryptlib.h"
#include "aes.h"


#include <iostream>

using namespace std;

using namespace CryptoPP;

namespace AUXILIARY {
	char* base32Encode(byte* p, size_t l);
	byte* base32Decode(char* pszIn, int* outSize);
}

namespace BYTE_BUFFERIZED_CRYPTOPP {

	//======================
	// forward declaration
	//======================
	byte* getSecureHash(int algo, byte* pDataBuffer, int nDataBufferLength, int* pnSecureHashSize);
	int getDecryptedBufferSizeUsingJavaformat(int nInputSize);
	int getEncryptedBufferSizeUsingJavaformat(int algo, int nInputSize);
	int getInitialVectorLength(int algo);

	//===================
	//  global variable
	//===================
	static AutoSeededRandomPool _grng;

	static OID _gCURVE = CryptoPP::ASN1::secp256r1();



	// ======================================
	//  DH
	// ======================================

	struct DHState_t
	{
		int dhtype;
		SecByteBlock* pPrivateKey;
		SecByteBlock* pPublicKey;
		SecByteBlock* pSharedSecret;
		bool fHandshakeCompleted;
		char* pszInitializationParameters;
		byte* sharedSecretBinary;

		DH* pDH;
		ECDH<ECP>::Domain* pEllipticalDh;
	};
	typedef struct DHState_t DHState;

	static char* pvtGetInitializationParameters(Integer* piPrime, Integer* piGenerator)
	{
		//char* pszRetVal = NULL;
		int nPrimeBufferSize;
		byte* pPrimeBuffer = NULL;
		char* pszEncodedPrime = NULL;
		int nGeneratorBufferSize;
		byte* pGeneratorBuffer = NULL;
		char* pszEncodedGenerator = NULL;

		nPrimeBufferSize = piPrime->MinEncodedSize();
		pPrimeBuffer = (byte*)malloc(nPrimeBufferSize);
		piPrime->Encode(pPrimeBuffer, nPrimeBufferSize);
		pszEncodedPrime = AUXILIARY::base32Encode(pPrimeBuffer, nPrimeBufferSize);

		nGeneratorBufferSize = piGenerator->MinEncodedSize();
		pGeneratorBuffer = (byte*)malloc(nGeneratorBufferSize);
		piGenerator->Encode(pGeneratorBuffer, nGeneratorBufferSize);
		pszEncodedGenerator = AUXILIARY::base32Encode(pGeneratorBuffer, nGeneratorBufferSize);

		// get formatted string

		size_t l1 = strlen(pszEncodedPrime);
		size_t l2 = strlen(pszEncodedGenerator);
		char* out = (char*)malloc(l1 + l2 + 2);

		char* p = out;

		memcpy(p, pszEncodedPrime, l1);
		p += l1;
		*p++ = ',';
		memcpy(p, pszEncodedGenerator, l2);
		p += l2;

		*p = '\0';

		free(pPrimeBuffer);
		free(pGeneratorBuffer);
		free(pszEncodedGenerator);
		free(pszEncodedPrime);

		return out;
	}

	static bool pvtGetPrimeAndGenerator(char* pszInitializationParameter, Integer** ppiPrime, Integer** ppiGenerator)
	{
		Integer* piPrime = NULL;
		Integer* piGenerator = NULL;
		char* pPrime;
		char* pGenerator;
		char* pComma;
		byte* decodedPrime;
		int decodedPrimeSize;
		byte* decodedGenerator;
		int decodedGeneratorSize;

		size_t l = strlen(pszInitializationParameter);

		pComma = strchr(pszInitializationParameter, ',');

		pPrime = pszInitializationParameter;
		*pComma = '\0';
		pGenerator = pComma + 1;

		//  a  b  c  ,  d  e  f  g  h  \0

		decodedPrime = AUXILIARY::base32Decode(pPrime, &decodedPrimeSize);

		piPrime = new Integer();
		piPrime->Decode((byte*)decodedPrime, decodedPrimeSize);

		decodedGenerator = AUXILIARY::base32Decode(pGenerator, &decodedGeneratorSize);

		piGenerator = new Integer();
		piGenerator->Decode((byte*)decodedGenerator, decodedGeneratorSize);

		*ppiPrime = piPrime;
		*ppiGenerator = piGenerator;

		return true;
	}

	DHState* DhInitialize(int dhtype, char* pszRemotePartyParams)
	{
		int nKeySize;
		DHState* ret = NULL;

		if (dhtype == 1)
		{
			nKeySize = 1024;
		}
		else if (dhtype == 2)
		{
			nKeySize = 2048;
		}

		ret = (DHState*)malloc(sizeof(DHState));
		memset(ret, 0, sizeof(DHState));

		ret->dhtype = dhtype;

		if (pszRemotePartyParams != NULL)
		{
			size_t l = strlen(pszRemotePartyParams) + 1;
			ret->pszInitializationParameters = (char*)malloc(l);
			memcpy(ret->pszInitializationParameters, pszRemotePartyParams, l);
		}

		if (dhtype == 1 || dhtype == 2)
		{
			// discrete logarithm DH

			ret->pDH = new DH();

			if (pszRemotePartyParams == NULL)
			{
				// Alice initiating DH

				if (dhtype == 1)
				{

					Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
						"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
						"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
						"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
						"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
						"DF1FB2BC2E4A4371");

					Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
						"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
						"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
						"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
						"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
						"855E6EEB22B3B2E5");

					Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");


					//ret->pDH->AccessGroupParameters().GenerateRandomWithKeySize(_grng, nKeySize);

					ret->pDH->AccessGroupParameters().Initialize(p, q, g);

					Integer iPrime = ret->pDH->GetGroupParameters().GetModulus();
					Integer iGenerator = ret->pDH->GetGroupParameters().GetGenerator();

					ret->pszInitializationParameters = pvtGetInitializationParameters(&iPrime, &iGenerator);
				}
				else if (dhtype == 2)
				{
					Integer p(
						"0x"
						"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
						"A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
						"D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
						"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
						"BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
						"AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
						"9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
						"C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF");

					Integer g("0x02");

					Integer q(
						"0x"
						"7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4A"
						"D4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD"
						"69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49A"
						"CC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD"
						"5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA"
						"572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0"
						"C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002"
						"E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF"
					);

					ret->pDH->AccessGroupParameters().Initialize(p, q, g);

					Integer iPrime = ret->pDH->GetGroupParameters().GetModulus();
					Integer iGenerator = ret->pDH->GetGroupParameters().GetGenerator();

					ret->pszInitializationParameters = pvtGetInitializationParameters(&iPrime, &iGenerator);
				}
			}
			else
			{
				// Bob responding to DH
				Integer* piPrime;
				Integer* piGenerator;
				pvtGetPrimeAndGenerator(pszRemotePartyParams, &piPrime, &piGenerator);
				ret->pDH->AccessGroupParameters().Initialize(*piPrime, *piGenerator);

				delete piPrime;
				delete piGenerator;
			}

			ret->pPrivateKey = new SecByteBlock(ret->pDH->PrivateKeyLength());
			ret->pPublicKey = new SecByteBlock(ret->pDH->PublicKeyLength());

			ret->pDH->GenerateKeyPair(_grng, *(ret->pPrivateKey), *(ret->pPublicKey));

		}
		else
		{
			// elliptic curve DH

			ret->pEllipticalDh = new ECDH<ECP>::Domain(_gCURVE);
			ret->pPrivateKey = new SecByteBlock(ret->pEllipticalDh->PrivateKeyLength());
			ret->pPublicKey = new SecByteBlock(ret->pEllipticalDh->PublicKeyLength());
			ret->pEllipticalDh->GenerateKeyPair(_grng, *(ret->pPrivateKey), *(ret->pPublicKey));

		}
		return ret;
	}

	char* DhGetInitializationParameters(DHState* pState)
	{
		char* p = NULL;
		size_t l = strlen(pState->pszInitializationParameters) + 1;
		p = (char*)malloc(l);
		memcpy(p, pState->pszInitializationParameters, l);
		return p;
	}

	byte* DhGetPublicKey(DHState* pState, int* pnPublicKeyLength)
	{
		byte* ret = NULL;

		ret = (byte*)malloc(pState->pPublicKey->SizeInBytes());

		memcpy(ret, pState->pPublicKey->BytePtr(), pState->pPublicKey->SizeInBytes());
		*pnPublicKeyLength = pState->pPublicKey->SizeInBytes();

		return ret;
	}

	int DhCompleteHandshake(DHState* pState, byte* pRemotePublicKey, int nRemotePublicKeyLength)
	{
		SecByteBlock remotePublicKey(nRemotePublicKeyLength);

		remotePublicKey.Assign(pRemotePublicKey, nRemotePublicKeyLength);

		if (pState->pDH != NULL)
		{
			pState->pSharedSecret = new SecByteBlock(pState->pDH->AgreedValueLength());
			bool ret;
			ret = pState->pDH->Agree(*(pState->pSharedSecret), *(pState->pPrivateKey), remotePublicKey); // Dereferencing SecByteBlock gives a byte array
			if (!ret)
			{
				std::cout << "Agree Failed" << std::endl;
				return 1;
			}
			size_t l = pState->pSharedSecret->SizeInBytes();
			byte* p = (byte*)malloc(l);
			memcpy(p, pState->pSharedSecret->BytePtr(), l);
			pState->sharedSecretBinary = p;
			pState->fHandshakeCompleted = true;
		}
		else if (pState->pEllipticalDh != NULL)
		{
			pState->pSharedSecret = new SecByteBlock(pState->pEllipticalDh->AgreedValueLength());
			pState->pEllipticalDh->Agree(*(pState->pSharedSecret), *(pState->pPrivateKey), remotePublicKey);
			pState->fHandshakeCompleted = true;
		}

		return 0;
	}

	byte* DhGenerateAESKey(DHState* pState, int* pnAESKeyLength)
	{
		byte* ret = NULL;

		SecByteBlock AESkey(SHA256::DIGESTSIZE);

		SHA256().CalculateDigest(AESkey, *(pState->pSharedSecret), pState->pSharedSecret->SizeInBytes());

		ret = (byte*)malloc(AESkey.SizeInBytes());
		memcpy(ret, AESkey.BytePtr(), AESkey.SizeInBytes());
		*pnAESKeyLength = AESkey.SizeInBytes();

		return ret;
	}

	int DhRelease(DHState* pState)
	{
		if (pState != NULL)
		{
			if (pState->pEllipticalDh != NULL)
				delete pState->pEllipticalDh;

			if (pState->pDH != NULL)
				delete pState->pDH;

			if (pState->pPrivateKey != NULL)
				delete pState->pPrivateKey;

			if (pState->pPublicKey != NULL)
				delete pState->pPublicKey;

			if (pState->pSharedSecret != NULL)
				delete pState->pSharedSecret;

			if (pState->pszInitializationParameters != NULL)
				free(pState->pszInitializationParameters);

			free(pState);
		}
		return 0;
	}



	// ================================
	//  Random number
	// ================================

	byte RngGenerateByte()
	{
		byte ret;
		ret = _grng.GenerateByte();

		return ret;
	}

	DWORD RngGenerateDword()
	{
		return _grng.GenerateWord32();
	}

	LONGLONG RngGenerateQword()
	{
		LARGE_INTEGER x;

		x.LowPart = _grng.GenerateWord32();
		x.HighPart = _grng.GenerateWord32();

		return x.QuadPart;
	}

	void RngFillByteArrayRegion(byte* pArray, int nStartingOffset, int nBytes)
	{
		_grng.GenerateBlock(pArray + nStartingOffset, nBytes);
	}

	bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pByteGenerationBuffer, int nByteGenerationLength)
	{
		int nBytesGenerated = 0;
		while (nBytesGenerated < nByteGenerationLength)
		{
			int nSecureHashSize;
			byte* pSecureHash = getSecureHash(3 /*com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512*/, pKeyMaterial, nKeyMaterialLength, &nSecureHashSize);
			memmove(pByteGenerationBuffer + nBytesGenerated, pSecureHash, min(nSecureHashSize, (nByteGenerationLength - nBytesGenerated)));
			free(pSecureHash);
			nBytesGenerated += nSecureHashSize;
		}
		return true;
	}



	// ============================
	//  Secure Hash
	// ============================

	struct SecureHashState_t
	{
		int hashingAlgo;
		SHA256* pSha256;
		SHA384* pSha384;
		SHA512* pSha512;
		int nSecureHashLength;
	};

	typedef struct SecureHashState_t SecureHashState;

	SecureHashState* SHInitialize(int algo)
	{
		SecureHashState* pState = NULL;

		pState = (SecureHashState*)calloc(sizeof(SecureHashState), sizeof(char));
		pState->hashingAlgo = algo;

		switch (pState->hashingAlgo)
		{
		case 1:
			pState->pSha256 = new SHA256();
			pState->nSecureHashLength = pState->pSha256->DigestSize();
			break;
		case 2:
			pState->pSha384 = new SHA384();
			pState->nSecureHashLength = pState->pSha384->DigestSize();
			break;
		case 3:
			pState->pSha512 = new SHA512();
			pState->nSecureHashLength = pState->pSha512->DigestSize();
			break;
		default:
			free(pState);
			pState = NULL;
			break;
		}
		return pState;
	}

	int SHGetDigestLength(SecureHashState* pState)
	{
		if (pState != NULL)
			return pState->nSecureHashLength;

		return 0;
	}

	bool SHUpdate(SecureHashState* pState, byte input)
	{
		if (pState != NULL)
		{
			switch (pState->hashingAlgo)
			{
			case 1:
				pState->pSha256->Update(&input, 1);
				break;
			case 2:
				pState->pSha384->Update(&input, 1);
				break;
			case 3:
				pState->pSha512->Update(&input, 1);
				break;
			default:
				break;
			}
		}
		return true;
	}

	bool SHUpdate(SecureHashState* pState, byte* input, int nOffset, int nLen)
	{
		switch (pState->hashingAlgo)
		{
		case 1:
			pState->pSha256->Update(input + nOffset, nLen);
			break;
		case 2:
			pState->pSha384->Update(input + nOffset, nLen);
			break;
		case 3:
			pState->pSha512->Update(input + nOffset, nLen);
			break;
		default:
			break;
		}
		return true;
	}

	byte* SHDigest(SecureHashState* pState, int* pnByteArraySize)
	{
		byte* digest;

		digest = (byte*)malloc(pState->nSecureHashLength);

		switch (pState->hashingAlgo)
		{
		case 1:
			pState->pSha256->Final(digest);
			break;
		case 2:
			pState->pSha384->Final(digest);
			break;
		case 3:
			pState->pSha512->Final(digest);
			break;
		default:
			break;
		}

		*pnByteArraySize = pState->nSecureHashLength;
		return digest;
	}

	bool SHReset(SecureHashState* pState)
	{
		if (pState != NULL)
		{
			switch (pState->hashingAlgo)
			{
			case 1:
				pState->pSha256->Restart();
				break;
			case 2:
				pState->pSha384->Restart();
				break;
			case 3:
				pState->pSha512->Restart();
				break;
			default:
				break;
			}
			return true;
		}
		return false;
	}

	bool SHCleanUp(SecureHashState* pState)
	{
		if (pState != NULL)
		{
			if (pState->pSha256 != NULL)
				delete pState->pSha256;

			if (pState->pSha384 != NULL)
				delete pState->pSha384;

			if (pState->pSha512 != NULL)
				delete pState->pSha512;

			free(pState);
		}
		return true;
	}

	byte* getSecureHash(int algo, byte* pDataBuffer, int nDataBufferLength, int* pnSecureHashSize)
	{
		byte* pRet = NULL;
		SecureHashState* shState = NULL;

		shState = SHInitialize(algo);

		SHUpdate(shState, pDataBuffer, 0, nDataBufferLength);

		pRet = SHDigest(shState, pnSecureHashSize);

		return pRet;
	}



	// ===========================
	//  symmetric encryption
	// ===========================

	struct Cipher_t
	{
		int nAlgorithm;
		bool fEncrypt;
		byte* pKey;
		int nKeyLength;
		byte* pInitialVector;
		int nInitialVectorLength;

		int nBytesToBeSkipped;
		int nBytesToBeInjected;
		int nBytesAlreadyInjected;
		byte* pBytesToBeInjected;

		int nBlockSize;

		CBC_Mode<AES>::Encryption* pEncryptionAesCbc;
		EAX<AES>::Encryption* pEncryptionAesEax;
		GCM<AES>::Encryption* pEncryptionAesGcm;
		CBC_Mode<DES_EDE3>::Encryption* pEncryption3DesCbc;

		CBC_Mode<AES>::Decryption* pDecryptionAesCbc;
		EAX<AES>::Decryption* pDecryptionAesEax;
		GCM<AES>::Decryption* pDecryptionAesGcm;
		CBC_Mode<DES_EDE3>::Decryption* pDecryption3DesCbc;

		StreamTransformationFilter* pStream;
		AuthenticatedEncryptionFilter* pAuthEncryptionFilter;
		AuthenticatedDecryptionFilter* pAuthDecryptionFilter;

	};

	typedef struct Cipher_t Cipher;

	Cipher* CipherInitialize(int nAlgo, bool fEn)
	{
		Cipher* pRet;

		pRet = (Cipher*)calloc(sizeof(Cipher), sizeof(char));

		pRet->nAlgorithm = nAlgo;
		pRet->fEncrypt = fEn;

		if (fEn == true)
		{
			switch (nAlgo)
			{
			case 1:
				pRet->pEncryptionAesCbc = new CBC_Mode<AES>::Encryption();
				pRet->pStream = new StreamTransformationFilter(*(pRet->pEncryptionAesCbc));
				pRet->nBlockSize = 16;
				break;
			case 2:
				pRet->pEncryptionAesEax = new EAX<AES>::Encryption();
				pRet->pAuthEncryptionFilter = new AuthenticatedEncryptionFilter(*(pRet->pEncryptionAesEax));
				pRet->nBlockSize = 16;
				break;
			case 3:
				pRet->pEncryptionAesGcm = new GCM<AES>::Encryption();
				pRet->pAuthEncryptionFilter = new AuthenticatedEncryptionFilter(*(pRet->pEncryptionAesGcm));
				pRet->nBlockSize = 16;
				break;
			case 4:
				pRet->pEncryption3DesCbc = new CBC_Mode<DES_EDE3>::Encryption();
				pRet->pStream = new StreamTransformationFilter(*(pRet->pEncryption3DesCbc));
				pRet->nBlockSize = 8;
				break;
			}
		}
		else
		{
			switch (nAlgo)
			{
			case 1:
				pRet->pDecryptionAesCbc = new CBC_Mode<AES>::Decryption();
				pRet->pStream = new StreamTransformationFilter(*(pRet->pDecryptionAesCbc));
				pRet->nBlockSize = 16;
				break;
			case 2:
				pRet->pDecryptionAesEax = new EAX<AES>::Decryption();
				pRet->pAuthDecryptionFilter = new AuthenticatedDecryptionFilter(*(pRet->pDecryptionAesEax));
				pRet->nBlockSize = 16;
				break;
			case 3:
				pRet->pDecryptionAesGcm = new GCM<AES>::Decryption();
				pRet->pAuthDecryptionFilter = new AuthenticatedDecryptionFilter(*(pRet->pDecryptionAesGcm));
				pRet->nBlockSize = 16;
				break;
			case 4:
				pRet->pDecryption3DesCbc = new CBC_Mode<DES_EDE3>::Decryption();
				pRet->pStream = new StreamTransformationFilter(*(pRet->pDecryption3DesCbc));
				pRet->nBlockSize = 8;
				break;
			}
		}
		return pRet;
	}

	bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
	{
		pCipher->pKey = pKey;
		pCipher->nKeyLength = nKeyLength;
		pCipher->pInitialVector = pIV;
		pCipher->nInitialVectorLength = nIVLength;

		if (pCipher->fEncrypt)
		{
			switch (pCipher->nAlgorithm)
			{
			case 1:
				pCipher->pEncryptionAesCbc->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 2:
				pCipher->pEncryptionAesEax->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 3:
				pCipher->pEncryptionAesGcm->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 4:
				pCipher->pEncryption3DesCbc->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			}
		}
		else
		{
			switch (pCipher->nAlgorithm)
			{
			case 1:
				pCipher->pDecryptionAesCbc->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 2:
				pCipher->pDecryptionAesEax->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 3:
				pCipher->pDecryptionAesGcm->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			case 4:
				pCipher->pDecryption3DesCbc->SetKeyWithIV(pKey, nKeyLength, pIV, nIVLength);
				break;
			}
		}
		return true;
	}

	bool CipherRelease(Cipher* pCipher)
	{
		if (pCipher != NULL)
		{
			if (pCipher->pKey != NULL)
				free(pCipher->pKey);

			if (pCipher->pInitialVector != NULL)
				free(pCipher->pInitialVector);

			if (pCipher->pBytesToBeInjected != NULL)
				free(pCipher->pBytesToBeInjected);


			if (pCipher->pEncryptionAesCbc != NULL)
				delete pCipher->pEncryptionAesCbc;

			if (pCipher->pEncryptionAesEax != NULL)
				delete pCipher->pEncryptionAesEax;

			if (pCipher->pEncryptionAesGcm != NULL)
				delete pCipher->pEncryptionAesGcm;

			if (pCipher->pEncryption3DesCbc != NULL)
				delete pCipher->pEncryption3DesCbc;


			if (pCipher->pDecryptionAesCbc != NULL)
				delete pCipher->pDecryptionAesCbc;

			if (pCipher->pDecryptionAesEax != NULL)
				delete pCipher->pDecryptionAesEax;

			if (pCipher->pDecryptionAesGcm != NULL)
				delete pCipher->pDecryptionAesGcm;

			if (pCipher->pDecryption3DesCbc != NULL)
				delete pCipher->pDecryption3DesCbc;

			free(pCipher);
		}
		return true;
	}

	bool CipherReset(Cipher* pCipher)
	{
		if (pCipher != NULL)
		{
			if (pCipher->pEncryptionAesCbc)
				pCipher->pEncryptionAesCbc->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pEncryptionAesEax)
				pCipher->pEncryptionAesEax->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pEncryptionAesGcm)
				pCipher->pEncryptionAesGcm->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pEncryption3DesCbc)
				pCipher->pEncryption3DesCbc->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pDecryptionAesCbc)
				pCipher->pDecryptionAesCbc->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pDecryptionAesEax)
				pCipher->pDecryptionAesEax->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pDecryptionAesGcm)
				pCipher->pDecryptionAesGcm->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			else if (pCipher->pDecryption3DesCbc)
				pCipher->pDecryption3DesCbc->SetKeyWithIV(pCipher->pKey, pCipher->nKeyLength, pCipher->pInitialVector, pCipher->nInitialVectorLength);

			pCipher->nBytesToBeSkipped = 0;
			pCipher->nBytesToBeInjected = 0;
			pCipher->nBytesAlreadyInjected = 0;
			free(pCipher->pBytesToBeInjected);
			pCipher->pBytesToBeInjected = NULL;

			return true;
		}
		return false;
	}

	bool CipherSubmitInput(Cipher* pC, byte *pIn, int nOffset, int nLength)
	{
		if (pC->pStream != NULL)
			pC->pStream->Put(pIn + nOffset, nLength);

		else if (pC->pAuthEncryptionFilter != NULL)
			pC->pAuthEncryptionFilter->Put(pIn + nOffset, nLength);

		else if (pC->pAuthDecryptionFilter != NULL)
			pC->pAuthDecryptionFilter->Put(pIn + nOffset, nLength);

		return true;
	}

	int CipherRetrieveOutput(Cipher* pC, byte* pOut, int nOffset, int nLength)
	{
		int bytesWritten = 0;

		while (pC->nBytesToBeSkipped > 0)
		{
			byte b, & refB = b;
			int skipped = 0;

			if (pC->pStream != NULL)
				skipped = pC->pStream->Get(b);
			else if (pC->pAuthEncryptionFilter != NULL)
				skipped = pC->pAuthEncryptionFilter->Get(b);
			else if (pC->pAuthDecryptionFilter != NULL)
				skipped = pC->pAuthDecryptionFilter->Get(b);

			if (skipped == 0)
				return 0;

			(pC->nBytesToBeSkipped)--;
		}

		int nBytesInjected = 0;
		while (pC->nBytesToBeInjected > pC->nBytesAlreadyInjected && nLength > nBytesInjected)
		{
			pOut[nOffset + nBytesInjected] = pC->pBytesToBeInjected[pC->nBytesAlreadyInjected];
			nBytesInjected++;
			(pC->nBytesAlreadyInjected)++;
			bytesWritten++;

		}

		if (nLength > nBytesInjected)
		{
			if (pC->pStream != NULL)
				bytesWritten += pC->pStream->Get(pOut + nOffset + nBytesInjected, nLength - nBytesInjected);

			else if (pC->pAuthEncryptionFilter != NULL)
				bytesWritten += pC->pAuthEncryptionFilter->Get(pOut + nOffset + nBytesInjected, nLength - nBytesInjected);

			else if (pC->pAuthDecryptionFilter != NULL)
				bytesWritten += pC->pAuthDecryptionFilter->Get(pOut + nOffset + nBytesInjected, nLength - nBytesInjected);
		}

		return bytesWritten;
	}

	int CipherSkipBytes(Cipher* pCipher, int nSkippedByteCount)
	{
		pCipher->nBytesToBeSkipped += nSkippedByteCount;
		return nSkippedByteCount;
	}

	int CipherInjectBytes(Cipher* pC, byte* pInject, int nOffset, int nCount)
	{
		pC->pBytesToBeInjected = (byte*)realloc(pC->pBytesToBeInjected, pC->nBytesToBeInjected + nCount);

		memcpy(pC->pBytesToBeInjected + pC->nBytesToBeInjected, pInject, nCount);

		pC->nBytesToBeInjected += nCount;

		return nCount;
	}

	bool CipherEndInput(Cipher* pC)
	{
		if (pC != NULL)
		{
			if (pC->pStream != NULL)
				pC->pStream->MessageEnd();

			else if (pC->pAuthEncryptionFilter != NULL)
				pC->pAuthEncryptionFilter->MessageEnd();

			else if (pC->pAuthDecryptionFilter != NULL)
				pC->pAuthDecryptionFilter->MessageEnd();
		}
		return true;
	}

	byte* encryptBufferUsingJavaformat(int algo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize)
	{
		byte* pEncryptedBuffer = NULL;
		int nEncryptedBufferSize = 0;
		int nEncryptedDataSize = 0;
		byte* pInitialVector = NULL;
		int nInitialVectorLength = 0;
		Cipher* pC = NULL;

		nEncryptedBufferSize = getEncryptedBufferSizeUsingJavaformat(algo, nDataBufferLength);
		pEncryptedBuffer = (byte*)malloc(nEncryptedBufferSize);
		pEncryptedBuffer[0] = 75; // com_adaptiva_fips_CryptoConstants_KEY_TYPE_NONE;
		pEncryptedBuffer[1] = (byte)algo;
		*((DWORD*)(pEncryptedBuffer + 2)) = RngGenerateDword();

		byte salt[4];
		*((DWORD*)(salt)) = RngGenerateDword();

		nInitialVectorLength = getInitialVectorLength(algo);

		pInitialVector = (byte*)malloc(nInitialVectorLength);

		generateBytesFromKeyMaterial((byte*)(pEncryptedBuffer + 2), 4, pInitialVector, nInitialVectorLength);

		pC = CipherInitialize(algo, true);

		byte* pDuplicateKey = (byte*)malloc(nKeyLength);
		memcpy(pDuplicateKey, key, nKeyLength);

		CipherSetKeyAndInitialVector(pC, pDuplicateKey, nKeyLength, pInitialVector, nInitialVectorLength);

		CipherSubmitInput(pC, salt, 0, 4);

		CipherSubmitInput(pC, pDataBuffer, 0, nDataBufferLength);

		CipherEndInput(pC);

		nEncryptedDataSize = CipherRetrieveOutput(pC, pEncryptedBuffer, 6, nEncryptedBufferSize - 6);

		*pnEncryptedBufferSize = nEncryptedDataSize + 6;

		return pEncryptedBuffer;
	}

	byte* decryptBufferUsingJavaformat(int algo, byte* key, int nKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize)
	{
		byte* pDecryptedBuffer = NULL;
		int nDecryptedBufferSize = 0;
		int nDecryptedDataSize = 0;
		byte* pInitialVector = NULL;
		int nInitialVectorLength = 0;
		Cipher* pC = NULL;

		nDecryptedBufferSize = getDecryptedBufferSizeUsingJavaformat(nDataBufferLength);
		pDecryptedBuffer = (byte*)malloc(nDecryptedBufferSize);

		nInitialVectorLength = getInitialVectorLength(algo);

		pInitialVector = (byte*)malloc(nInitialVectorLength);

		generateBytesFromKeyMaterial((byte*)(pDataBuffer + 2), 4, pInitialVector, nInitialVectorLength);

		pC = CipherInitialize(algo, false);

		byte* pDuplicateKey = (byte*)malloc(nKeyLength);
		memcpy(pDuplicateKey, key, nKeyLength);

		CipherSetKeyAndInitialVector(pC, pDuplicateKey, nKeyLength, pInitialVector, nInitialVectorLength);

		CipherSubmitInput(pC, pDataBuffer + 6, 0, nDataBufferLength - 6);

		CipherEndInput(pC);

		CipherRetrieveOutput(pC, pDecryptedBuffer, 0, 4);

		nDecryptedDataSize = CipherRetrieveOutput(pC, pDecryptedBuffer, 0, nDataBufferLength - 10);

		*pnDecryptedBufferSize = nDecryptedDataSize;

		return pDecryptedBuffer;
	}

	int getDecryptedBufferSizeUsingJavaformat(int nInputSize)
	{
		return max(12, (nInputSize - 10));
	}

	int getEncryptedBufferSizeUsingJavaformat(int algo, int nInputSize)
	{
		switch (algo)
		{
		case 1:
			return nInputSize + 10 + 16 - ((nInputSize + 4) % 16);
		case 2:
			return nInputSize + 10 + 16;
		case 3:
			return nInputSize + 10 + 16;
		case 4:
			return nInputSize + 10 + 8;
		}
		return 0;
	}

	int getInitialVectorLength(int algo)
	{
		switch (algo)
		{
		case 1:
			return 16;
		case 2:
			return 256;
		case 3:
			return 128; // need to change this to 128 if I want to test crypto++ <--> OpenSSL interoperability, and if I take open source OpenSSL *as it is*.
						// crypto++ can support wider range of IV length, adaptiva uses 256
		case 4:
			return 8;
		}
		return 0;
	}

	byte* generateEncryptionKey(int algo, int* pnEncryptionKeyLength)
	{
		byte* pKey = NULL;
		int nKeyLength = 0;

		switch (algo)
		{
		case 1:
		case 2:
		case 3:
			nKeyLength = 16;
			break;
		case 4:
			nKeyLength = 24;
			break;
		default:
			break;
		}

		pKey = (byte*)malloc(nKeyLength);

		RngFillByteArrayRegion(pKey, 0, nKeyLength);

		*pnEncryptionKeyLength = nKeyLength;

		return pKey;
	}



	// ======================================
	//  Elliptic Curve Public/Private Key
	// ======================================

	int DsaGenerateKeyPair(byte** pri, int* priLen, byte** pub, int* pubLen)
	{
		ECDSA<ECP, SHA512>::PrivateKey privateKey;
		ECDSA<ECP, SHA512>::PublicKey publicKey;

		privateKey.Initialize(_grng, _gCURVE);

		ByteQueue qPriKey;
		int actualSize;

		privateKey.Save(qPriKey);
		*priLen = (int)(qPriKey.MaxRetrievable());
		*pri = (byte*)malloc(*priLen);
		actualSize = qPriKey.Get((byte*)*pri, *priLen);
		*priLen = actualSize;


		privateKey.MakePublicKey(publicKey);
		ByteQueue qPubKey;
		publicKey.Save(qPubKey);
		*pubLen = (int)(qPubKey.MaxRetrievable());
		*pub = (byte*)malloc(*pubLen);
		actualSize = qPubKey.Get((byte*)*pub, *pubLen);
		*pubLen = actualSize;

		return 0;
	}


	// =========================
	//  ECDSA
	// =========================

	int DsaGenerateSignature(byte* pDataBuffer, int nDataBufferLength, byte* pPrivateKey, int nPrivateKeyLength, byte** ppSignature, int* pnSignatureLength)
	{
		ByteQueue qPrivateKey;
		qPrivateKey.Put((const byte*)pPrivateKey, nPrivateKeyLength);
		ECDSA<ECP, SHA512>::PrivateKey privateKey;
		privateKey.Load(qPrivateKey);
		ECDSA<ECP, SHA512>::Signer signer(privateKey);

		int nMaxSignatureSize = signer.MaxSignatureLength();
		*ppSignature = (byte*)malloc(nMaxSignatureSize);
		*pnSignatureLength = signer.SignMessage(_grng, pDataBuffer, nDataBufferLength, *ppSignature);
		
		return 0;
	}

	int DsaVerifySignature(byte* pDataBuffer, int nDataBufferLength, byte* pPublicKey, int nPublicKeyLength, byte* pSignature, int nSignatureLength)
	{
		ByteQueue qPublicKey;

		qPublicKey.Put((const byte*)pPublicKey, nPublicKeyLength);
		ECDSA<ECP, SHA512>::PublicKey publicKey;
		publicKey.Load(qPublicKey);
		ECDSA<ECP, SHA512>::Verifier verifier(publicKey);

		bool isMatch;
		isMatch = verifier.VerifyMessage((const byte*)pDataBuffer, nDataBufferLength, (const byte*)pSignature, nSignatureLength);
		return isMatch ? 0 : -99;
	}


	// ========================
	//  ECIES
	// ========================

	byte* DsaEncryptBuffer(byte* pub, int pubLen, byte* data, int dataLen, int* encryptedBufferSize)
	{
		byte* ret = NULL;

		ECIES<ECP>::Encryptor encryptor;

		StringSource ss(pub, pubLen, true);
		encryptor.AccessPublicKey().Load(ss);

		encryptor.GetPublicKey().ThrowIfInvalid(_grng, 3);

		size_t s;

		s = encryptor.CiphertextLength(dataLen);

		ret = (byte*)malloc(s);

		encryptor.Encrypt(_grng, data, dataLen, ret);

		*encryptedBufferSize = s;

		return ret;
	}

	byte* DsaDecryptBuffer(byte* pri, int priLen, byte* data, int dataLen, int *decryptedBufferSize)
	{
		byte* ret = NULL;
		
		ECIES<ECP>::Decryptor d;

		StringSource ss(pri, priLen, true);

		d.AccessPrivateKey().Load(ss);

		d.GetPrivateKey().ThrowIfInvalid(_grng, 3);

		size_t s;

		s = d.MaxPlaintextLength(dataLen);

		ret = (byte*)malloc(s);

		d.Decrypt(_grng, data, dataLen, ret);

		*decryptedBufferSize = s;

		return ret;
	}





	// ==================
	//   CMAC
	// ==================

	// Using SecByteBlock to initialize StringSource doesn't work
	byte* generateCMAC(byte* plaintext, int plaintextLength, byte*key, int key_size, int* tag_size)
	{
		SecByteBlock keyBlock(key_size);
		keyBlock.Assign(key, key_size);
		SecByteBlock plaintextBlock(plaintextLength);
		plaintextBlock.Assign(plaintext, plaintextLength);

		CMAC<AES> cmac(keyBlock, keyBlock.size());

		std::string tag;
		SecByteBlock tagBlock;

		StringSource(plaintextBlock, plaintextBlock.size(), true, new HashFilter(cmac, new StringSink(tag)));

		size_t tsize = tag.size();

		byte* ret = (byte*)malloc(tsize);
		memcpy(ret, tag.c_str(), tsize);
		*tag_size = (int)tsize;

		return ret;
	}

	// Using std::string to initialize StringSource doesn't work
	byte* generateCMAC_2(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size)
	{
		SecByteBlock keyBlock(key_size);
		keyBlock.Assign(key, key_size);

		std::string plaintext_str((char*)plaintext, plaintextLength);
		
		CMAC<AES> cmac(keyBlock, keyBlock.size());

		std::string tag;

		StringSource(plaintext_str, true, new HashFilter(cmac, new StringSink(tag)));

		size_t tsize = tag.size();

		byte* ret = (byte*)malloc(tsize);
		memcpy(ret, tag.c_str(), tsize);
		*tag_size = (int)tsize;

		return ret;
	}

	byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size)
	{
		byte* tag;
		CMAC<AES> cmac(key, key_size);
		cmac.Update(plaintext, plaintextLength);
		*tag_size = cmac.DigestSize();
		tag = (byte*)calloc(*tag_size, sizeof(byte));
		cmac.Final(tag);

		return tag;
	}

	// The two tag generating functions using StringSource don't work, so I didn't test this verifying function
	bool verifyCMAC(byte* plaintext, int plaintextLength, byte* key, int key_size, byte* tag, int tag_size)
	{
		SecByteBlock keyBlock(key_size);
		keyBlock.Assign(key, key_size);

		CMAC<AES>cmac(keyBlock, keyBlock.size());

		byte* combined = (byte*)malloc(plaintextLength + tag_size);
		memcpy(combined, plaintext, plaintextLength);
		memcpy(combined + plaintextLength, tag, tag_size);

		SecByteBlock combinedBlock(plaintextLength + tag_size);
		combinedBlock.Assign(combined, plaintextLength + tag_size);

		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		StringSource(combinedBlock, combinedBlock.size(), true, new HashVerificationFilter(cmac, NULL, flags));

		return true;
	}

	bool verifyCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, byte* tag, int tag_size)
	{
		bool isMatch = false;
		CMAC<AES> cmac(key, key_size);
		cmac.Update(plaintext, plaintextLength);
		isMatch = cmac.Verify(tag);
		return isMatch;
	}



	// ==============
	//  EAX
	// ==============

	byte* eax_encrypt(byte* data, int data_len, byte* key, int key_size, byte* iv, int iv_size)
	{
		string plaintext((char const*)data, data_len);
		string ciphertext_and_tag;
		byte* out;

		EAX<AES>::Encryption enc;
		enc.SetKeyWithIV(key, key_size, iv, iv_size);
		StringSource(plaintext, true, new AuthenticatedEncryptionFilter(enc, new StringSink(ciphertext_and_tag)));

		out = (byte*)malloc(ciphertext_and_tag.size());
		memcpy(out, ciphertext_and_tag.data(), ciphertext_and_tag.size());
		return out;
	}

	byte* eax_decrypt(byte* data, int data_len, byte* key, int key_size, byte* iv, int iv_size)
	{
		string recovered;
		byte* out;
		EAX<AES>::Decryption dec;
		dec.SetKeyWithIV(key, key_size, iv, iv_size);
		ArraySource(data, data_len, true, new AuthenticatedDecryptionFilter(dec, new StringSink(recovered)));
		out = (byte*)malloc(recovered.size());
		memcpy(out, recovered.data(), recovered.size());
		return out;
	}

}