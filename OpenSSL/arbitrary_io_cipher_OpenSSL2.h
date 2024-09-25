#pragma once

#include <sstream>
#include <iostream>

#include <Windows.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>



namespace AIO_CIPHER_OPENSSL2 {

	void xorbuf(byte* output, byte* input, byte* mask, int len);
	byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size);
	byte* cmac_with_prefix(byte* data, int data_len, int prefix, byte* key, int key_size, int* tag_size);

	class BlockCipher
	{
	public:
		virtual char const * getAlgorithmName() = 0;
		virtual int getBlockSize() = 0;
		virtual std::string getFormalName();
	};

	class AES : BlockCipher
	{
	public:
		using BlockCipher::getFormalName;
		char const* getAlgorithmName();
		int getBlockSize();
	};

	class DES3 : BlockCipher
	{
	public:
		char const* getAlgorithmName();
		int getBlockSize();
		std::string getFormalName();
	};


	template<class Type_BlockCipher>
	class CipherMode
	{
	private:
		Type_BlockCipher blockCipher;

	protected:
		
		bool isEncrypt;

		byte* pIv;
		int nIvLength;

		byte* pKey;
		int nKeyLength;

		int nBytesToBeSkipped;
		int nBytesToBeInjected;
		int nBytesAlreadyInjected;
		byte* pBytesToBeInjected;

		BIO* pBioOutput;
		BIO* pBioCipherFilter;
		bool isBioConnected;

		CipherMode(bool _isEncrypt) :
			isEncrypt(_isEncrypt),
			pKey(NULL),
			nKeyLength(0),
			pIv(NULL),
			nIvLength(0),
			nBytesToBeSkipped(0),
			nBytesToBeInjected(0),
			nBytesAlreadyInjected(0),
			pBytesToBeInjected(NULL),
			pBioOutput(NULL),
			pBioCipherFilter(NULL),
			isBioConnected(false)
		{
		}

		~CipherMode()
		{
			if (isBioConnected)
			{
				BIO_free_all(pBioCipherFilter);
			}
			else
			{
				if (pBioOutput != NULL)
				{
					BIO_set_flags(pBioOutput, BIO_FLAGS_MEM_RDONLY);
					BIO_free(pBioOutput);
				}
				if (pBioCipherFilter != NULL)
				{
					BIO_free(pBioCipherFilter);
				}
			}
			if (pKey != NULL)
			{
				OPENSSL_free(pKey);
			}
			if (pIv != NULL)
			{
				OPENSSL_free(pIv);
			}
			if (pBytesToBeInjected != NULL)
			{
				OPENSSL_free(pBytesToBeInjected);
			}
		}

		CipherMode(CipherMode const&) = delete;
		CipherMode(CipherMode&&) = delete;
		CipherMode& operator =(CipherMode const&) = delete;
		CipherMode& operator =(CipherMode&&) = delete;

		virtual char const* getModeName() = 0;

		std::string getTransformationName()
		{
			std::stringstream ss;
			ss << blockCipher.getFormalName() << "-" << getModeName();
			return ss.str();
		}

		virtual bool setKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIv, int _nIvLength)
		{
			shallowCopyKeyAndIV(_pKey, _nKeyLength, _pIv, _nIvLength);

			setupBioChain(_pKey, _nKeyLength, _pIv, _nIvLength);
			return true;
		}

		void shallowCopyKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
		{
			this->pKey = _pKey;
			this->nKeyLength = _nKeyLength;
			this->pIv = _pIV;
			this->nIvLength = _nIVLength;
		}

		virtual bool setupBioChain(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
		{
			EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, getTransformationName().c_str(), NULL/*prop queue*/);

			pBioCipherFilter = BIO_new(BIO_f_cipher());
			BIO_set_cipher(pBioCipherFilter, evp_cipher, _pKey, _pIV, (int)isEncrypt);
			pBioOutput = BIO_new(BIO_s_mem());
			BIO_push(pBioCipherFilter, pBioOutput);
			isBioConnected = true;
			return true;
		}

		int skipBytes(int _nBytesToBeSkipped)
		{
			nBytesToBeSkipped += _nBytesToBeSkipped;
			return _nBytesToBeSkipped;
		}

		int injectBytes(byte* _pBytesToBeInjected, int _nOffset, int _nBytesToBeInjected)
		{
			pBytesToBeInjected = (byte*)OPENSSL_realloc(pBytesToBeInjected, nBytesToBeInjected + _nBytesToBeInjected);
			memcpy(pBytesToBeInjected + nBytesToBeInjected, _pBytesToBeInjected, _nBytesToBeInjected);
			nBytesToBeInjected += _nBytesToBeInjected;
			return _nBytesToBeInjected;
		}

		virtual bool submitInput(byte* pInput, int nOffset, int nLength) = 0;

		virtual bool endInput() = 0;

		bool dealWithSkippingWhenRetrieveOutput()
		{
			if (nBytesToBeSkipped > 0)
			{
				BYTE* pSkip = (BYTE*)OPENSSL_zalloc(nBytesToBeSkipped);
				int bytesRead = BIO_read(pBioOutput, pSkip, nBytesToBeSkipped);
				if (bytesRead == -1)
				{
					bytesRead = 0;
				}
				if (bytesRead < nBytesToBeSkipped)
				{
					nBytesToBeSkipped -= bytesRead;
					OPENSSL_free(pSkip);
					return false;
				}
				nBytesToBeSkipped -= bytesRead;
				OPENSSL_free(pSkip);
			}
			return true;
		}

		int dealWithInjectionWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength)
		{
			int nInject = min(nLength, nBytesToBeInjected);
			if (nInject > 0)
			{
				BYTE* pInjectStart = (pBytesToBeInjected + nBytesAlreadyInjected);
				memcpy(pOutput + nOffset, pInjectStart, nInject);
				nBytesToBeInjected -= nInject;
				nBytesAlreadyInjected += nInject;
			}
			return nInject;
		}

		virtual int dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength)
		{
			int nCopy = nLength;
			int bytesRead = 0;
			if (nCopy > 0)
			{
				bytesRead = BIO_read(pBioOutput, pOutput + nOffset, nCopy);
				if (bytesRead == -1)
					bytesRead = 0;
			}

			return bytesRead;
		}

		int retrieveOutput(byte* pOutput, int nOffset, int nLength)
		{
			bool isContinue = dealWithSkippingWhenRetrieveOutput();
			if (isContinue)
			{
				int nInject = dealWithInjectionWhenRetrieveOutput(pOutput, nOffset, nLength);
				int nCopy = dealWithCopyWhenRetrieveOutput(pOutput, nOffset+nInject, nLength-nInject);
				return nCopy + nInject;
			}
			else
			{
				return 0;
			}
		}

		virtual bool reset()
		{
			nBytesAlreadyInjected = nBytesToBeSkipped = nBytesToBeInjected = 0;
			if (pBytesToBeInjected != NULL)
			{
				OPENSSL_free(pBytesToBeInjected);
			}

			EVP_CIPHER_CTX* ctx;
			BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
			EVP_CIPHER_CTX_reset(ctx);

			BIO_reset(pBioCipherFilter);
			BIO_reset(pBioOutput);
			isBioConnected = false;
			return setKeyAndIV(pKey, nKeyLength, pIv, nIvLength);
		}
	};

	template<class Type_BlockCipher>
	class CBC : CipherMode<Type_BlockCipher>
	{
	private:
		using CipherMode<Type_BlockCipher>::pBioCipherFilter;

	public:
		
		using CipherMode<Type_BlockCipher>::setKeyAndIV;
		using CipherMode<Type_BlockCipher>::skipBytes;
		using CipherMode<Type_BlockCipher>::injectBytes;
		using CipherMode<Type_BlockCipher>::retrieveOutput;
		using CipherMode<Type_BlockCipher>::reset;

		CBC(bool _isEncrypt) :CipherMode<Type_BlockCipher>(_isEncrypt) {}

		~CBC() = default;

		CBC(CBC const&) = delete;
		CBC(CBC&&) = delete;
		CBC& operator =(CBC const&) = delete;
		CBC& operator =(CBC&&) = delete;

		char const* getModeName()
		{
			return "CBC";
		}
		
		bool submitInput(byte* pInput, int nOffset, int nLength)
		{
			BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
			return true;
		}
		bool endInput()
		{
			BIO_flush(pBioCipherFilter);
			return true;
		}
	};

	template<class Type_BlockCipher, int TagSize>
	class AuthCipher : CipherMode<Type_BlockCipher>
	{
	protected:

		using CipherMode<Type_BlockCipher>::isEncrypt;
		using CipherMode<Type_BlockCipher>::pIv;
		using CipherMode<Type_BlockCipher>::nIvLength;
		using CipherMode<Type_BlockCipher>::pKey;
		using CipherMode<Type_BlockCipher>::nKeyLength;
		using CipherMode<Type_BlockCipher>::nBytesToBeSkipped;
		using CipherMode<Type_BlockCipher>::nBytesToBeInjected;
		using CipherMode<Type_BlockCipher>::nBytesAlreadyInjected;
		using CipherMode<Type_BlockCipher>::pBytesToBeInjected;
		using CipherMode<Type_BlockCipher>::pBioOutput;
		using CipherMode<Type_BlockCipher>::pBioCipherFilter;
		using CipherMode<Type_BlockCipher>::isBioConnected;

		using CipherMode<Type_BlockCipher>::setKeyAndIV;
		using CipherMode<Type_BlockCipher>::skipBytes;
		using CipherMode<Type_BlockCipher>::injectBytes;
		using CipherMode<Type_BlockCipher>::retrieveOutput;
		using CipherMode<Type_BlockCipher>::submitInput;
		using CipherMode<Type_BlockCipher>::endInput;
		using CipherMode<Type_BlockCipher>::shallowCopyKeyAndIV;
		using CipherMode<Type_BlockCipher>::setupBioChain;
		using CipherMode<Type_BlockCipher>::getTransformationName;

		byte potentialTag[TagSize];
		int nBufferedPotentialTagLength;
		int nTagSize;
		AuthCipher(bool _isEncrypt) : CipherMode<Type_BlockCipher>(_isEncrypt), nBufferedPotentialTagLength(0), nTagSize(TagSize)
		{
			memset(potentialTag, 0, sizeof(potentialTag));
		}
		~AuthCipher() = default;
		AuthCipher(AuthCipher const&) = delete;
		AuthCipher(AuthCipher&&) = delete;
		AuthCipher& operator =(AuthCipher const&) = delete;
		AuthCipher& operator =(AuthCipher&&) = delete;
		bool reset() override
		{
			memset(potentialTag, 0, sizeof(potentialTag));
			nBufferedPotentialTagLength = 0;
			return CipherMode<Type_BlockCipher>::reset();
		}
	};

	template<class Type_BlockCipher>
	class GCM : AuthCipher<Type_BlockCipher, 16>
	{
	private:
		using AuthCipher<Type_BlockCipher, 16>::isEncrypt;
		using AuthCipher<Type_BlockCipher, 16>::pKey;
		using AuthCipher<Type_BlockCipher, 16>::nKeyLength;
		using AuthCipher<Type_BlockCipher, 16>::pIv;
		using AuthCipher<Type_BlockCipher, 16>::nIvLength;
		using AuthCipher<Type_BlockCipher, 16>::pBioOutput;
		using AuthCipher<Type_BlockCipher, 16>::pBioCipherFilter;
		using AuthCipher<Type_BlockCipher, 16>::isBioConnected;

		using AuthCipher<Type_BlockCipher, 16>::potentialTag;
		using AuthCipher<Type_BlockCipher, 16>::nBufferedPotentialTagLength;

		using AuthCipher<Type_BlockCipher, 16>::getTransformationName;
		using AuthCipher<Type_BlockCipher, 16>::nTagSize;
	public:
		using AuthCipher<Type_BlockCipher, 16>::setKeyAndIV;
		using AuthCipher<Type_BlockCipher, 16>::skipBytes;
		using AuthCipher<Type_BlockCipher, 16>::injectBytes;
		using AuthCipher<Type_BlockCipher, 16>::retrieveOutput;
		using AuthCipher<Type_BlockCipher, 16>::reset;

		GCM(bool _isEncrypt) :AuthCipher<Type_BlockCipher, 16>(_isEncrypt)
		{
		}
		~GCM() = default;
		GCM(GCM const&) = delete;
		GCM(GCM&&) = delete;
		GCM& operator =(GCM const&) = delete;
		GCM& operator =(GCM&&) = delete;

		char const* getModeName()
		{
			return "GCM";
		}

		bool setupBioChain(byte* _pKey, int _nKeyLength, byte* _pIv, int _nIvLength) override
		{
			EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, getTransformationName().c_str(), NULL/*prop queue*/);

			pBioCipherFilter = BIO_new(BIO_f_cipher());

			if (_nIvLength == 12)
			{
				BIO_set_cipher(pBioCipherFilter, evp_cipher, _pKey, _pIv, (int)isEncrypt);
			}
			else
			{
				BIO_set_cipher(pBioCipherFilter, evp_cipher, _pKey, NULL, (int)isEncrypt);

				EVP_CIPHER_CTX* ctx;
				BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
				EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, _nIvLength, NULL);
				if (isEncrypt)
				{
					EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, _pIv);
				}
				else
				{
					EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, _pIv);
				}
			}
			pBioOutput = BIO_new(BIO_s_mem());
			BIO_push(pBioCipherFilter, pBioOutput);
			isBioConnected = true;

			return true;
		}

		bool submitInput(byte* pInput, int nOffset, int nLength)
		{
			if (isEncrypt)
			{
				BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
			}
			else
			{
				int total = nBufferedPotentialTagLength + nLength;
				if (total > nTagSize)
				{
					int send = total - nTagSize;
					if (send >= nBufferedPotentialTagLength)
					{
						BIO_write(pBioCipherFilter, potentialTag, nBufferedPotentialTagLength);
						send -= nBufferedPotentialTagLength;
						BIO_write(pBioCipherFilter, pInput + nOffset, send);
						memcpy(potentialTag, pInput + nOffset + send, nTagSize);

					}
					else
					{
						byte tmp[16];
						memcpy(tmp, potentialTag, sizeof(potentialTag));
						BIO_write(pBioCipherFilter, potentialTag, send);
						memcpy(potentialTag, tmp + send, nBufferedPotentialTagLength - send);
						memcpy(potentialTag + nBufferedPotentialTagLength - send, pInput + nOffset, nLength);
					}
					nBufferedPotentialTagLength = nTagSize;
				}
				else
				{
					memcpy(potentialTag + nBufferedPotentialTagLength, pInput + nOffset, nLength);
					nBufferedPotentialTagLength += nLength;
				}
			}
			return true;
		}

		bool endInput()
		{
			if (isEncrypt)
			{
				BIO_flush(pBioCipherFilter);
				EVP_CIPHER_CTX* ctx;
				BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
				byte tag[16];
				OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
				params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
				EVP_CIPHER_CTX_get_params(ctx, params);
				BIO_write(pBioOutput, tag, sizeof(tag));
			}
			else
			{
				EVP_CIPHER_CTX* ctx;
				BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
				OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
				params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
					(void*)potentialTag, nTagSize);

				EVP_CIPHER_CTX_set_params(ctx, params);

				int tmpLen;
				// verify tag
				int ret = EVP_DecryptFinal_ex(ctx, NULL/*can this be NULL?*/, &tmpLen); // must call final if there is padding
				if (ret != 1)
				{
					throw std::runtime_error("AES GCM decryption authentication tag mismatch");
				}
			}
			return true;
		}
	};

	template<class Type_BlockCipher>
	class EAX : AuthCipher<Type_BlockCipher, 16>
	{
	private:
		using AuthCipher<Type_BlockCipher, 16>::isEncrypt;
		using AuthCipher<Type_BlockCipher, 16>::pKey;
		using AuthCipher<Type_BlockCipher, 16>::nKeyLength;
		using AuthCipher<Type_BlockCipher, 16>::pIv;
		using AuthCipher<Type_BlockCipher, 16>::nIvLength;
		
		using AuthCipher<Type_BlockCipher, 16>::pBioOutput;
		using AuthCipher<Type_BlockCipher, 16>::pBioCipherFilter;
		using AuthCipher<Type_BlockCipher, 16>::isBioConnected;

		using AuthCipher<Type_BlockCipher, 16>::shallowCopyKeyAndIV;
		using AuthCipher<Type_BlockCipher, 16>::setupBioChain;

		using AuthCipher<Type_BlockCipher, 16>::potentialTag;
		using AuthCipher<Type_BlockCipher, 16>::nBufferedPotentialTagLength;
		using AuthCipher<Type_BlockCipher, 16>::nTagSize;

		byte* big_N;
		byte* big_H;
		int dataSize;
		bool isTagProcessed;
		BIO* pBioCiphertextBackup;

	public:
		using AuthCipher<Type_BlockCipher, 16>::skipBytes;
		using AuthCipher<Type_BlockCipher, 16>::injectBytes;
		using AuthCipher<Type_BlockCipher, 16>::retrieveOutput;
		

		EAX(bool _isEncrypt) :
			AuthCipher<Type_BlockCipher, 16>(_isEncrypt),
			big_N(NULL),
			big_H(NULL),
			dataSize(0),
			isTagProcessed(false),
			pBioCiphertextBackup(BIO_new(BIO_s_mem()))
		{
		}

		~EAX()
		{
			if (big_N != NULL)
			{
				OPENSSL_free(big_N);
			}
			if (big_H != NULL)
			{
				OPENSSL_free(big_H);
			}
			if (pBioCiphertextBackup != NULL)
			{
				BIO_set_flags(pBioCiphertextBackup, BIO_FLAGS_MEM_RDONLY);
				BIO_free(pBioCiphertextBackup);
			}
		}
		
		EAX(EAX const&) = delete;
		EAX(EAX&&) = delete;
		EAX& operator =(EAX const&) = delete;
		EAX& operator =(EAX&&) = delete;

		char const* getModeName()
		{
			return "CTR";
		}

		bool setKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIv, int _nIvLength) override
		{
			shallowCopyKeyAndIV(_pKey, _nKeyLength, _pIv, _nIvLength);
			
			int tag_size;
			big_N = cmac_with_prefix(pIv, nIvLength, 0, pKey, nKeyLength, &tag_size);
			big_H = cmac_with_prefix(NULL, 0, 1, pKey, nKeyLength, &tag_size);
			
			setupBioChain(_pKey, _nKeyLength, big_N, tag_size);

			return true;
		}

		bool submitInput(byte* pInput, int nOffset, int nLength)
		{
			if (isEncrypt)
			{
				BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
				dataSize += nLength;
			}
			else
			{
				int total = nBufferedPotentialTagLength + nLength;
				if (total > nTagSize)
				{
					int send = total - nTagSize;
					dataSize += send;
					if (send >= nBufferedPotentialTagLength)
					{
						BIO_write(pBioCipherFilter, potentialTag, nBufferedPotentialTagLength);
						BIO_write(pBioCiphertextBackup, potentialTag, nBufferedPotentialTagLength);
						send -= nBufferedPotentialTagLength;
						BIO_write(pBioCipherFilter, pInput + nOffset, send);
						BIO_write(pBioCiphertextBackup, pInput + nOffset, send);
						memcpy(potentialTag, pInput + nOffset + send, nTagSize);
					}
					else
					{
						byte tmp[16];
						memcpy(tmp, potentialTag, sizeof(potentialTag));
						BIO_write(pBioCipherFilter, potentialTag, send);
						BIO_write(pBioCiphertextBackup, potentialTag, send);
						memcpy(potentialTag, tmp + send, nBufferedPotentialTagLength - send);
						memcpy(potentialTag + nBufferedPotentialTagLength - send, pInput + nOffset, nLength);
					}
					nBufferedPotentialTagLength = nTagSize;
				}
				else
				{
					memcpy(potentialTag + nBufferedPotentialTagLength, pInput + nOffset, nLength);
					nBufferedPotentialTagLength += nLength;
				}
			}
			return true;
		}

		bool endInput()
		{
			int tag_size;
			byte* ciphertext = (byte*)OPENSSL_zalloc(dataSize);
			byte tag[16];
			byte one_block[16];

			int bytesFromBackup = BIO_read(pBioCiphertextBackup, ciphertext, dataSize);
			if (bytesFromBackup == -1)
			{
				bytesFromBackup == 0;
			}
			

			if (bytesFromBackup < dataSize)
			{
				int bytesFromMainOutput = BIO_read(pBioOutput, ciphertext + bytesFromBackup, dataSize - bytesFromBackup);
				if (bytesFromMainOutput > 0)
				{
					BIO_write(pBioOutput, ciphertext + bytesFromBackup, dataSize - bytesFromBackup);
				}
			}

			byte* big_C = cmac_with_prefix(ciphertext, dataSize, 2, pKey, nKeyLength, &tag_size);

			xorbuf(one_block, big_N, big_C, 16);
			xorbuf(tag, one_block, big_H, 16);

			OPENSSL_free(big_C);
			OPENSSL_free(ciphertext);

			if (isEncrypt)
			{
				BIO_write(pBioOutput, tag, sizeof(tag));
			}
			else
			{
				int diff = memcmp(tag, potentialTag, 16);
				if (diff != 0)
					throw std::runtime_error("tag mismatch");
			}
			isTagProcessed = true;

			return true;
		}

		int dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength) override
		{
			int nCopy = nLength;
			int bytesRead = 0;
			if (nCopy > 0)
			{
				bytesRead = BIO_read(pBioOutput, pOutput + nOffset, nCopy);
				if (bytesRead == -1)
					bytesRead = 0;

				if (isEncrypt && !isTagProcessed)
				{
					BIO_write(pBioCiphertextBackup, pOutput + nOffset, bytesRead);
				}
			}
			return bytesRead;
		}

		bool reset() override
		{
			dataSize = 0;
			BIO_reset(pBioCiphertextBackup);
			isTagProcessed = false;
			return AuthCipher<Type_BlockCipher, 16>::reset();
		}
	};

	struct Cipher_t
	{
		int nAlgo;
		CBC<AES>* pCbcAes;
		CBC<DES3>* pCbcDes3;
		GCM<AES>* pGcmAes;
		EAX<AES>* pEaxAes;
		Cipher_t(int _nAlgorithm) :
			nAlgo(_nAlgorithm),
			pCbcAes(NULL),
			pCbcDes3(NULL),
			pGcmAes(NULL),
			pEaxAes(NULL)
		{}
		~Cipher_t()
		{
			if (pCbcAes != NULL)
				delete pCbcAes;
			if (pCbcDes3 != NULL)
				delete pCbcDes3;
			if (pGcmAes != NULL)
				delete pGcmAes;
			if (pEaxAes != NULL)
				delete pEaxAes;
		}
	};
	typedef struct Cipher_t Cipher;

	bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

	int CipherSkipBytes(Cipher* pCipher, int nSkipBytesCount);

	int CipherInjectBytes(Cipher* pCipher, byte* pInjectBytes, int nOffset, int nInjectBytesCount);

	bool CipherSubmitInput(Cipher* pCipher, byte* pInput, int nOffset, int nLength);

	bool CipherEndInput(Cipher* pCipher);

	int CipherRetrieveOutput(Cipher* pCipher, byte* pOutput, int nOffset, int nLength);

	Cipher* CipherInitialize(int nAlgorithm, bool isEncrypt);

	bool CipherRelease(Cipher* p);

	bool CipherReset(Cipher* p);
}