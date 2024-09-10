#pragma once

#include <Windows.h>


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

namespace CO2 {

    class Cipher
    {
    protected:
        int nAlgorithm;
        bool fEncrypt;

        byte* pKey;
        int nKeyLength;

        byte* pIV;
        int nIVLength;

        int nBlockSize;

        int nBytesToBeSkipped;
        int nBytesToBeInjected;
        int nBytesAlreadyInjected;
        byte* pBytesToBeInjected;

        virtual bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength) = 0;

        //virtual bool reset() = 0;

        virtual bool submitInput(byte* pInput, int nOffset, int nLength) = 0;

        virtual bool endInput() = 0;

        virtual int retrieveOutput(byte* pOutput, int nOffset, int nLength) = 0;

        int skipBytes(int _nBytesToBeSkipped)
        {
            nBytesToBeSkipped = _nBytesToBeSkipped;
        }

        int injectBytes(byte* pInjectBytes, int nOffset, int _nBytesToBeInjected)
        {
            pBytesToBeInjected = (byte*)OPENSSL_realloc(pBytesToBeInjected, nBytesToBeInjected + _nBytesToBeInjected);
            memcpy(pBytesToBeInjected + nBytesToBeInjected, pInjectBytes, _nBytesToBeInjected);
            nBytesToBeInjected += _nBytesToBeInjected;
        }
    };


	class AESGCM : Cipher
	{
		BIO* pBIOOutput;
		BIO* pBIOCipher;
		bool fBioConnected;
		EVP_CIPHER* evp_cipher;

		byte potentialTag[16];
		int nBufferedPotentialTagLength;
	public:
		AESGCM(bool);
        ~AESGCM();
		bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);
		bool submitInput(byte* pInput, int nOffset, int nLength);
		bool endInput();
		int retrieveOutput(byte* pOutput, int nOffset, int nLength);
	};

    byte* eax_encrypt(byte* data, int data_len, byte* key, int key_size, byte* iv, int iv_size);

    

    class AESEAX : Cipher
    {
        BIO* pBIOOutput;
        BIO* pBIOCipher;
        bool fBioConnected;


        byte* big_N;
        byte* big_H;
        byte* big_C;

        BIO* pBIOCipherOutputBackup;
        int data_size;

        bool isInputEnd;

        void processTag();

    public:
        AESEAX(bool);
        ~AESEAX();
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);
        bool submitInput(byte* pInput, int nOffset, int nLength);
        bool endInput();
        int retrieveOutput(byte* pOutput, int nOffset, int nLength);
    };

    
}