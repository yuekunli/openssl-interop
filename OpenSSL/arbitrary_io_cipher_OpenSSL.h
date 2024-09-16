#pragma once

#include <Windows.h>

#include <openssl/bio.h>

namespace ARBITRARY_IO_CIPHER_OPENSSL {

    class Cipher
    {
    protected:
        int nAlgorithm;
        bool fEncrypt;

        byte* pKey;
        int nKeyLength;

        byte* pIV;
        int nIVLength;

        int nBytesToBeSkipped;
        int nBytesToBeInjected;
        int nBytesAlreadyInjected;
        byte* pBytesToBeInjected;
    public:
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

    class CBC : Cipher
    {
    protected:
        BIO* pBIOOutput;
        BIO* pBIOCipherFilter;
        bool fBioConnected;
        int nBlockSize;
        char const* cipherName[2] = { "AES-128-CBC", "DES-EDE3-CBC" };
        char const* pChosenCipherName;
    public:
        CBC(bool);
        ~CBC();
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
        bool submitInput(byte* pInput, int nOffset, int nLength);
        bool endInput();
        int retrieveOutput(byte* pOutput, int nOffset, int nLength);
    };

    class AESCBC : CBC
    {
    public:
        AESCBC(bool);
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
    };

    class DES3CBC : CBC
    {
    public:
        DES3CBC(bool);
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
    };

	class AESGCM : Cipher
	{
		BIO* pBIOOutput;
		BIO* pBIOCipher;
		bool fBioConnected;

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

    class AESEAX : Cipher
    {
        BIO* pBIOOutput;
        BIO* pBIOCipherFilter;
        bool fBioConnected;

        byte* big_N;
        byte* big_H;
    
        int data_size;

        BIO* pBIOCiphertextBackup;

        //bool isInputEnd;
        byte potentialTag[16];
        int nBufferedPotentialTagLength;

        bool isTagProcessed;

        void processTag();

    public:
        AESEAX(bool);
        ~AESEAX();
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);
        bool submitInput(byte* pInput, int nOffset, int nLength);
        bool endInput();
        int retrieveOutput(byte* pOutput, int nOffset, int nLength);
    };


    bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

    bool CipherSubmitInput(Cipher* pCipher, byte* pInput, int nOffset, int nLength);

    bool CipherEndInput(Cipher* pCipher);

    int CipherRetrieveOutput(Cipher* pCipher, byte* pOutput, int nOffset, int nLength);

    Cipher* CipherInitialize(int nAlgorithm, bool isEncrypt);

    bool CipherRelease(Cipher* p);
}