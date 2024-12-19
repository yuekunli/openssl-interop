#pragma once

#include <Windows.h>

#include <openssl/bio.h>

namespace ARBITRARY_IO_CIPHER_OPENSSL {

    class Cipher
    {
    protected:

        bool fEncrypt;
        char aFullTransformationName[32];
        byte* pKey;
        int nKeyLength;

        byte* pIV;
        int nIVLength;

        int nBytesToBeSkipped;
        int nBytesToBeInjected;
        int nBytesAlreadyInjected;
        byte* pBytesToBeInjected;

        BIO* pBioOutput;
        BIO* pBioCipherFilter;
        bool isBioConnected;

        Cipher() = delete;

        Cipher(bool _fEncrypt);

        void shallowCopyKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

        bool setupBioChain(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);



        bool dealWithSkippingWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength);

        int dealWithInjectionWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength);

        virtual int dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject);

    public:
        virtual ~Cipher(); // making this destructor virtual is super important. I create objects of derived classes, but cast pointer to a pointer to this base class,
                            // when I delete the pointer, the pointer is recognized as a pointer to this base class, if this destructor is not virtual, the destructor
                            // of the derived class is not called.

        int skipBytes(int _nBytesToBeSkipped);
        
        int injectBytes(byte* pInjectBytes, int nOffset, int _nBytesToBeInjected);

        virtual bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength) = 0;
        virtual bool submitInput(byte* pInput, int nOffset, int nLength) = 0;

        virtual bool endInput() = 0;

        int retrieveOutput(byte* pOutput, int nOffset, int nLength);
        virtual bool reset();
    };

    //===========================================================================//

    class CBC : Cipher
    {
    protected:

        char const* cipherName[2] = { "AES-128-CBC", "DES-EDE3-CBC" };
        char const* pChosenCipherName;
    
        CBC(bool);
        ~CBC() = default;
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
        bool submitInput(byte* pInput, int nOffset, int nLength);
        bool endInput();
    };

    //===========================================================================//

    class AESCBC : CBC
    {
    public:
        AESCBC(bool);
        ~AESCBC() = default;
        
        //bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
    };

    class DES3CBC : CBC
    {
    public:
        DES3CBC(bool);
        ~DES3CBC() = default;
        
        //bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIvLength);
    };

    //===========================================================================//

	class AESGCM : Cipher
	{
    private:
		byte potentialTag[16];
		int nBufferedPotentialTagLength;
        int dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject) override;

	public:
		AESGCM(bool);
        ~AESGCM() = default;
		bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);
		bool submitInput(byte* pInput, int nOffset, int nLength);
		bool endInput();
        bool reset() override;
	};

    //===========================================================================//

    class AESEAX : Cipher
    {
    private:
        byte* big_N;
        byte* big_H;
        int data_size;
        BIO* pBioCiphertextBackup;
        byte potentialTag[16];
        int nBufferedPotentialTagLength;
        bool isTagProcessed;

        int dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject) override;

    public:
        AESEAX(bool);
        ~AESEAX();
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength);
        bool submitInput(byte* pInput, int nOffset, int nLength);
        bool endInput();
        bool reset() override;
    };

    //===========================================================================//

    bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength);

    bool CipherSubmitInput(Cipher* pCipher, byte* pInput, int nOffset, int nLength);

    bool CipherEndInput(Cipher* pCipher);

    int CipherRetrieveOutput(Cipher* pCipher, byte* pOutput, int nOffset, int nLength);

    Cipher* CipherInitialize(int nAlgorithm, bool isEncrypt);

    bool CipherRelease(Cipher* p);

    bool CipherReset(Cipher* p);
}