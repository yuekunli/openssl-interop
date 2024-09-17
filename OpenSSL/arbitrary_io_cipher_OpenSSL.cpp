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

#include "arbitrary_io_cipher_OpenSSL.h"

typedef unsigned char byte;

namespace ARBITRARY_IO_CIPHER_OPENSSL {

    OSSL_LIB_CTX* fips_libctx = NULL;
    char const* propertyString = NULL;

    static void xorbuf(byte* output, byte* input, byte* mask, int len)
    {
        uint64_t i64, m64, o64;
        uint32_t i32, m32, o32;
        uint16_t i16, m16, o16;
        uint8_t i8, m8, o8;
        int filledLen = 0;
        byte* po = output;
        byte* pi = input;
        byte* pm = mask;
        while (filledLen < len)
        {
            if (len - filledLen >= 8)
            {
                i64 = *((uint64_t*)pi);
                m64 = *((uint64_t*)pm);
                o64 = i64 ^ m64;
                *((uint64_t*)po) = o64;
                po += 8;
                pi += 8;
                pm += 8;
                filledLen += 8;
            }
            else if (len - filledLen < 8 && len - filledLen >= 4)
            {
                i32 = *((uint32_t*)pi);
                m32 = *((uint32_t*)pm);
                o32 = i32 ^ m32;
                *((uint32_t*)po) = o32;
                po += 4;
                pi += 4;
                pm += 4;
                filledLen += 4;
            }
            else if (len - filledLen < 4 && len - filledLen >= 2)
            {
                i16 = *((uint16_t*)pi);
                m16 = *((uint16_t*)pm);
                o16 = i16 ^ m16;
                *((uint16_t*)po) = o16;
                po += 2;
                pi += 2;
                pm += 2;
                filledLen += 2;
            }
            else
            {
                i8 = *((uint8_t*)pi);
                m8 = *((uint8_t*)pm);
                o8 = i8 ^ m8;
                *((uint8_t*)po) = o8;
                po += 1;
                pi += 1;
                pm += 1;
                filledLen += 1;
            }
        }
    }

    static byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size)
    {
        EVP_MAC* cmac = NULL;
        EVP_MAC_CTX* ctx = NULL;
        byte* tag = NULL;
        size_t out_len = 0;
        OSSL_PARAM params[4];
        OSSL_PARAM* p = params;
        char cipher_name[] = "AES-128-CBC";

        cmac = EVP_MAC_fetch(fips_libctx, "CMAC", propertyString/*property queue*/);

        ctx = EVP_MAC_CTX_new(cmac);

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, sizeof(cipher_name));

        *p = OSSL_PARAM_construct_end();

        EVP_MAC_init(ctx, key, key_size, params);

        EVP_MAC_update(ctx, plaintext, plaintextLength);

        EVP_MAC_final(ctx, NULL, &out_len, 0);

        tag = (byte*)OPENSSL_zalloc(out_len);

        EVP_MAC_final(ctx, tag, &out_len, out_len);

        *tag_size = (int)out_len;

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(cmac);

        return tag;
    }

    static byte* cmac_with_prefix(byte* data, int data_len, int prefix, byte* key, int key_size, int* tag_size)
    {
        size_t t = sizeof(prefix);
        size_t total = data_len + 16;
        byte* input = (byte*)OPENSSL_zalloc(total);

        u_long big_endi_prefix = htonl(prefix);

        memset(input, 0, 16 - t);
        memcpy(input + 16 - t, (void*)&big_endi_prefix, t);

        if (data_len > 0)
            memcpy(input + 16, data, data_len);

        byte* tag = generateCMAC_3(input, total, key, key_size, tag_size);
        OPENSSL_free(input);
        return tag;
    }

    //==========================================================================================//

    Cipher::Cipher(bool _fEncrypt) :
        fEncrypt(_fEncrypt),
        pKey(NULL),
        nKeyLength(0),
        pIV(NULL),
        nIVLength(0),
        nBytesToBeSkipped(0),
        nBytesToBeInjected(0),
        nBytesAlreadyInjected(0),
        pBytesToBeInjected(NULL),
        pBioOutput(BIO_new(BIO_s_mem())),
        pBioCipherFilter(NULL),
        isBioConnected(false)
    {
        memset(aFullTransformationName, 0, sizeof(aFullTransformationName));
    }

    Cipher::~Cipher()
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
        if (pIV != NULL)
        {
            OPENSSL_free(pIV);
        }
    }

    int Cipher::retrieveOutput(byte* pOutput, int nOffset, int nLength)
    {
        bool isContinue = dealWithSkippingWhenRetrieveOutput(pOutput, nOffset, nLength);
        if (isContinue)
        {
            int nInject = dealWithInjectionWhenRetrieveOutput(pOutput, nOffset, nLength);
            int nCopy = dealWithCopyWhenRetrieveOutput(pOutput, nOffset, nLength, nInject);
            return nCopy + nInject;
        }
        else
        {
            return 0;
        }
    }

    bool Cipher::dealWithSkippingWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength)
    {
        if (nBytesToBeSkipped > 0)
        {
            BYTE* pSkip = (BYTE*)OPENSSL_zalloc(nBytesToBeSkipped);
            int bytesRead = BIO_read(pBioOutput, pSkip, nBytesToBeSkipped);
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

    int Cipher::dealWithInjectionWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength)
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

    int Cipher::dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject)
    {
        int nCopy = nLength - nInject;
        int bytesRead = 0;
        if (nCopy > 0)
        {
            bytesRead = BIO_read(pBioOutput, pOutput + nOffset + nInject, nCopy);
            if (bytesRead == -1)
                bytesRead = 0;
        }

        return bytesRead;
    }

    int Cipher::skipBytes(int _nBytesToBeSkipped)
    {
        nBytesToBeSkipped = _nBytesToBeSkipped;
        return nBytesToBeSkipped;
    }

    int Cipher::injectBytes(byte* pInjectBytes, int nOffset, int _nBytesToBeInjected)
    {
        pBytesToBeInjected = (byte*)OPENSSL_realloc(pBytesToBeInjected, nBytesToBeInjected + _nBytesToBeInjected);
        memcpy(pBytesToBeInjected + nBytesToBeInjected, pInjectBytes, _nBytesToBeInjected);
        nBytesToBeInjected += _nBytesToBeInjected;
        return nBytesToBeInjected;
    }

    void Cipher::shallowCopyKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
    {
        this->pKey = _pKey;
        this->nKeyLength = _nKeyLength;
        this->pIV = _pIV;
        this->nIVLength = _nIVLength;
    }

    bool Cipher::setupBioChain(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
    {
        EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, aFullTransformationName, NULL/*prop queue*/);

        pBioCipherFilter = BIO_new(BIO_f_cipher());
        BIO_set_cipher(pBioCipherFilter, evp_cipher, _pKey, _pIV, (int)fEncrypt);
        BIO_push(pBioCipherFilter, pBioOutput);
        isBioConnected = true;
        return true;
    }

    bool Cipher::reset()
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
        return setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
    }

    //==========================================================================================//

    AESEAX::AESEAX(bool _fEncrypt):
        Cipher(_fEncrypt),
        big_N(NULL),
        big_H(NULL),
        data_size(0),
        nBufferedPotentialTagLength(0),
        isTagProcessed(false),
        pBioCiphertextBackup(BIO_new(BIO_s_mem()))
    {
        memset(potentialTag, 0, sizeof(potentialTag));
    }

    AESEAX::~AESEAX()
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

    bool AESEAX::reset()
    {
        data_size = 0;
        BIO_reset(pBioCiphertextBackup);
        memset(potentialTag, 0, sizeof(potentialTag));
        nBufferedPotentialTagLength = 0;
        isTagProcessed = false;
        return Cipher::reset();
    }

    bool AESEAX::setKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
    {
        // 1. set full transformation name
        char const* p = "AES-128-CTR";
        memcpy(aFullTransformationName, p, strlen(p));

        // 2. shallow copy key and IV
        shallowCopyKeyAndIV(_pKey, _nKeyLength, _pIV, _nIVLength);
        
        // 3. set up BIO chain
        int tag_size;
        big_N = cmac_with_prefix(pIV, nIVLength, 0, pKey, nKeyLength, &tag_size);
        big_H = cmac_with_prefix(NULL, 0, 1, pKey, nKeyLength, &tag_size);

        setupBioChain(_pKey, _nKeyLength, big_N, tag_size);

        return true;
    }

    bool AESEAX::submitInput(byte* pInput, int nOffset, int nLength)
    {
        if (fEncrypt)
        {
            BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
            data_size += nLength;
        }
        else
        {
            int total = nBufferedPotentialTagLength + nLength;
            if (total > 16)
            {
                int send = total - 16;
                data_size += send;
                if (send >= nBufferedPotentialTagLength)
                {
                    BIO_write(pBioCipherFilter, potentialTag, nBufferedPotentialTagLength);
                    BIO_write(pBioCiphertextBackup, potentialTag, nBufferedPotentialTagLength);
                    send -= nBufferedPotentialTagLength;
                    BIO_write(pBioCipherFilter, pInput + nOffset, send);
                    BIO_write(pBioCiphertextBackup, pInput + nOffset, send);
                    memcpy(potentialTag, pInput + nOffset + send, 16);
                }
                else
                {
                    byte tmp[16];
                    memcpy(tmp, potentialTag, 16);
                    BIO_write(pBioCipherFilter, potentialTag, send);
                    BIO_write(pBioCiphertextBackup, potentialTag, send);
                    memcpy(potentialTag, tmp + send, nBufferedPotentialTagLength - send);
                    memcpy(potentialTag + nBufferedPotentialTagLength - send, pInput + nOffset, nLength);
                }
                nBufferedPotentialTagLength = 16;   
            }
            else
            {
                memcpy(potentialTag + nBufferedPotentialTagLength, pInput + nOffset, nLength);
                nBufferedPotentialTagLength += nLength;
            }
        }
        return true;
    }


    bool AESEAX::endInput()
    {
        int tag_size;
        byte* ciphertext = (byte*)OPENSSL_zalloc(data_size);
        byte tag[16];
        byte one_block[16];

        int bytesFromBackup = BIO_read(pBioCiphertextBackup, ciphertext, data_size);

        int bytesFromMainOutput = 0;

        if (bytesFromBackup < data_size)
        {
            bytesFromMainOutput = BIO_read(pBioOutput, ciphertext + bytesFromBackup, data_size - bytesFromBackup);
            BIO_write(pBioOutput, ciphertext + bytesFromBackup, data_size - bytesFromBackup);
        }

        byte* big_C = cmac_with_prefix(ciphertext, data_size, 2, pKey, nKeyLength, &tag_size);

        xorbuf(one_block, big_N, big_C, 16);
        xorbuf(tag, one_block, big_H, 16);

        OPENSSL_free(big_C);
        OPENSSL_free(ciphertext);

        if (fEncrypt)
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

    int AESEAX::dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject)
    {
        int nCopy = nLength - nInject;
        int bytesRead = 0;
        int bytesRead2 = 0;
        if (nCopy > 0)
        {
            bytesRead = BIO_read(pBioOutput, pOutput + nOffset + nInject, nCopy);
            if (bytesRead == -1)
                bytesRead = 0;

            if (fEncrypt && !isTagProcessed)
            {
                BIO_write(pBioCiphertextBackup, pOutput + nOffset + nInject, bytesRead);
            }
        }
        return nInject + bytesRead + bytesRead2;
    }

    //==========================================================================================//

    CBC::CBC(bool _fEncrypt):Cipher(_fEncrypt),pChosenCipherName(NULL)
    {
    }

    bool CBC::setKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
    {
        // 1. set full transformation name
        memcpy(aFullTransformationName, pChosenCipherName, strlen(pChosenCipherName));

        // 2. shallow copy key and IV
        shallowCopyKeyAndIV(_pKey, _nKeyLength, _pIV, _nIVLength);

        // 3. set up BIO chain
        setupBioChain(_pKey, _nKeyLength, _pIV, _nIVLength);
        return true;
    }

    bool CBC::submitInput(byte* pInput, int nOffset, int nLength)
    {
        BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
        return true;
    }

    bool CBC::endInput()
    {
        BIO_flush(pBioCipherFilter);
        return true;
    }

    //==========================================================================================//

    AESCBC::AESCBC(bool isEncrypt) : CBC(isEncrypt)
    {
        pChosenCipherName = cipherName[0];
    }
    
    DES3CBC::DES3CBC(bool isEncrypt) : CBC(isEncrypt) 
    {
        pChosenCipherName = cipherName[1];
    }

    //==========================================================================================//

    AESGCM::AESGCM (bool _fEncrypt):Cipher(_fEncrypt), nBufferedPotentialTagLength(0)
    {
        memset(potentialTag, 0, sizeof(potentialTag));
    }

    bool AESGCM::reset()
    {
        memset(potentialTag, 0, sizeof(potentialTag));
        nBufferedPotentialTagLength = 0;
        return Cipher::reset();
    }

    bool AESGCM::setKeyAndIV(byte* _pKey, int _nKeyLength, byte* _pIV, int _nIVLength)
    {
        // 1. set full transformation name
        char const* p = "AES-128-GCM";
        memcpy(aFullTransformationName, p, strlen(p));

        // 2. shallow copy key and IV
        shallowCopyKeyAndIV(_pKey, _nKeyLength, _pIV, _nIVLength);

        // 3. set up BIO chain
        EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, aFullTransformationName, NULL/*prop queue*/);
        
        pBioCipherFilter = BIO_new(BIO_f_cipher());

        if (nIVLength == 12)
        {
            BIO_set_cipher(pBioCipherFilter, evp_cipher, pKey, pIV, (int)fEncrypt);
        }
        else
        {
            BIO_set_cipher(pBioCipherFilter, evp_cipher, pKey, NULL, (int)fEncrypt);

            EVP_CIPHER_CTX* ctx;
            BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nIVLength, NULL);
            if (fEncrypt)
            {
                EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, pIV);
            }
            else
            {
                EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, pIV);
            }
        }
        BIO_push(pBioCipherFilter, pBioOutput);
        isBioConnected = true;

        return true;
    }

    bool AESGCM::submitInput(byte* pInput, int nOffset, int nLength)
    {
        if (fEncrypt)
        {
            BIO_write(pBioCipherFilter, pInput + nOffset, nLength);
        }
        else
        {
            int total = nBufferedPotentialTagLength + nLength;
            if (total > 16)
            {
                int send = total - 16;
                if (send >= nBufferedPotentialTagLength)
                {
                    BIO_write(pBioCipherFilter, potentialTag, nBufferedPotentialTagLength);
                    send -= nBufferedPotentialTagLength;
                    BIO_write(pBioCipherFilter, pInput + nOffset, send);
                    memcpy(potentialTag, pInput + nOffset + send, 16);
                        
                }
                else
                {
                    byte tmp[16];
                    memcpy(tmp, potentialTag, 16);
                    BIO_write(pBioCipherFilter, potentialTag, send);
                    memcpy(potentialTag, tmp + send, nBufferedPotentialTagLength - send);
                    memcpy(potentialTag + nBufferedPotentialTagLength - send, pInput + nOffset, nLength);
                }
                nBufferedPotentialTagLength = 16;
            }
            else
            {
                memcpy(potentialTag + nBufferedPotentialTagLength, pInput + nOffset, nLength);
                nBufferedPotentialTagLength += nLength;
            }
        }
        return true;
    }

    bool AESGCM::endInput()
    {
        if (fEncrypt)
        {
            BIO_flush(pBioCipherFilter);
            EVP_CIPHER_CTX* ctx;
            BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
            byte tag[16];
            OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
            EVP_CIPHER_CTX_get_params(ctx, params);
            BIO_write(pBioOutput, tag, 16);
        }
        else
        {
            EVP_CIPHER_CTX* ctx;
            BIO_get_cipher_ctx(pBioCipherFilter, &ctx);
            OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                (void*)potentialTag, 16);

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
    
    int AESGCM::dealWithCopyWhenRetrieveOutput(byte* pOutput, int nOffset, int nLength, int nInject)
    {
        int nCopy = nLength - nInject;
        int bytesRead = 0;
        if (nCopy > 0)
        {
            bytesRead = BIO_read(pBioOutput, pOutput + nOffset + nInject, nCopy);
            if (bytesRead == -1)
                bytesRead = 0;
        }
        return nInject + bytesRead;
    }

    //==========================================================================================//

    bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
    {
        return pCipher->setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
    }

    bool CipherSubmitInput(Cipher* pCipher, byte* pInput, int nOffset, int nLength)
    {
        return pCipher->submitInput(pInput, nOffset, nLength);
    }

    bool CipherEndInput(Cipher* pCipher)
    {
        return pCipher->endInput();
    }

    int CipherRetrieveOutput(Cipher* pCipher, byte* pOutput, int nOffset, int nLength)
    {
        return pCipher->retrieveOutput(pOutput, nOffset, nLength);
    }

    Cipher* CipherInitialize(int nAlgorithm, bool isEncrypt)
    {
        switch (nAlgorithm)
        {
        case 1:
            return (Cipher*) new AESCBC(isEncrypt);
            
        case 2:
            return (Cipher*) new AESEAX(isEncrypt);
            
        case 3:
            return (Cipher*) new AESGCM(isEncrypt);
            
        case 4:
            return (Cipher*) new DES3CBC(isEncrypt);
        default:
            return NULL;
        }
    }

    bool CipherReset(Cipher* p)
    {
        return p->reset();
    }

    bool CipherRelease(Cipher* p)
    {
        delete p;
        return true;
    }
}