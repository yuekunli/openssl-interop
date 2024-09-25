#include <stdint.h>
#include <cstring>
#include <string.h>
#include <iostream>
#include <sstream>

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

#include "arbitrary_io_cipher_OpenSSL2.h"

typedef unsigned char byte;

namespace AIO_CIPHER_OPENSSL2 {

    void xorbuf(byte* output, byte* input, byte* mask, int len)
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

    byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size)
    {
        EVP_MAC* cmac = NULL;
        EVP_MAC_CTX* ctx = NULL;
        byte* tag = NULL;
        size_t out_len = 0;
        OSSL_PARAM params[4];
        OSSL_PARAM* p = params;
        char cipher_name[] = "AES-128-CBC";

        cmac = EVP_MAC_fetch(NULL/*lib context*/, "CMAC", NULL/*property queue*/);

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

    byte* cmac_with_prefix(byte* data, int data_len, int prefix, byte* key, int key_size, int* tag_size)
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

    std::string BlockCipher::getFormalName()
    {
        char const* name = getAlgorithmName();
        int b = getBlockSize();
        std::stringstream ss;
        ss << name << "-" << (b*8);
        return ss.str();
    }

    char const* AES::getAlgorithmName()
    {
        return "AES";
    }

    int AES::getBlockSize()
    {
        return 16;
    }

    char const* DES3::getAlgorithmName()
    {
        return "DES-EDE3";
    }

    int DES3::getBlockSize()
    {
        return 8;
    }

    std::string DES3::getFormalName()
    {
        return getAlgorithmName();
    }

    //==========================================================================================//

    bool CipherSetKeyAndInitialVector(Cipher* pCipher, byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
    {
        switch (pCipher->nAlgo)
        {
        case 1:
            return pCipher->pCbcAes->setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        case 2:
            return pCipher->pEaxAes->setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        case 3:
            return pCipher->pGcmAes->setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        case 4:
            return pCipher->pCbcDes3->setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        default:
            return false;
        }
    }
    
    bool CipherSubmitInput(Cipher* pCipher, byte* pInput, int nOffset, int nLength)
    {
        switch (pCipher->nAlgo)
        {
        case 1:
            return pCipher->pCbcAes->submitInput(pInput, nOffset, nLength);
        case 2:
            return pCipher->pEaxAes->submitInput(pInput, nOffset, nLength);
        case 3:
            return pCipher->pGcmAes->submitInput(pInput, nOffset, nLength);
        case 4:
            return pCipher->pCbcDes3->submitInput(pInput, nOffset, nLength);
        default:
            return false;
        }
    }

    bool CipherEndInput(Cipher* pCipher)
    {
        switch (pCipher->nAlgo)
        {
        case 1:
            return pCipher->pCbcAes->endInput();
        case 2:
            return pCipher->pEaxAes->endInput();
        case 3:
            return pCipher->pGcmAes->endInput();
        case 4:
            return pCipher->pCbcDes3->endInput();
        default:
            return false;
        }
    }

    int CipherRetrieveOutput(Cipher* pCipher, byte* pOutput, int nOffset, int nLength)
    {
        switch (pCipher->nAlgo)
        {
        case 1:
            return pCipher->pCbcAes->retrieveOutput(pOutput, nOffset, nLength);
        case 2:
            return pCipher->pEaxAes->retrieveOutput(pOutput, nOffset, nLength);
        case 3:
            return pCipher->pGcmAes->retrieveOutput(pOutput, nOffset, nLength);
        case 4:
            return pCipher->pCbcDes3->retrieveOutput(pOutput, nOffset, nLength);
        default:
            return 0;
        }
    }

    Cipher* CipherInitialize(int nAlgorithm, bool isEncrypt)
    {
        Cipher* p = new Cipher(nAlgorithm);
        
        switch (nAlgorithm)
        {
        case 1:
            p->pCbcAes = new CBC<AES>(isEncrypt);
            break;
        case 2:
            p->pEaxAes = new EAX<AES>(isEncrypt);
            break;
        case 3:
            p->pGcmAes = new GCM<AES>(isEncrypt);
            break;
        case 4:
            p->pCbcDes3 = new CBC<DES3>(isEncrypt);
            break;
        default:
            delete p;
            return NULL;
        }
        return p;
    }

    bool CipherRelease(Cipher* p)
    {
        delete p;
        return true;
    }

    bool CipherReset(Cipher* p)
    {
        switch (p->nAlgo)
        {
        case 1:
            return p->pCbcAes->reset();
        case 2:
            return p->pEaxAes->reset();
        case 3:
            return p->pGcmAes->reset();
        case 4:
            return p->pCbcDes3->reset();
        default:
            return false;
        }
    }

    int CipherSkipBytes(Cipher* p, int nSkipBytesCount)
    {
        switch (p->nAlgo)
        {
        case 1:
            return p->pCbcAes->skipBytes(nSkipBytesCount);
        case 2:
            return p->pEaxAes->skipBytes(nSkipBytesCount);
        case 3:
            return p->pGcmAes->skipBytes(nSkipBytesCount);
        case 4:
            return p->pCbcDes3->skipBytes(nSkipBytesCount);
        default:
            return 0;
        }
    }

    int CipherInjectBytes(Cipher* p, byte* pInjectBytes, int nOffset, int nInjectBytesCount)
    {
        switch (p->nAlgo)
        {
        case 1:
            return p->pCbcAes->injectBytes(pInjectBytes, nOffset, nInjectBytesCount);
        case 2:
            return p->pEaxAes->injectBytes(pInjectBytes, nOffset, nInjectBytesCount);
        case 3:
            return p->pGcmAes->injectBytes(pInjectBytes, nOffset, nInjectBytesCount);
        case 4:
            return p->pCbcDes3->injectBytes(pInjectBytes, nOffset, nInjectBytesCount);
        default:
            return 0;
        }
    }
}