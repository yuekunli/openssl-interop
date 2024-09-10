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


#include "cipher_openssl2.h"

typedef unsigned char byte;


#define ___ENCRYPTION_ALGORITHM_AES256_CBC 1
#define ___ENCRYPTION_ALGORITHM_AES256_EAX 2
#define ___ENCRYPTION_ALGORITHM_AES256_GCM 3
#define ___ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC 4


#define ___BLOCK_SIZE_AES256_CBC  16
#define ___BLOCK_SIZE_AES256_EAX  16
#define ___BLOCK_SIZE_AES256_GCM  16
#define ___BLOCK_SIZE_TRIPLE_DES_CBC 8


#define ___IV_LENGTH_AES256_CBC 16
#define ___IV_LENGTH_AES256_EAX 256
#define ___IV_LENGTH_AES256_GCM 128
#define ___IV_LENGTH_TRIPLE_DES_CBC 8


#define ___KEY_TYPE_NONE 75

namespace CO2 {


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

    static void incrementWord32(unsigned char a[4])
    {
        for (int i = 3; i >= 0; i--)
        {
            unsigned char b = a[i];
            if (b < 255)
            {
                a[i]++;
                for (int j = i + 1; j < 4; j++)
                {
                    a[j] = 0;
                }
                return;
            }
            else if (i == 0)
            {
                memset(a, 0, 4);
                return;
            }
        }
    }


    byte* aes128_block_encrypt(byte* data, int data_len, byte* key)
    {
        EVP_CIPHER* aes = NULL;
        EVP_CIPHER_CTX* aesctx = NULL;

        byte* out = (byte*)OPENSSL_zalloc(data_len);
        int aes_len = 0;

        aes = EVP_CIPHER_fetch(fips_libctx, "AES-128-ECB", propertyString/*property queue*/);
        aesctx = EVP_CIPHER_CTX_new();

        EVP_EncryptInit_ex(aesctx, aes, NULL/*implementation*/, key, NULL/*iv*/);

        EVP_CIPHER_CTX_set_padding(aesctx, 0);

        EVP_EncryptUpdate(aesctx, out, &aes_len, data, data_len);

        EVP_CIPHER_CTX_free(aesctx);
        EVP_CIPHER_free(aes);
        return out;
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

// =====================
//   EAX
// =====================


    byte* aes128_ctr(byte* data, int data_len, byte* key, byte* iv)
    {
        int r = data_len % 16;
        int blocks = r > 0 ? (data_len / 16 + 1) : (data_len / 16);

        byte* out = NULL;
        out = (byte*)OPENSSL_zalloc(data_len);

        byte one_block[16];
        memcpy(one_block, iv, 16);
        byte ctr[4];
        memcpy(ctr, iv + 12, 4);

        byte* ctr_concatenate = NULL;
        ctr_concatenate = (byte*)OPENSSL_zalloc(blocks * 16);

        int i = 0;
        while (i < blocks)
        {
            memcpy(ctr_concatenate + (i * 16), one_block, 16);
            i++;
            incrementWord32(ctr);
            memcpy(one_block + 12, ctr, 4);
        }

        byte* encrypted_ctr = aes128_block_encrypt(ctr_concatenate, blocks * 16, key);

        xorbuf(out, data, encrypted_ctr, data_len);

        OPENSSL_free(ctr_concatenate);
        OPENSSL_free(encrypted_ctr);

        return out;
    }


    byte* aes128_ctr2(byte* data, int data_len, byte* key, byte* iv)
    {
        byte* out = (byte*)OPENSSL_zalloc(data_len);
        int len = 0;
        EVP_CIPHER* c = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-CTR", NULL/*prop queue*/);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex2(ctx, c, key, iv, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        EVP_EncryptUpdate(ctx, out, &len, data, data_len);

        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(c);
        return out;
    }



    //byte* generateCMAC_3(byte* plaintext, int plaintextLength, byte* key, int key_size, int* tag_size)


    byte* cmac_with_prefix(byte* data, int data_len, int prefix, byte* key, int key_size, int* tag_size)
    {
        size_t t = sizeof(prefix);
        size_t total = data_len + 16;
        byte* input = (byte*)OPENSSL_zalloc(total);

        //memset(input, 0, 16);
        //memcpy(input + 15, (byte*)&prefix, 1);

        u_long big_endi_prefix = htonl(prefix);

        memset(input, 0, 16 - t);
        memcpy(input + 16 - t, (void*)&big_endi_prefix, t);

        if (data_len > 0)
            memcpy(input + 16, data, data_len);

        byte* tag = generateCMAC_3(input, total, key, key_size, tag_size);
        OPENSSL_free(input);
        return tag;
    }

    byte* eax_encrypt(byte* data, int data_len, byte* key, int key_size, byte* iv, int iv_size)
    {
        int total = data_len + 16;
        byte* out = (byte*)OPENSSL_zalloc(total);
        int tag_size;
        byte* big_N = cmac_with_prefix(iv, iv_size, 0, key, key_size, &tag_size);

        byte* big_H = cmac_with_prefix(NULL, 0, 1, key, key_size, &tag_size);

        byte* ciphertext = aes128_ctr2(data, data_len, key, big_N);

        byte* big_C = cmac_with_prefix(ciphertext, data_len, 2, key, key_size, &tag_size);

        byte one_block[16];
        byte tag[16];
        xorbuf(one_block, big_N, big_C, 16);
        xorbuf(tag, one_block, big_H, 16);

        memcpy(out, ciphertext, data_len);
        memcpy(out + data_len, tag, 16);

        OPENSSL_free(big_N);
        OPENSSL_free(big_C);
        OPENSSL_free(big_H);
        OPENSSL_free(ciphertext);

        return out;
    }

    byte* eax_decrypt(byte* data, int data_len, byte* key, int key_size, byte* iv, int iv_size)
    {
        int text_len = data_len - 16;
        int tag_size;

        byte tag_to_be_verified[16];
        memcpy(tag_to_be_verified, data + text_len, 16);

        byte* big_N = cmac_with_prefix(iv, iv_size, 0, key, key_size, &tag_size);

        byte* big_H = cmac_with_prefix(NULL, 0, 1, key, key_size, &tag_size);

        byte* big_C = cmac_with_prefix(data, text_len, 2, key, key_size, &tag_size);

        byte one_block[16];
        byte tag[16];
        xorbuf(one_block, big_N, big_C, 16);
        xorbuf(tag, one_block, big_H, 16);

        int diff = memcmp(tag, tag_to_be_verified, 16);

        if (diff != 0)
        {
            return NULL;
        }

        byte* plaintext = aes128_ctr(data, text_len, key, big_N);

        OPENSSL_free(big_N);
        OPENSSL_free(big_C);
        OPENSSL_free(big_H);

        return plaintext;
    }

    //===================================================================
    //===================================================================



    AESEAX::AESEAX(bool _fEncrypt)
    {
        nBlockSize = 16;
        fEncrypt = _fEncrypt;
        pBIOOutput = BIO_new(BIO_s_mem());
        pBIOCipherOutputBackup = BIO_new(BIO_s_mem());
        pBIOCipher = NULL;
        fBioConnected = false;
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
        if (big_C != NULL)
        {
            OPENSSL_free(big_C);
        }

        if (fBioConnected)
        {
            BIO_free_all(pBIOCipher);
        }
        else
        {
            if (pBIOOutput != NULL)
            {
                BIO_set_flags(pBIOOutput, BIO_FLAGS_MEM_RDONLY);
                BIO_free(pBIOOutput);
            }
            if (pBIOCipher != NULL)
            {
                BIO_free(pBIOCipher);
            }
        }
        BIO_set_flags(pBIOCipherOutputBackup, BIO_FLAGS_MEM_RDONLY);
        BIO_free(pBIOCipherOutputBackup);
    }

    bool AESEAX::setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
    {
        EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-CTR", NULL/*prop queue*/);
        int tag_size;
        big_N = cmac_with_prefix(pIV, nIVLength, 0, pKey, nKeyLength, &tag_size);
        big_H = cmac_with_prefix(NULL, 0, 1, pKey, nKeyLength, &tag_size);

        BIO* bio_cipher = BIO_new(BIO_f_cipher());
        BIO_set_cipher(bio_cipher, evp_cipher, pKey, big_N, (int)fEncrypt);

        BIO_push(bio_cipher, pBIOOutput);
        fBioConnected = true;
        pBIOCipher = bio_cipher;

        return true;
    }

    bool AESEAX::submitInput(byte* pInput, int nOffset, int nLength)
    {
        BIO_write(pBIOCipher, pInput + nOffset, nLength);
        data_size += nLength;
        return true;
    }


    bool AESEAX::endInput()
    {
        isInputEnd = true;
        return true;
    }

    void AESEAX::processTag()
    {
        int tag_size;
        byte* ciphertext = (byte*)OPENSSL_zalloc(data_size);
        
        BIO_read(pBIOCipherOutputBackup, ciphertext, data_size);
        
        big_C = cmac_with_prefix(ciphertext, data_size, 2, pKey, nKeyLength, &tag_size);

        byte one_block[16];
        byte tag[16];
        xorbuf(one_block, big_N, big_C, 16);
        xorbuf(tag, one_block, big_H, 16);

        BIO_write(pBIOOutput, tag, sizeof(tag));
    }

    int AESEAX::retrieveOutput(byte* pOutput, int nOffset, int nLength)
    {
        int nInject = 0, nCopy = 0;

        if (nBytesToBeSkipped > 0)
        {
            BYTE* pSkip = (BYTE*)OPENSSL_zalloc(nBytesToBeSkipped);
            int bytesRead = BIO_read(pBIOOutput, pSkip, nBytesToBeSkipped);

            BIO_write(pBIOCipherOutputBackup, pSkip, bytesRead); // !!!
            
            if (bytesRead < nBytesToBeSkipped)
            {

                if (isInputEnd)
                {
                    processTag();
                }

                OPENSSL_free(pSkip);
                return 0;
            }
            nBytesToBeSkipped -= bytesRead;
            OPENSSL_free(pSkip);
        }

        nInject = min(nLength, nBytesToBeInjected);
        if (nInject > 0)
        {
            BYTE* pInjectStart = (pBytesToBeInjected + nBytesAlreadyInjected);
            memcpy(pOutput + nOffset, pInjectStart, nInject);
            nBytesToBeInjected -= nInject;
            nBytesAlreadyInjected += nInject;
        }
        nCopy = nLength - nInject;
        int bytesRead = 0;
        int bytesRead2 = 0;
        if (nCopy > 0)
        {
            bytesRead = BIO_read(pBIOOutput, pOutput + nOffset + nInject, nCopy);

            BIO_write(pBIOCipherOutputBackup, pOutput + nOffset + nInject, bytesRead);  // !!!

            if (bytesRead < nCopy && isInputEnd)
            {
                processTag();
                int diff = nCopy - bytesRead;
                bytesRead2 = BIO_read(pBIOOutput, pOutput + nOffset + nInject + bytesRead, diff);

            }
        }
        return nInject + bytesRead + bytesRead2;
    }

	//===================================================================
    //===================================================================



#if 0
    class CBC : Cipher
    {
    public:

        BIO* pBIOOutput;
        BIO* pBIOCipher;
        bool fBioConnected;
        EVP_CIPHER* evp_cipher;

        void initialize(bool _fEncrypt)
        {
            nBlockSize = 0;
            fEncrypt = _fEncrypt;
            pBIOOutput = BIO_new(BIO_s_mem());
            pBIOCipher = NULL;
            fBioConnected = false;
        }

        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
        {
            //EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-CBC", NULL/*prop queue*/);
            BIO* bio_cipher = BIO_new(BIO_f_cipher());
            BIO_set_cipher(bio_cipher, evp_cipher, pKey, pIV, (int)fEncrypt);
            BIO_push(bio_cipher, pBIOOutput);
            fBioConnected = true;
            pBIOCipher = bio_cipher;
            return true;
        }

        bool relese(Cipher* pCipher)
        {
            if (fBioConnected)
            {
                BIO_free_all(pBIOCipher);
            }
            else
            {
                if (pBIOOutput != NULL)
                {
                    BIO_set_flags(pBIOOutput, BIO_FLAGS_MEM_RDONLY);
                    BIO_free(pBIOOutput);
                }
                if (pBIOCipher != NULL)
                {
                    BIO_free(pBIOCipher);
                }
            }
            OPENSSL_free(pCipher);
        }

        bool submitInput(byte* pInput, int nOffset, int nLength)
        {
            BIO_write(pBIOCipher, pInput + nOffset, nLength);
            return true;
        }

        bool endInput()
        {
            BIO_flush(pBIOCipher);
        }

        int retrieveOutput(byte* pOutput, int nOffset, int nLength)
        {
            int nInject = 0, nCopy = 0;

            if (nBytesToBeSkipped > 0)
            {
                BYTE* pSkip = (BYTE*)OPENSSL_zalloc(nBytesToBeSkipped);
                int bytesRead = BIO_read(pBIOOutput, pSkip, nBytesToBeSkipped);
                if (bytesRead < nBytesToBeSkipped)
                {
                    OPENSSL_free(pSkip);
                    return 0;
                }
                nBytesToBeSkipped -= bytesRead;
                OPENSSL_free(pSkip);
            }

            nInject = min(nLength, nBytesToBeInjected);
            if (nInject > 0)
            {
                BYTE* pInjectStart = (pBytesToBeInjected + nBytesAlreadyInjected);
                memcpy(pOutput + nOffset, pInjectStart, nInject);
                nBytesToBeInjected -= nInject;
                nBytesAlreadyInjected += nInject;
            }
            nCopy = nLength - nInject;
            int bytesRead = 0;
            if (nCopy > 0)
            {
                bytesRead = BIO_read(pBIOOutput, pOutput + nOffset + nInject, nCopy);
            }

            return nInject + bytesRead;
        }
    };




    class AESCBC : CBC
    {
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
        {
            evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-CBC", NULL/*prop queue*/);
            CBC::setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        }
    };

    class DES3CBC : CBC
    {
        bool setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
        {
            evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "DES-EDE3-CBC", NULL/*prop queue*/);
            CBC::setKeyAndIV(pKey, nKeyLength, pIV, nIVLength);
        }
    };
#endif





        AESGCM::AESGCM (bool _fEncrypt)
        {
            nBlockSize = 0;
            fEncrypt = _fEncrypt;
            pBIOOutput = BIO_new(BIO_s_mem());
            pBIOCipher = NULL;
            fBioConnected = false;
            nBufferedPotentialTagLength = 0;
        }

        AESGCM::~AESGCM()
        {
            if (fBioConnected)
            {
                BIO_free_all(pBIOCipher);
            }
            else
            {
                if (pBIOOutput != NULL)
                {
                    BIO_set_flags(pBIOOutput, BIO_FLAGS_MEM_RDONLY);
                    BIO_free(pBIOOutput);
                }
                if (pBIOCipher != NULL)
                {
                    BIO_free(pBIOCipher);
                }
            }
        }

        bool AESGCM::setKeyAndIV(byte* pKey, int nKeyLength, byte* pIV, int nIVLength)
        {
            EVP_CIPHER* evp_cipher = EVP_CIPHER_fetch(NULL/*lib context*/, "AES-128-GCM", NULL/*prop queue*/);
            BIO* bio_cipher = BIO_new(BIO_f_cipher());

            if (nIVLength == 12)
            {
                BIO_set_cipher(bio_cipher, evp_cipher, pKey, pIV, (int)fEncrypt);
            }
            else
            {
                BIO_set_cipher(bio_cipher, evp_cipher, pKey, NULL, (int)fEncrypt);

                //EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                EVP_CIPHER_CTX* ctx;
                BIO_get_cipher_ctx(bio_cipher, &ctx);
                //EVP_EncryptInit_ex2(ctx, evp_cipher, pKey, NULL, NULL);
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
            BIO_push(bio_cipher, pBIOOutput);
            fBioConnected = true;
            pBIOCipher = bio_cipher;
            return true;
        }

        bool AESGCM::submitInput(byte* pInput, int nOffset, int nLength)
        {
            if (fEncrypt)
            {
                BIO_write(pBIOCipher, pInput + nOffset, nLength);
            }
            else
            {
                int total = nBufferedPotentialTagLength + nLength;
                if (total > 16)
                {
                    int send = total - 16;
                    if (send >= nBufferedPotentialTagLength)
                    {
                        BIO_write(pBIOCipher, potentialTag, nBufferedPotentialTagLength);
                        send -= nBufferedPotentialTagLength;
                        BIO_write(pBIOCipher, pInput + nOffset, send);
                        memcpy(potentialTag, pInput + nOffset + send, 16);
                        
                    }
                    else
                    {
                        byte tmp[16];
                        memcpy(tmp, potentialTag, 16);
                        BIO_write(pBIOCipher, potentialTag, send);
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
                BIO_flush(pBIOCipher);
                EVP_CIPHER_CTX* ctx;
                BIO_get_cipher_ctx(pBIOCipher, &ctx);
                byte tag[16];
                OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
                params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));
                EVP_CIPHER_CTX_get_params(ctx, params);
                BIO_write(pBIOOutput, tag, 16);
            }
            else
            {
                //BIO_flush(pBIOCipher);
                EVP_CIPHER_CTX* ctx;
                BIO_get_cipher_ctx(pBIOCipher, &ctx);
                OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
                params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                    (void*)potentialTag, 16);

                EVP_CIPHER_CTX_set_params(ctx, params);

                int tmpLen;
                // verify tag
                EVP_DecryptFinal_ex(ctx, NULL/*can this be NULL?*/, &tmpLen); // must call final if there is padding
            }
            return true;
        }
        int AESGCM::retrieveOutput(byte* pOutput, int nOffset, int nLength)
        {
            int nInject = 0, nCopy = 0;

            if (nBytesToBeSkipped > 0)
            {
                BYTE* pSkip = (BYTE*)OPENSSL_zalloc(nBytesToBeSkipped);
                int bytesRead = BIO_read(pBIOOutput, pSkip, nBytesToBeSkipped);
                if (bytesRead < nBytesToBeSkipped)
                {
                    OPENSSL_free(pSkip);
                    return 0;
                }
                nBytesToBeSkipped -= bytesRead;
                OPENSSL_free(pSkip);
            }

            nInject = min(nLength, nBytesToBeInjected);
            if (nInject > 0)
            {
                BYTE* pInjectStart = (pBytesToBeInjected + nBytesAlreadyInjected);
                memcpy(pOutput + nOffset, pInjectStart, nInject);
                nBytesToBeInjected -= nInject;
                nBytesAlreadyInjected += nInject;
            }
            nCopy = nLength - nInject;
            int bytesRead = 0;
            if (nCopy > 0)
            {
                bytesRead = BIO_read(pBIOOutput, pOutput + nOffset + nInject, nCopy);
            }
            return nInject + bytesRead;
        }
    



}