// C headers
#include <stdbool.h>
#include <cstddef>
#include <stdint.h>
#include <cstring>
#include <string.h>
#include<iostream>



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



// Windows hearder
#include <Windows.h>


typedef unsigned char byte;

namespace ADAPTIVA_AUX {
    char* base32Encode(byte* p, size_t l);
    byte* base32Decode(char* pszIn, int* outSize);
}

namespace ADAPTIVA_OPENSSL {


#define com_adaptiva_fips_CryptoConstants_DH1024 1
#define com_adaptiva_fips_CryptoConstants_DH2048 2
#define com_adaptiva_fips_CryptoConstants_DHEC256 3

#define com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256 1
#define com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384 2
#define com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512 3


#define com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC 1
#define com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX 2
#define com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM 3
#define com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC 4


#define com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_CBC  16
#define com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_GCM  16
#define com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_TRIPLE_DES_CBC 8


#define com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_CBC 16
#define com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_EAX 0   // Java code has this macro as 256, OpenSSL has no EAX implementation
#define com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_GCM 128 /*256*/ // OpenSSL can support up to 128 bytes IV, Crypto++ can support up to 2^64 - 1
#define com_adaptiva_fips_CryptoConstants_IV_LENGTH_TRIPLE_DES_CBC 8


#define com_adaptiva_fips_CryptoConstants_KEY_TYPE_NONE 75 // Set this to a non-zero value, so that debugger can show encrypted buffer.


#define LOG3 printf


char* getFormattedString(char const* pszformat, ...)
{
    va_list v;
    va_start(v, pszformat);
    int len = _vscprintf(pszformat, v) + 1;
    char* pszBuffer = (char*)malloc(len * sizeof(char));
    if (pszBuffer)
        memset(pszBuffer, 0, len);
    vsnprintf_s(pszBuffer, len, len, pszformat, v);
    return pszBuffer;
}

void zeroAndFreeBuffer(void* p, int l)
{
    memset(p, 0, l);
    free(p);
}

void* memdup(void* p, int l)
{
    void* out = malloc(l);
    memcpy(out, p, l);
    return out;
}



char const *logMessage = "Result:%s,  Action:%s,  Code:%ul,  FromLower:%d,  Message:%s\n";


// =========================
// Random Number Generation
// =========================

byte RngGenerateByte()
{
    byte result;
    if (RAND_bytes(&result, 1) <= 0)
    {
        LOG3(logMessage, "FAIL", "Generate 1 byte random", ERR_get_error(), 1, "");
    }
    return result;
}

DWORD RngGenerateDword()
{
    DWORD result;
    if (RAND_bytes((unsigned char*)(&result), sizeof(DWORD)) <= 0)
    {
        LOG3(logMessage, "FAIL", "Generate DWROD random", ERR_get_error(), 1, "");
    }
    return result;
}

LONGLONG RngGenerateQword()
{
    LARGE_INTEGER x;

    x.LowPart = RngGenerateDword();
    x.HighPart = RngGenerateDword();

    return x.QuadPart;
}

void RngFillByteArrayRegion(byte* pArray, int nStartingOffset, int nBytes)
{
    if (pArray != NULL && nStartingOffset >= 0 && nBytes > 0)
    {
        if (RAND_bytes(pArray+nStartingOffset, nBytes) <= 0)
        {
            LOG3(logMessage, "FAIL", "Generate array random", ERR_get_error(), 1, "");
        }
        return;
    }
    LOG3(logMessage, "FAIL", "Generate array random", 0, 0, "Invalid Input");
}





// ===========================
// Secure Hash  (SHA-2)
// ===========================

struct SecureHashState_t
{
    int hashingAlgorithm;

    EVP_MD *pSha256;
    EVP_MD_CTX *pSha256Ctx;
    EVP_MD *pSha384;
    EVP_MD_CTX *pSha384Ctx;
    EVP_MD *pSha512;
    EVP_MD_CTX *pSha512Ctx;

    int nSecureHashLength;
};

typedef struct SecureHashState_t SecureHashState;


SecureHashState *SHInitialize(int hashingAlgorithm)
{
    SecureHashState *pState = NULL;
    bool success = false;
    if ((pState = (SecureHashState*)OPENSSL_zalloc(sizeof(SecureHashState))) == NULL)
    {
        LOG3(logMessage, "FAIL", "alloc for SecureHashState", 0, 0, "");
        return NULL;
    }
    pState->hashingAlgorithm = hashingAlgorithm;

    OSSL_LIB_CTX *libCtx;
    libCtx = OSSL_LIB_CTX_new();
    if (libCtx == NULL)
    {
        LOG3(logMessage, "FAIL", "Initialize lib context", 0, 0, "");
        goto cleanup;
    }

    switch(pState->hashingAlgorithm)
    {
        case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
            pState->pSha256 = EVP_MD_fetch(libCtx, "SHA256", /*properties*/NULL);
            if (pState->pSha256 == NULL)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA256", 0, 0, "EVP_MD_fetch fail");
                goto cleanup;
            }
            pState->nSecureHashLength = EVP_MD_get_size(pState->pSha256);
            if (pState->nSecureHashLength <= 0)
            {
                LOG3(logMessage, "FAIL", "Get SHA256 hash length", 0, 0, "EVP_MD_get_size fail");
                goto cleanup;
            }
            pState->pSha256Ctx = EVP_MD_CTX_new();
            if (pState->pSha256Ctx == NULL)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA256 Context", 0, 0, "EVP_MD_CTX_new fail");
                goto cleanup;
            }
            if (EVP_DigestInit(pState->pSha256Ctx, pState->pSha256) != 1)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA256", 0, 0, "EVP_DigestInit fail");
                goto cleanup;
            }
            success = true;
            break;
        case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
            pState->pSha384 = EVP_MD_fetch(libCtx, "SHA384", /*properties*/NULL);
            if (pState->pSha384 == NULL)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA384", 0, 0, "EVP_MD_fetch fail");
                goto cleanup;
            }
            pState->nSecureHashLength = EVP_MD_get_size(pState->pSha384);
            if (pState->nSecureHashLength <= 0)
            {
                LOG3(logMessage, "FAIL", "Get SHA384 hash length", 0, 0, "EVP_MD_get_size fail");
                goto cleanup;
            }
            pState->pSha384Ctx = EVP_MD_CTX_new();
            if (pState->pSha384Ctx == NULL)
            {
                LOG3(logMessage, "FAIL", "Initializa SHA384 Context", 0, 0, "EVP_MD_CTX_new fail");
                goto cleanup;
            }
            if (EVP_DigestInit(pState->pSha384Ctx, pState->pSha384) != 1)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA384", 0, 0, "EVP_DigestInit fail");
                goto cleanup;
            }
            success = true;
            break;
        case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
            pState->pSha512 = EVP_MD_fetch(libCtx, "SHA512", /*properties*/NULL);
            if (pState->pSha512 == NULL)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA512", 0, 0, "EVP_MD_fetch fail");
                goto cleanup;                
            }
            pState->nSecureHashLength = EVP_MD_get_size(pState->pSha512);
            if (pState->nSecureHashLength <= 0)
            {
                LOG3(logMessage, "FAIL", "Get SHA512 hash length", 0, 0, "EVP_MD_get_size fail");
                goto cleanup;
            }            
            pState->pSha512Ctx = EVP_MD_CTX_new();
            if (pState->pSha512Ctx == NULL)
            {
                LOG3(logMessage, "FAIL", "Initializa SHA512 Context", 0, 0, "EVP_MD_CTX_new fail");
                goto cleanup;                
            }
            if (EVP_DigestInit(pState->pSha512Ctx, pState->pSha512) != 1)
            {
                LOG3(logMessage, "FAIL", "Initialize SHA512", 0, 0, "EVP_DigestInit fail");
                goto cleanup;
            }
            success = true;
            break;
        default:
            goto cleanup;
            break;
    }
    
    cleanup:

    if (!success)
    {
        switch (hashingAlgorithm)
        {
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
                if (pState->pSha256 != NULL)
                    EVP_MD_free(pState->pSha256);
                if (pState->pSha256Ctx != NULL)
                    EVP_MD_CTX_free(pState->pSha256Ctx);
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
                if (pState->pSha384 != NULL)
                    EVP_MD_free(pState->pSha384);
                if (pState->pSha384Ctx != NULL)
                    EVP_MD_CTX_free(pState->pSha384Ctx);
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
                if (pState->pSha512 != NULL)
                    EVP_MD_free(pState->pSha512);
                if (pState->pSha512Ctx != NULL)
                    EVP_MD_CTX_free(pState->pSha512Ctx);
                break;
            default:
                break;
        }
        OPENSSL_free(pState);
        pState = NULL;
    }
    OSSL_LIB_CTX_free(libCtx);
    return pState;
}

int SHGetDigestLength(SecureHashState *pState)
{
    if (pState != NULL)
        return pState->nSecureHashLength;

    return 0;
}

bool SHUpdate(SecureHashState *pState, byte input)
{
    if (pState != NULL)
    {
        switch(pState->hashingAlgorithm)
        {
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
                if (pState->pSha256 != NULL && pState->pSha256Ctx != NULL)
                {
                    if (EVP_DigestUpdate(pState->pSha256Ctx, &input, 1) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA256 add input", 0, 0, "EVP_DigestUpdate");
                    }
                    return true;
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
                if (pState->pSha384 != NULL && pState->pSha384Ctx != NULL)
                {
                    if (EVP_DigestUpdate(pState->pSha384Ctx, &input, 1) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA384 add input", 0, 0, "EVP_DigestUpdate");
                    }
                    return true;
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
                if (pState->pSha512 != NULL && pState->pSha512Ctx != NULL)
                {
                    if (EVP_DigestUpdate(pState->pSha512Ctx, &input, 1) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA512 add input", 0, 0, "EVP_DigestUpdate");
                    }
                    return true;
                }
                break;
            default:
                break;
        }
    }
    return false;
}

bool SHUpdate(SecureHashState *pState, byte *input, int nOffset, int nLen)
{
    if (pState != NULL && input != NULL && nOffset >= 0 && nLen >0)
    {
        switch(pState->hashingAlgorithm)
        {
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
                if (pState->pSha256 != NULL && pState->pSha256Ctx != NULL)
                {
                    EVP_DigestUpdate(pState->pSha256Ctx, input+nOffset, nLen);
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
                if (pState->pSha384 != NULL && pState->pSha384Ctx != NULL)
                {
                    EVP_DigestUpdate(pState->pSha384Ctx, input+nOffset, nLen);
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
                if (pState->pSha512 != NULL && pState->pSha512Ctx != NULL)
                {
                    EVP_DigestUpdate(pState->pSha512Ctx, input+nOffset, nLen);
                }
                break;
            default:
                break;
        }
    }
    return true;
}

byte *SHDigest(SecureHashState *pState, int *pnByteArraySize)
{
    byte *digest = NULL;
    unsigned int nLen;
    bool success = false;
                                                    /********************************/
                                                    /* MAKE SURE NO ALGO MACRO IS 0 */
                                                    /********************************/
    if (pState != NULL && pnByteArraySize != NULL && pState->hashingAlgorithm != 0)
    {
        if ((digest = (byte*)OPENSSL_malloc(pState->nSecureHashLength)) == NULL)
        {
            LOG3(logMessage, "FAIL", "alloc hash result", 0, 0, "OPENSSL_malloc fail");
            return NULL;
        }
        
        switch(pState->hashingAlgorithm)
        {
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
                if (pState->pSha256 != NULL && pState->pSha256Ctx != NULL)
                {
                    if (EVP_DigestFinal(pState->pSha256Ctx, digest, &nLen) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA256 hash final", 0, 0, "EVP_DigestFinal fail");
                        goto cleanup;
                    }
                    success = true;
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
                if (pState->pSha384 != NULL && pState->pSha384Ctx != NULL)
                {
                    if (EVP_DigestFinal(pState->pSha384Ctx, digest, &nLen) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA384 hash final", 0, 0, "EVP_DigestFinal fail");
                        goto cleanup;
                    }
                    success = true;
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
                if (pState->pSha512 != NULL && pState->pSha512Ctx != NULL)
                {
                    if (EVP_DigestFinal(pState->pSha512Ctx, digest, &nLen) != 1)
                    {
                        LOG3(logMessage, "FAIL", "SHA512 hash final", 0, 0, "EVP_DigestFinal fail");
                        goto cleanup;
                    }
                    success = true;
                }
                break;
            default:
                break;                            
        }

        cleanup:

        if (success)
        {
            if (pState->nSecureHashLength != nLen)
            {
                LOG3(logMessage, "ERROR", "Pre-determined and actual secure hash length mismatch", 0, 0, "");
                return NULL;
            }

            *pnByteArraySize = nLen;
            return digest;
        }
        else
        {
            if (pnByteArraySize != NULL)
               *pnByteArraySize = 0;

            OPENSSL_free(digest);
            return NULL;
        }
    }
    return NULL;
}

bool SHReset(SecureHashState *pState)
{
    if (pState != NULL)
    {
        switch(pState->hashingAlgorithm)
        {
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256:
                if (pState->pSha256 != NULL && pState->pSha256Ctx != NULL)
                {
                    if (EVP_DigestInit(pState->pSha256Ctx, pState->pSha256) != 1) // call EVP_MD_CTX_reset internally
                    {
                        LOG3(logMessage, "FAIL", "Reset SHA256", 0, 0, "EVP_DigestInit fail");
                        return false;
                    }
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA384:
                if (pState->pSha384 != NULL && pState->pSha384Ctx != NULL)
                {
                    if (EVP_DigestInit(pState->pSha384Ctx, pState->pSha384) != 1)
                    {
                        LOG3(logMessage, "FAIL", "Reset SHA384", 0, 0, "EVP_DigestInit fail");
                        return false;
                    }
                }
                break;
            case com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512:
                if (pState->pSha512 != NULL && pState->pSha512Ctx != NULL)
                {
                    if (EVP_DigestInit(pState->pSha512Ctx, pState->pSha512) != 1)
                    {
                        LOG3(logMessage, "FAIL", "Reset SHA512", 0, 0, "EVP_DigestInit fail");
                        return false;
                    }
                }
                break;
            default:
                return false;
        }
        return true;
    }
    return false;
}

bool SHCleanUp(SecureHashState *pState)
{
    if (pState != NULL)
    {
        if (pState->pSha256 != NULL)
            EVP_MD_free(pState->pSha256);

        if (pState->pSha256Ctx != NULL)
            EVP_MD_CTX_free(pState->pSha256Ctx);

        if (pState->pSha384 != NULL)
            EVP_MD_free(pState->pSha384);

        if (pState->pSha384Ctx != NULL)
            EVP_MD_CTX_free(pState->pSha384Ctx);

        if (pState->pSha512 != NULL)
            EVP_MD_free(pState->pSha512);

        if (pState->pSha512Ctx != NULL)
            EVP_MD_CTX_free(pState->pSha512Ctx);
    }
    OPENSSL_free(pState);
    return true;
}

byte *getSecureHash(int hashingAlgorithm, byte *pDataBuffer, int nDataBufferLength, int *pnSecureHashSize)
{
    byte *digest = NULL;
    SecureHashState *pState = NULL;

    if (pDataBuffer == NULL || nDataBufferLength <= 0 || pnSecureHashSize == NULL)
    {
        LOG3(logMessage, "FAIL", "Check input", 0, 0, "Invalid input");
        return NULL;
    }

    if ((pState = SHInitialize(hashingAlgorithm)) == NULL)
    {
        LOG3(logMessage, "FAIL", "Initialize SHA", 0, 0, "");
        goto cleanup;
    }

    if (SHUpdate(pState, pDataBuffer, /*nOffset*/0, nDataBufferLength) == false)
    {
        LOG3(logMessage, "FAIL", "Update input", 0, 0, "");
        goto cleanup;
    }

    if ((digest = SHDigest(pState, pnSecureHashSize)) == NULL)
    {
        LOG3(logMessage, "FAIL", "Finalize digest", 0, 0, "");
        goto cleanup;
    }

    cleanup:

    if (pState != NULL)
        SHCleanUp(pState);

    return digest;
}





// =====================================
// Symmetric Encryption AES or DES3
// =====================================


struct SymmetricCipher_t
{
    int nAlgorithm;
    bool fEncrypt;

    byte *pKey;
    int nKeyLength;

    byte *pInitialVector;
    int nInitialVectorLength;

    int nBlockSize;

    EVP_CIPHER* pImplement;
    EVP_CIPHER_CTX* pCtx;

    int nBytesToBeSkipped;
    int nBytesToBeInjected;
    byte *pBytesToBeInjected;

    BIO *pBIOInput;
    unsigned char *psInput;
    int nInputSize;
};
typedef struct SymmetricCipher_t SymmetricCipher;
typedef struct SymmetricCipher_t Cipher;

byte* generateEncryptionKey(int encrypAlgo, int* pnEncryptKeyLength); // just generate a random number, not in use

// generate initial vectors
bool generateBytesFromKeyMaterial(byte* pKeyMaterial, int nKeyMaterialLength, byte* pByteGenerationBuffer, int nBytesWanted)
{
    if (pKeyMaterial == NULL || nKeyMaterialLength <= 0 || pByteGenerationBuffer == NULL || nBytesWanted <= 0)
        return false;

    int nBytesFilled = 0;
    int nSecureHashSize;

    byte* pSecureHash = getSecureHash(com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA512, pKeyMaterial, nKeyMaterialLength, &nSecureHashSize);

    while (nBytesFilled < nBytesWanted)
    {
        memcpy(pByteGenerationBuffer + nBytesFilled, pSecureHash, min(nSecureHashSize, (nBytesWanted - nBytesFilled)));
        nBytesFilled += nSecureHashSize;
    }
    OPENSSL_free(pSecureHash);
    return true;
}

// return pre-defined macros
int getInitialVectorLength(int encryptionAlgo)
{
    switch (encryptionAlgo)
    {
    case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
        return com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_CBC;

    case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX:
        return com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_EAX;

    case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
        return com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_GCM;

    case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
        return com_adaptiva_fips_CryptoConstants_IV_LENGTH_TRIPLE_DES_CBC;
    }
    return 0;
}

SymmetricCipher *CipherInitialize(int nAlgo, bool fEncrypt)
{
    SymmetricCipher *pSymCipher;

    pSymCipher = (SymmetricCipher*)OPENSSL_zalloc(sizeof(SymmetricCipher));

    //char const *pCipherName[] = {"AEC-256-CBC", "AES-256-GCM", "DES-EDE3-CBC"};

    char const* pCipherName[] = { "AES-128-CBC", "UNDEFINED-AES-EAX", "AES-128-GCM", "DES-EDE3-CBC" };

    char const *pChosen = pCipherName[0];

        switch (nAlgo)
        {
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
            pChosen = pCipherName[0];
            pSymCipher->nBlockSize = com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_CBC;
            break;
            
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX:
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
            pChosen = pCipherName[2];
            pSymCipher->nBlockSize = com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_GCM;
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
            pChosen = pCipherName[3];
            pSymCipher->nBlockSize = com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_TRIPLE_DES_CBC;
            break;
        }

        pSymCipher->fEncrypt = fEncrypt;
        pSymCipher->nAlgorithm = nAlgo;
        pSymCipher->pCtx = EVP_CIPHER_CTX_new();
        pSymCipher->pImplement = EVP_CIPHER_fetch(/*libctx*/ NULL, pChosen, /*property queue*/ NULL);
        pSymCipher->pBIOInput = BIO_new(BIO_s_mem());

    return pSymCipher;
}

bool CipherSetKeyAndInitialVector(SymmetricCipher *pSymCipher, byte *pKey, int nKeyLength, byte *pIV, int nIVLength)
{
    pSymCipher->pKey = pKey;
    pSymCipher->nKeyLength = nKeyLength;
    pSymCipher->pInitialVector = pIV;
    pSymCipher->nInitialVectorLength = nIVLength;

    OSSL_PARAM params[2] = {OSSL_PARAM_END, OSSL_PARAM_END};
    size_t ivlen = 0;

    if (pSymCipher->fEncrypt)
    {
        switch (pSymCipher->nAlgorithm)
        {
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
                EVP_EncryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX:
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
                
                ivlen = com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_GCM;
                if (ivlen == 12)
                {
                    EVP_EncryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
                }
                else
                {
                    EVP_EncryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, NULL /*pIV*/, NULL);
                    EVP_CIPHER_CTX_ctrl(pSymCipher->pCtx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL);
                    EVP_EncryptInit_ex(pSymCipher->pCtx, NULL, NULL, NULL, pIV);
                }
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
                EVP_EncryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
            break;
        }
    }
    else
    {
        switch (pSymCipher->nAlgorithm)
        {
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
                EVP_DecryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
            break;

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX:
            break;
            
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:

                ivlen = com_adaptiva_fips_CryptoConstants_IV_LENGTH_AES256_GCM;
                if (ivlen == 12)
                {
                    EVP_DecryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
                }
                else
                {
                    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen);
                    EVP_DecryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, NULL, params);
                    EVP_DecryptInit_ex(pSymCipher->pCtx, NULL, NULL, NULL, pIV);
                }
            break;
            
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
                EVP_DecryptInit_ex2(pSymCipher->pCtx, pSymCipher->pImplement, pKey, pIV, NULL);
            break;
        }
    }
    return true;
}

bool CipherRelease(SymmetricCipher *pSymCipher)
{
    if (pSymCipher != NULL)
    {
        if (pSymCipher->pKey != NULL && pSymCipher)
            zeroAndFreeBuffer(pSymCipher->pKey, pSymCipher->nKeyLength);

        if (pSymCipher->pInitialVector != NULL && pSymCipher->nInitialVectorLength > 0)
            zeroAndFreeBuffer(pSymCipher->pInitialVector, pSymCipher->nInitialVectorLength);

        if (pSymCipher->pBytesToBeInjected != NULL && pSymCipher->nBytesToBeInjected > 0)
            zeroAndFreeBuffer(pSymCipher->pBytesToBeInjected, pSymCipher->nBytesToBeInjected);

        if (pSymCipher->pImplement != NULL)
            EVP_CIPHER_free(pSymCipher->pImplement);

        if (pSymCipher->pCtx != NULL)
            EVP_CIPHER_CTX_free(pSymCipher->pCtx);
    
        if (pSymCipher->psInput != NULL)
            OPENSSL_free(pSymCipher->psInput);

        if (pSymCipher->pBIOInput != NULL)
        {
            BIO_set_flags(pSymCipher->pBIOInput, BIO_FLAGS_MEM_RDONLY); // very necessary
            BIO_free(pSymCipher->pBIOInput);
        }
        OPENSSL_free(pSymCipher);
    }
    return true;
}

bool CipherReset(SymmetricCipher *pSymCipher)
{
    if (pSymCipher != NULL)
    {
        EVP_CIPHER_CTX_reset(pSymCipher->pCtx);
    }
    CipherSetKeyAndInitialVector(pSymCipher, pSymCipher->pKey, pSymCipher->nKeyLength, pSymCipher->pInitialVector, pSymCipher->nInitialVectorLength);

    if (pSymCipher->psInput != NULL)
    {
        OPENSSL_free(pSymCipher->psInput);
        pSymCipher->psInput = NULL;
    }
    pSymCipher->nInputSize = 0;
    BIO_reset(pSymCipher->pBIOInput);

    pSymCipher->nBytesToBeSkipped = 0;
    if (pSymCipher->pBytesToBeInjected != NULL)
    {
        zeroAndFreeBuffer(pSymCipher->pBytesToBeInjected, pSymCipher->nBytesToBeInjected);
        pSymCipher->pBytesToBeInjected = NULL;
        pSymCipher->nBytesToBeInjected = 0;
    }
    return true;
}

bool CipherSubmitInput(SymmetricCipher *pSymCipher, byte *pInput, int nOffset, int nLength)
{
    if (pSymCipher != NULL && pInput != NULL && nOffset >= 0 && nLength > 0)
    {
        BIO_write(pSymCipher->pBIOInput, pInput+nOffset, nLength);
    }
    return true;
}

bool CipherEndInput(SymmetricCipher* pSymCipher)
{
    pSymCipher->nInputSize = BIO_get_mem_data(pSymCipher->pBIOInput, (char**)&(pSymCipher->psInput));
    return true;
}

/*
*                             nLength
*      |------------------------------------------------------|
*      |  injection  |        cipher             |    tag     |
* 
*  It doesn't make sense to skip part of the cipher. Injection doesn't affect the verification of the tag
*  as long as the receiver knows the length of the injection. We don't include length of the injection in
*  the output, the caller has to communicate that information to the receiver.
*/
static int CipherRetrieveEncryptionOutput_AES_GCM(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength)
{
    byte* pAlgorithmOutput;
    int len = 0;
    byte tag[16];
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    if (nLength < pSymCipher->nBytesToBeInjected + pSymCipher->nInputSize + sizeof(tag))
    {
        LOG3(logMessage, "WARN", "provided output buffer is shorter than minimum required");
        return 0;
    }

    pAlgorithmOutput = (byte*)OPENSSL_zalloc(pSymCipher->nInputSize);

    EVP_EncryptUpdate(pSymCipher->pCtx, pAlgorithmOutput, &len, pSymCipher->psInput, pSymCipher->nInputSize);
        
    if (len != pSymCipher->nInputSize)
    {
        LOG3(logMessage, "ERROR", "output size not equal to estimation");
    }

    EVP_EncryptFinal_ex(pSymCipher->pCtx, NULL /*can this be NULL?*/, &len); // purpose is to compute tag
    
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, sizeof(tag));

    EVP_CIPHER_CTX_get_params(pSymCipher->pCtx, params);

    if (pSymCipher->nBytesToBeInjected > 0)
        memcpy(pOutput + nOffset, pSymCipher->pBytesToBeInjected, pSymCipher->nBytesToBeInjected);

    memcpy(pOutput + nOffset + pSymCipher->nBytesToBeInjected, pAlgorithmOutput, pSymCipher->nInputSize);
    memcpy(pOutput + nOffset + pSymCipher->nBytesToBeInjected + pSymCipher->nInputSize, tag, sizeof(tag));
    return pSymCipher->nBytesToBeInjected + pSymCipher->nInputSize + sizeof(tag);
}

static int CipherRetrieveEncryptionOutput_CBC(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength)
{
    int nEstimatedOutputSize;
    byte* pAlgorithmOutput;
    int len = 0, nConfirmedOutputSize = 0;
    int nInject = 0, nCopy = 0;

    nEstimatedOutputSize = pSymCipher->nInputSize + (pSymCipher->nBlockSize - pSymCipher->nInputSize % pSymCipher->nBlockSize);

    pAlgorithmOutput = (byte*)OPENSSL_zalloc(nEstimatedOutputSize);

    EVP_EncryptUpdate(pSymCipher->pCtx, pAlgorithmOutput, &len, pSymCipher->psInput, pSymCipher->nInputSize);
    nConfirmedOutputSize += len;
    EVP_EncryptFinal_ex(pSymCipher->pCtx, pAlgorithmOutput + len, &len);
    nConfirmedOutputSize += len; // this "len" will be final block of encryted data, the residual of real data + pad, it should be equal to block size

    // why would anyone skip the output of encryption for CBC mode?
    if (pSymCipher->nBytesToBeSkipped > 0)
    {
        LOG3(logMessage, "ERROR", "Deliver encryption output", 0, 0, "Encryption output is partially skipped");
        return 0;
    }

    nInject = min(nLength, pSymCipher->nBytesToBeInjected);
    if (nInject > 0)
        memcpy(pOutput + nOffset, pSymCipher->pBytesToBeInjected, nInject);

    nCopy = min(nLength - nInject, nConfirmedOutputSize);
    if (nCopy < nConfirmedOutputSize)
    {
        LOG3(logMessage, "ERROR", "Deliver encryption output", 0, 0, "Not entire encryption output is delivered");
    }
    memcpy(pOutput + nOffset + nInject, pAlgorithmOutput, nCopy);
    return nCopy;
}

// If there were injected bytes in front of the output of encryption, the caller of this function should strip off those injected bytes
static int CipherRetrieveDecryptionOutput_AES_GCM(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength)
{
    int nCipherTextSize;
    byte* pAlgorithmOutput;
    int len = 0, nConfirmedOutputSize = 0;
    int nInject = 0, nCopy = 0;
    byte tag[16];
    byte* pTagStart;

    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };

    pTagStart = pSymCipher->psInput + pSymCipher->nInputSize - 16;
    memcpy(tag, pTagStart, 16);

    nCipherTextSize = pSymCipher->nInputSize - sizeof(tag);

    pAlgorithmOutput = (byte*)OPENSSL_zalloc(nCipherTextSize);

    EVP_DecryptUpdate(pSymCipher->pCtx, pAlgorithmOutput, &len, pSymCipher->psInput, nCipherTextSize);
    if (len != nCipherTextSize)
    {
        LOG3(logMessage, "WARN", "Decryption output size is not equal to estimation", 0, 0, "");
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        (void*)tag, sizeof(tag));

    EVP_CIPHER_CTX_set_params(pSymCipher->pCtx, params);

    // verify tag
    EVP_DecryptFinal_ex(pSymCipher->pCtx, NULL/*can this be NULL?*/, &len); // must call final if there is padding
    

    nInject = min(nLength, pSymCipher->nBytesToBeInjected);
    if (nInject > 0)
        memcpy(pOutput + nOffset, pSymCipher->pBytesToBeInjected, nInject);

    nCopy = 0;
    if (nInject < nLength)
    {
        nCopy = min(nLength - nInject, nCipherTextSize - pSymCipher->nBytesToBeSkipped);
        memcpy(pOutput + nOffset + nInject, pAlgorithmOutput + pSymCipher->nBytesToBeSkipped, nCopy);
    }
    return nInject + nCopy;
}

/*
* "nLength" is the available space of pOutput
* Must not write more than "nLength" to pOutput.
* "nLength" is equal to real plain text + padding, because we can't know how long the padding is.
* we know the length of the bytes spat out by encryption algorithm.
* And we know there are 4 bytes salt at the beginning.
*/
static int CipherRetrieveDecryptionOutput_CBC(SymmetricCipher* pSymCipher, byte* pOutput, int nOffset, int nLength)
{
    int nEstimatedOutputSize;
    byte* pAlgorithmOutput;
    int len = 0, nConfirmedOutputSize = 0;
    int nInject = 0, nCopy = 0;

    nEstimatedOutputSize = pSymCipher->nInputSize; 
    // This "nInputSize" is the length of the bytes that are fed to the decryption algorithm.
    // It denotes the bytes that are spat out by the encryption algorithm.
    // It should be multiple of block size.
    // It should be equal to salt + plain text + padding

    pAlgorithmOutput = (byte*)OPENSSL_zalloc(nEstimatedOutputSize);

    EVP_DecryptUpdate(pSymCipher->pCtx, pAlgorithmOutput, &len, pSymCipher->psInput, pSymCipher->nInputSize);
    nConfirmedOutputSize += len;
    EVP_DecryptFinal_ex(pSymCipher->pCtx, pAlgorithmOutput + len, &len); // must call final if there is padding
    nConfirmedOutputSize += len; // this "len" will be the final block of real data (not including pad)

    nInject = min(nLength, pSymCipher->nBytesToBeInjected);
    if (nInject > 0)
        memcpy(pOutput + nOffset, pSymCipher->pBytesToBeInjected, nInject);

    nCopy = 0;
    if (nInject < nLength)
    {
        nCopy = min(nLength - nInject, nConfirmedOutputSize - pSymCipher->nBytesToBeSkipped);
        memcpy(pOutput + nOffset + nInject, pAlgorithmOutput + pSymCipher->nBytesToBeSkipped, nCopy);
    }
    return nInject + nCopy;
}

int CipherRetrieveOutput(SymmetricCipher *pSymCipher, byte *pOutput, int nOffset, int nLength)
{
    if (pSymCipher->fEncrypt)
    {
        switch (pSymCipher->nAlgorithm)
        {
        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
            return CipherRetrieveEncryptionOutput_CBC(pSymCipher, pOutput, nOffset, nLength);

        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
            return CipherRetrieveEncryptionOutput_AES_GCM(pSymCipher, pOutput, nOffset, nLength);
        }
    }
    else
    {
        switch (pSymCipher->nAlgorithm)
        {
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
                return CipherRetrieveDecryptionOutput_CBC(pSymCipher, pOutput, nOffset, nLength);

            case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
                return CipherRetrieveDecryptionOutput_AES_GCM(pSymCipher, pOutput, nOffset, nLength);
        }
    }
    return -1;
}

int CipherSkipBytes(SymmetricCipher *pSymCipher, int nToBeSkippedByteCount)
{
    if (pSymCipher == NULL || nToBeSkippedByteCount < 0)
        return 0;

    pSymCipher->nBytesToBeSkipped = nToBeSkippedByteCount;
    return nToBeSkippedByteCount;
}

int CipherInjectBytes(SymmetricCipher *pSymCipher, byte *pInjectBytes, int nOffset, int nInjectByteCount)
{
    if (pSymCipher != NULL && pInjectBytes != NULL && nOffset >= 0 && nInjectByteCount > 0)
    {
        pSymCipher->pBytesToBeInjected = (byte*)OPENSSL_realloc(pSymCipher->pBytesToBeInjected, pSymCipher->nBytesToBeInjected + nInjectByteCount);
        memcpy(pSymCipher->pBytesToBeInjected + pSymCipher->nBytesToBeInjected, pInjectBytes, nInjectByteCount);
        pSymCipher->nBytesToBeInjected += nInjectByteCount;

        return nInjectByteCount;
    }
    return 0;
}

int getEncryptedBufferSizeUsingJavaformat(int nEncrypAlog, int nInputSize)
{
    switch(nEncrypAlog)
    {
        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_CBC:
            return nInputSize + 10 + com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_CBC - ((nInputSize + 4) % com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_CBC);
    
        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_EAX:
            return 0;

        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_AES256_GCM:
            return nInputSize + 10 + com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_AES256_GCM;
            // counter mode, cipher text length = plain text length, default MAC tag length is one AES block size

        case com_adaptiva_fips_CyrptoConstants_ENCRYPTION_ALGORITHM_TRIPLE_DES_CBC:
            return nInputSize + 10 + com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_TRIPLE_DES_CBC - ((nInputSize + 4) % com_adaptiva_fips_CryptoConstants_BLOCK_SIZE_TRIPLE_DES_CBC);
    }
    return 0;
}

/*
* "nInputSize" is the size of the buffer produced by "encryptBufferUsingJavaformat"
* It equals 1(key type) + 1(algo) + 4(IV material) + bytes spat out by encryption algorithm
* 
* In case of GCM, "bytes spat out by the encryption algorithm" includes cipher text and MAC tag
* because I concatenate the tag to the end of the cipher text.
* 
* So nInputsize - 10 is either 
*    the cipher corresponding to (the real plain text + padding)
* or
*    (the cipher corresponding to the real plain text) + MAC tag
* salt is always included because salt is encrypted, so salt should be fed to decryption algorithm
* 
* 
* So this buffer size is almost always an over estimation (except in CBC mode where there is no padding needed)
* So the decryption API should return the true size of the decrypted plain text.
* If the decrypted plain text is ASCII string, the size should include the terminating '\0'
*/
int getDecryptedBufferSizeUsingJavaformat(int nInputSize)
{
    return max(12, (nInputSize - 10));  // Why 12?
}


/*
*    |___| |___|  |___________________|  |___________________|  |________....._____________|
*    k type algo   random (generate IV)      salt                      plain text

                                                                \______ pDataBuffer _______/

                                                                \____ nDataBufferLength ___/

                                         \____________________________ cipher output _____________________/ (maybe longer because of padding)

*                                        \_________________________ nEncryptedDataSize ___________________/ 
* 
*    \_________________________________________ nEncryptedBufferSize _____________________________________/
*/
byte *encryptBufferUsingJavaformat(int encrypAlgo, byte *key, int nKeyLength, byte *pDataBuffer, int nDataBufferLength, int *pnEncryptedBufferSize)
{
    byte *pEncryptedBuffer = NULL;
    int nEncryptedBufferSize = 0;
    int nEncryptedDataSize = 0;
    byte *pIV = NULL;
    int nIVLength = 0;
    SymmetricCipher *pSymCipher = NULL;
    byte salt[4];
    byte* pDuplicateKey = NULL;


    if (key == NULL || nKeyLength <= 0 || pDataBuffer == NULL || nDataBufferLength <= 0 || pnEncryptedBufferSize == NULL)
        return NULL;

    if ((nEncryptedBufferSize = getEncryptedBufferSizeUsingJavaformat(encrypAlgo, nDataBufferLength)) <= 0)
    {
        goto done;
    }
    if ((pEncryptedBuffer = (byte*)OPENSSL_zalloc(nEncryptedBufferSize)) == NULL)
    {
        goto done;
    }
    pEncryptedBuffer[0] = com_adaptiva_fips_CryptoConstants_KEY_TYPE_NONE;
    pEncryptedBuffer[1] = encrypAlgo;
    *((DWORD*)(pEncryptedBuffer + 2)) = RngGenerateDword();

    *((DWORD *)(salt)) = RngGenerateDword();

    if ((nIVLength = getInitialVectorLength(encrypAlgo)) <= 0)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if ((pIV = (byte*)OPENSSL_zalloc(nIVLength)) == NULL)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if (generateBytesFromKeyMaterial((byte*)(pEncryptedBuffer+2), 4, pIV, nIVLength) == false)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if ((pSymCipher = CipherInitialize(encrypAlgo, true)) == NULL)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    pDuplicateKey = (byte*)memdup(key, nKeyLength);
    if (CipherSetKeyAndInitialVector(pSymCipher, pDuplicateKey, nKeyLength, pIV, nIVLength) == false)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if (CipherSubmitInput(pSymCipher, salt, 0, 4) == NULL)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if (CipherSubmitInput(pSymCipher, pDataBuffer, 0, nDataBufferLength) == false)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if (CipherEndInput(pSymCipher) == false)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    if ((nEncryptedDataSize = CipherRetrieveOutput(pSymCipher, pEncryptedBuffer, 6, nEncryptedBufferSize-6)) <= 0)
    {
        OPENSSL_free(pEncryptedBuffer);
        pEncryptedBuffer = NULL;
        goto done;
    }

    done:

    if (pSymCipher != NULL)
        CipherRelease(pSymCipher);

    if (pEncryptedBuffer != NULL)
        *pnEncryptedBufferSize = nEncryptedDataSize + 6;

    return pEncryptedBuffer;
}


/*
*    |___|  |___|  |___________________|  |___________________|  |_______________________________| |________|
*    k type  algo   random (generate IV)         salt                        plain text               pad
* 
*    \__________________________________________ nDataBufferLength _________________________________________/
* 
*    \____________________________________________ pDataBuffer _____________________________________________/
* 
*                                         \__________________________ cipher input _________________________/
* 
*                                                               \____________ pDecryptedBuffer _____________/
* 
*                                                               \__________ nDecryptedBufferSize ___________/
* 
*                                                               \______ nDecryptedDataSize _____/
*/
byte *decryptBufferUsingJavaformat(int algo, byte *key, int nKeyLength, byte *pDataBuffer, int nDataBufferLength, int *pnDecryptedBufferSize)
{
    byte *pDecryptedBuffer = NULL;
    int nDecryptedBufferSize = 0;
    int nDecryptedDataSize = 0;
    byte *pIV = NULL;
    int nIVLength = 0;
    SymmetricCipher *pSymCipher = NULL;

    if (key == NULL || nKeyLength <= 0 || pDataBuffer == NULL || nDataBufferLength <= 10 || pnDecryptedBufferSize == NULL)
        return NULL;

    // without actually decrypting, there is no way to know how big the padding is
    // so this size is the plain text length + padding length
    nDecryptedBufferSize = getDecryptedBufferSizeUsingJavaformat(nDataBufferLength);
    // this buffer is longer than actual plain text because of padding.
    // a few bytes at the end will be unused. The value of those unused bytes actuall doesn't matter
    // if the plain text is a ascii string, the last byte of the plain text will be '\0'.
    // if the plain text is a binary message, the pnDecryptedBufferSize will denote the plain text length
    if ((pDecryptedBuffer = (byte*)OPENSSL_zalloc(nDecryptedBufferSize)) == NULL)
    {
        goto done;
    }

    if ((nIVLength = getInitialVectorLength(algo)) <= 0)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if ((pIV = (byte*)OPENSSL_zalloc(nIVLength)) == NULL)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if (generateBytesFromKeyMaterial((byte*)(pDataBuffer+2), 4, pIV, nIVLength) == false)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if ((pSymCipher = CipherInitialize(algo, false)) == NULL)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    byte *pDuplicateKey;
    if ((pDuplicateKey = (byte*)memdup(key, nKeyLength)) == NULL)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if (CipherSetKeyAndInitialVector(pSymCipher, pDuplicateKey, nKeyLength, pIV, nIVLength) == false)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if (CipherSubmitInput(pSymCipher, pDataBuffer+6, 0, nDataBufferLength-6) == false)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if (CipherEndInput(pSymCipher) == false)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if (CipherSkipBytes(pSymCipher, 4) <= 0)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    if ((nDecryptedDataSize = CipherRetrieveOutput(pSymCipher, pDecryptedBuffer, 0, nDataBufferLength - 10)) <= 0)
    {
        OPENSSL_free(pDecryptedBuffer);
        pDecryptedBuffer = NULL;
        goto done;
    }

    done:

    if (pSymCipher != NULL)
        CipherRelease(pSymCipher);

    if (pDecryptedBuffer != NULL)
    {
        *pnDecryptedBufferSize = nDecryptedDataSize;
    }
    return pDecryptedBuffer;
}





// =============================================================
// Raw binary  <==>  BIGNUM (for prime and genarator of DL DH)
// =============================================================

static char* DhDomainBignumToBinary(BIGNUM* pBNPrime, BIGNUM* pBNGenerator)
{
    char* pszRetVal = NULL;

    int nPrimeBufferSize;
    byte *pPrimeBuffer = NULL;
    char* pszBase32EncodedPrime = NULL;

    int nGeneratorBufferSize;
    byte* pGeneratorBuffer = NULL;
    char* pszBase32EncodedGenerator = NULL;

    if (pBNPrime == NULL || pBNGenerator == NULL)
    {
        LOG3(logMessage, "ERROR", "BIGNUM to binary conversion", 0, 0, "Invalid input");
        goto done;
    }

    nPrimeBufferSize = BN_num_bytes(pBNPrime); // this API has no error code
    if ((pPrimeBuffer = (byte*)OPENSSL_malloc(nPrimeBufferSize)) == NULL)
    {
        LOG3(logMessage, "FAIL", "alloc for Prime binary format", 0, 0, "malloc fail");
        goto done;
    }
    nPrimeBufferSize = BN_bn2bin(pBNPrime, pPrimeBuffer); // this API has no error code
    if ((pszBase32EncodedPrime = ADAPTIVA_AUX::base32Encode(pPrimeBuffer, nPrimeBufferSize)) == NULL)
    {
        LOG3(logMessage, "FAIL", "Base 32 encoding Prime binary format", 0, 0, "");
        goto done;
    }

    nGeneratorBufferSize = BN_num_bytes(pBNGenerator);
    if ((pGeneratorBuffer = (byte*)OPENSSL_malloc(nGeneratorBufferSize)) == NULL)
    {
        LOG3(logMessage, "FAIL", "alloc for Generator binary format", 0, 0, "malloc fail");
        goto done;
    }
    nGeneratorBufferSize = BN_bn2bin(pBNGenerator, pGeneratorBuffer);
    if ((pszBase32EncodedGenerator = ADAPTIVA_AUX::base32Encode(pGeneratorBuffer, nGeneratorBufferSize)) == NULL)
    {
        LOG3(logMessage, "FAIL", "Base 32 encoding Generator binary format", 0, 0, "");
        goto done;
    }

    pszRetVal = getFormattedString("%s,%s", pszBase32EncodedPrime, pszBase32EncodedGenerator);

done:

    if (pPrimeBuffer != NULL)
        OPENSSL_free(pPrimeBuffer);

    if (pGeneratorBuffer != NULL)
        OPENSSL_free(pGeneratorBuffer);

    if (pszBase32EncodedPrime != NULL)
        free(pszBase32EncodedPrime);

    if (pszBase32EncodedGenerator != NULL)
        free(pszBase32EncodedGenerator);

    return pszRetVal;
}

static bool DhDomainBinaryToBignum(char *pszInitializationParameter, BIGNUM** ppBNPrime, BIGNUM** ppBNGenerator)
{
    bool fRetVal = false;

    char* pszCopyOfInput = NULL;

    char *pszCommaPtr;

    char* pszBase32EncodedGenerator = NULL;
    byte* pGeneratorBuffer = NULL;
    int nGeneratorBufferSize;
    BIGNUM* pBNGenerator = NULL;

    char* pszBase32EncodedPrime = NULL;
    byte* pPrimeBuffer = NULL;
    int nPrimeBufferSize;
    BIGNUM* pBNPrime = NULL;

    if (pszInitializationParameter == NULL || ppBNPrime == NULL || ppBNGenerator == NULL)
    {
        LOG3(logMessage, "ERROR", "Binary to BIGNUM conversion", 0, 0, "Invalid input");
        return false;
    }

    pszCopyOfInput = _strdup(pszInitializationParameter);
    if (pszCopyOfInput == NULL)
    {
        LOG3(logMessage, "FAIL", "duplicate base32 encoded prime and generator binary", errno, 1, "strdup fail");
        goto done;
    }

    if ((pszCommaPtr = strchr(pszCopyOfInput, ',')) == NULL)
    {
        LOG3(logMessage, "ERROR", "Search comma in input string", 0, 0, "no comma in input string");
        goto done;
    }
    pszBase32EncodedPrime = pszCopyOfInput;
    *pszCommaPtr = '\0';
    pszBase32EncodedGenerator = pszCommaPtr + 1;

    if ((pPrimeBuffer = ADAPTIVA_AUX::base32Decode(pszBase32EncodedPrime, &nPrimeBufferSize)) == NULL || nPrimeBufferSize <= 0)
    {
        LOG3(logMessage, "FAIL", "Base32 decoding Prime binary format", 0, 0, "");
        goto done;
    }
    pBNPrime = BN_bin2bn(pPrimeBuffer, nPrimeBufferSize, pBNPrime); // This API has no error code

    if ((pGeneratorBuffer = ADAPTIVA_AUX::base32Decode(pszBase32EncodedGenerator, &nGeneratorBufferSize)) == NULL || nGeneratorBufferSize <= 0)
    {
        LOG3(logMessage, "FAIL", "Base32 decoding Generator binary format", 0, 0, "");
        goto done;
    }
    pBNGenerator = BN_bin2bn(pGeneratorBuffer, nGeneratorBufferSize, pBNGenerator);

    *ppBNPrime = pBNPrime;
    *ppBNGenerator = pBNGenerator;

    fRetVal = true;

done:
    if (pszCopyOfInput != NULL)
        free(pszCopyOfInput);

    if (pPrimeBuffer != NULL)
        free(pPrimeBuffer);

    if (pGeneratorBuffer != NULL)
        free(pGeneratorBuffer);

    if (fRetVal == false)
    {
        if (pBNPrime != NULL)
            BN_free(pBNPrime);

        if (pBNGenerator != NULL)
            BN_free(pBNGenerator);
    }

    return fRetVal;
}





// =========================================
// Discrete Logarithm Asymmetric Key Schema
// =========================================

static EVP_PKEY *createPeerPKEY_DL(BIGNUM* pBNPrime, BIGNUM *pBNGenerator, byte *pRemotePublicKey, int nRemotePublicKeyLength)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *paramBuild = NULL;
    OSSL_PARAM *params = NULL;


    BIGNUM* pBNPubKey = NULL;
    pBNPubKey = BN_bin2bn(pRemotePublicKey, nRemotePublicKeyLength, NULL);

    paramBuild = OSSL_PARAM_BLD_new();
    if (paramBuild == NULL)
    {
        goto done;
    }
    //if (OSSL_PARAM_BLD_push_octet_string(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, pRemotePublicKey, nRemotePublicKeyLength) != 1)
    // for discrete logarithm DH, remote public key must be submitted in BIGNUM format, not binary format
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, pBNPubKey) != 1)
    {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, pBNPrime) != 1)
    {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, pBNGenerator) != 1)
    {
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (params == NULL)
    {
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (ctx == NULL)
    {
        goto done;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        goto done;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        goto done;
    }

    done:

    if (paramBuild)
        OSSL_PARAM_BLD_free(paramBuild);
    if (params)
        OSSL_PARAM_free(params);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pBNPubKey)
        BN_free(pBNPubKey);

    return pkey;    
}

static EVP_PKEY* createPeerPKEY_DL_WithNamedGroup(BIGNUM* pBNPrime, BIGNUM* pBNGenerator, byte* pRemotePublicKey, int nRemotePublicKeyLength)
{
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* ctx = NULL;
    OSSL_PARAM_BLD* paramBuild = NULL;
    OSSL_PARAM* params = NULL;
    char const groupname[] = "ffdhe2048";

    BIGNUM* pBNPubKey = NULL;
    pBNPubKey = BN_bin2bn(pRemotePublicKey, nRemotePublicKeyLength, NULL);

    paramBuild = OSSL_PARAM_BLD_new();
    if (paramBuild == NULL)
    {
        goto done;
    }

    if (OSSL_PARAM_BLD_push_utf8_string(paramBuild, "group", groupname, strlen(groupname)) != 1)
    {
        goto done;
    }
    //if (OSSL_PARAM_BLD_push_octet_string(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, pRemotePublicKey, nRemotePublicKeyLength) != 1)
    // for discrete logarithm DH, remote public key must be submitted in BIGNUM format, not binary format
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, pBNPubKey) != 1)
    {
        goto done;
    }
    // If I do set parameters individually, must I set all three of p, g, q?
    // If I only set p and g, will key validation fail?
    /*
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, pBNPrime) != 1)
    {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, pBNGenerator) != 1)
    {
        goto done;
    }
    */
    params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (params == NULL)
    {
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (ctx == NULL)
    {
        goto done;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        goto done;
    }

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        goto done;
    }

done:

    if (paramBuild)
        OSSL_PARAM_BLD_free(paramBuild);
    if (params)
        OSSL_PARAM_free(params);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pBNPubKey)
        BN_free(pBNPubKey);

    return pkey;
}



// =========================================
// Elliptic Curve Asymmetric Key Schema
// =========================================

// not in use
static int generate_ec_curve(OSSL_LIB_CTX *libctx, EVP_PKEY **ppCurve)
{
    int result = 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *curve = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", /* prop query */NULL);

    EVP_PKEY_paramgen_init(ctx);

    EVP_PKEY_generate(ctx, &curve);

    if (result != 1)
    {
        EVP_PKEY_free(curve);
        curve = NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    *ppCurve = curve;
    return 1;
}

// not in use
static int generate_ec_key_pair(OSSL_LIB_CTX *libctx, EVP_PKEY *curve, EVP_PKEY **ppKeyPair)
{
    int result = 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, curve, /* prop query */NULL);
    if (ctx == NULL)
        goto end;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto end;

    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
        goto end;

    if (pkey == NULL)
        goto end;

    result = 1;

    end:

    if (result != 1)
    {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    *ppKeyPair = pkey;

    return result;
}

static EVP_PKEY *createPkeyWithOneKey_EC_combined_curve_keypair(byte *pKnownKey, int nKeyLength, bool isPublic)
{
    OSSL_PARAM_BLD *paramBuild = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    paramBuild = OSSL_PARAM_BLD_new();
    if (paramBuild == NULL)
    {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_utf8_string(paramBuild, OSSL_PKEY_PARAM_GROUP_NAME, SN_X9_62_prime256v1, 0) != 1)
    {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_utf8_string(paramBuild, OSSL_PKEY_PARAM_EC_FIELD_TYPE, "prime-field", 0) != 1)
    {
        goto done;
    }
    if (isPublic)
    {
        if (OSSL_PARAM_BLD_push_octet_string(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, pKnownKey, nKeyLength) != 1)
        {
            goto done;
        }
    }
    else
    {
        if (OSSL_PARAM_BLD_push_octet_string(paramBuild, OSSL_PKEY_PARAM_PRIV_KEY, pKnownKey, nKeyLength) != 1)
        {
            goto done;
        }
    }
    params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (params == NULL)
    {
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (ctx == NULL)
    {
        goto done;
    }
    if (EVP_PKEY_fromdata_init(ctx) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_fromdata(ctx, &pkey, isPublic ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params) != 1)
    {
        goto done;
    }

    done:

    if (paramBuild)
        OSSL_PARAM_BLD_free(paramBuild);
    if (params)
        OSSL_PARAM_free(params);
    if (ctx)
        EVP_PKEY_CTX_free(ctx); // Can I free the ctx here?

    return pkey;
}

static EVP_PKEY *createPkeyWithOneKey_EC_curve_keypair_separate(byte *pKnownKey, int nKeyLength, bool isPublic)
{
    EVP_PKEY *curve = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *curveCtx = NULL, *keyCtx = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)SN_X9_62_prime256v1, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char*)"prime-field", 0);
    *p = OSSL_PARAM_construct_end();

    curveCtx = EVP_PKEY_CTX_new_from_name(/*lib context*/NULL, "EC", /* prop query */ NULL);

    EVP_PKEY_keygen_init(curveCtx);

    EVP_PKEY_CTX_set_params(curveCtx, params);

    EVP_PKEY_keygen(curveCtx, &curve);

    keyCtx = EVP_PKEY_CTX_new_from_pkey(/*lib context*/NULL, curve, /*prop query*/ NULL);
    EVP_PKEY_fromdata_init(keyCtx);
    p = params;
    if (isPublic)
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)pKnownKey, nKeyLength);
    }
    else
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void*)pKnownKey, nKeyLength);
    }
    *p = OSSL_PARAM_construct_end();
    if (isPublic)
    {
        EVP_PKEY_fromdata(keyCtx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    }
    else
    {
        EVP_PKEY_fromdata(keyCtx, &pkey, EVP_PKEY_KEYPAIR, params);
                                        /*( EVP_PKEY_KEY_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY )*/ //?
    }

    EVP_PKEY_free(curve);
    EVP_PKEY_CTX_free(curveCtx);
    EVP_PKEY_CTX_free(keyCtx);

    return pkey;
}

static EVP_PKEY *createPeerPKEY_EC(byte *pRemotePublicKey, int nRemotePublicKeyLength)
{
    return createPkeyWithOneKey_EC_combined_curve_keypair(pRemotePublicKey, nRemotePublicKeyLength, /* is public*/true);
}

static EVP_PKEY* generate_EC_keypair_curve_keypair_separate()
{
    EVP_PKEY *curve = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *curveCtx = NULL, *keyCtx = NULL;

    OSSL_PARAM params[3];
    OSSL_PARAM *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)SN_X9_62_prime256v1, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char*)"prime-field", 0);
    *p = OSSL_PARAM_construct_end();

    curveCtx = EVP_PKEY_CTX_new_from_name(/* library context */ NULL, "EC", /* prop query */ NULL);
    if (curveCtx == NULL)
    {
        goto done;
    }
    if (EVP_PKEY_keygen_init(curveCtx) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_CTX_set_params(curveCtx, params) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_generate(curveCtx, &curve) != 1)
    {
        goto done;
    }

    keyCtx = EVP_PKEY_CTX_new_from_pkey(/* library context */ NULL, curve, /*prop query*/ NULL);
    if (keyCtx == NULL)
    {
        goto done;
    }
    if (EVP_PKEY_keygen_init(keyCtx) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_generate(keyCtx, &pkey) != 1)
    {
        goto done;
    }

    done:

    if (curveCtx)
        EVP_PKEY_CTX_free(curveCtx);
    if (keyCtx)
        EVP_PKEY_CTX_free(keyCtx);
    if (curve)
        EVP_PKEY_free(curve);

    return pkey;
}

static EVP_PKEY* generate_EC_keypair_single_context()
{
    int r;

    EVP_PKEY* key = NULL;

    OSSL_PARAM params[2];

    EVP_PKEY_CTX* ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(/*lib context*/NULL, "EC", /*properties*/NULL);

    r = EVP_PKEY_keygen_init(ctx);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"P-256", 0);

    params[1] = OSSL_PARAM_construct_end();

    r = EVP_PKEY_CTX_set_params(ctx, params);

    r = EVP_PKEY_generate(ctx, &key);

    return key;
}



// ==================================
// Diffie-Hellman Key Exchange
// ==================================


struct DHState_t
{
    int dhtype;
    bool fHandshakeCompleted;
    
    // Discrete Logarithm DH:

    char* pszDhPrimeAndGeneratorInBinary;
    BIGNUM *pBNPrime;
    BIGNUM *pBNGenerator;
    EVP_PKEY* dlDomain;
    EVP_PKEY *keyPair;
    BIGNUM* pBNPubKey;


    // ECDH:

    EVP_PKEY *ecKeyPair;
    //EVP_PKEY_CTX *ecCtx;
    //byte* pECPubKey;
    //int nECPubKeyLen;

    // Common between Discrete Logarithm DH and ECDH: 
    //BIGNUM* pBNPriKey;
    byte *sharedSecret;
    int nSharedSecretLength;
};
typedef struct DHState_t DHState;



static DHState *DhAllocAndDuplicateInput(int dhtype, char *pszRemotePartyParams)
{
    DHState *dhState = NULL;

    if ((dhState = (DHState*)OPENSSL_zalloc(sizeof(DHState))) == NULL)
    {
        LOG3(logMessage, "FAIL", "alloc DHState", 0, 0, "malloc fail");
        return NULL;
    }
    dhState->dhtype = dhtype;
    if (pszRemotePartyParams != NULL)
    {
        dhState->pszDhPrimeAndGeneratorInBinary = _strdup(pszRemotePartyParams);
        if (dhState->pszDhPrimeAndGeneratorInBinary == NULL)
        {
            LOG3(logMessage, "FAIL", "duplicate input string", 0, 0, "strdup fail");
            if (dhState != NULL)
                OPENSSL_free(dhState);
            return NULL;
        }
    }
    else
    {
        dhState->pszDhPrimeAndGeneratorInBinary = NULL;
    }
    return dhState;
}

static bool DhInitialize_DL_liyk(DHState* p)
{
    BIGNUM* pBNPrime = NULL, * pBNGenerator = NULL;
    OSSL_PARAM params[2];
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    BIGNUM* pBNPubKey = NULL;
    bool success = false;

    if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)) == NULL)
        return NULL;

    params[0] = OSSL_PARAM_construct_utf8_string("group", (char*)"ffdhe2048", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(pctx) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_CTX_set_params(pctx, params) != 1)
    {
        goto done;
    }
    if (EVP_PKEY_generate(pctx, &pkey) != 1)
    {
        goto done;
    }
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &pBNPrime))
    {
        LOG3(logMessage, "FAIL", "get Prime BIGNUM format", 0, 0, "");
        goto done;
    }
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &pBNGenerator))
    {
        LOG3(logMessage, "FAIL", "get Generator BIGNUM format", 0, 0, "");
        goto done;
    }
    p->pszDhPrimeAndGeneratorInBinary = DhDomainBignumToBinary(pBNPrime, pBNGenerator);
    if (p->pszDhPrimeAndGeneratorInBinary == NULL)
    {
        LOG3(logMessage, "FAIL", "Convert Prime and Generator to binary", 0, 0, "");
        goto done;
    }

    // this pkey is the key pair
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pBNPubKey))
    {
        LOG3(logMessage, "FAIL", "Get public key from key pair", 0, 0, "");
        goto done;
    }

    success = true;
done:
    EVP_PKEY_CTX_free(pctx);
    if (!success)
    {
        if (pkey)
            EVP_PKEY_free(pkey);
        if (pBNPrime)
            BN_free(pBNPrime);
        if (pBNGenerator)
            BN_free(pBNGenerator);
        if (p->pszDhPrimeAndGeneratorInBinary)
            free(p->pszDhPrimeAndGeneratorInBinary); // comes from getFormattedString, not OPENSSL_malloc'ed
    }
    else
    {
        p->pBNPrime = pBNPrime;
        p->pBNGenerator = pBNGenerator;

        // This pkey is already the key pair, don't need to store the domain
        //p->dlDomain = pkey;
        p->keyPair = pkey;
        p->pBNPubKey = pBNPubKey;
    }
    return success;
}

static bool DhInitialize_DL_AliceInitiate(DHState* p)
{
    EVP_PKEY* domainParams = NULL;
    EVP_PKEY_CTX* dompCtx = NULL;

    BIGNUM* pBNPrime = NULL, * pBNGenerator = NULL, *pBNQ = NULL;

    bool success = false;

    OSSL_PARAM paramsArray[2];

    dompCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (dompCtx == NULL)
    {
        LOG3(logMessage, "FAIL", "Create new domain paramter context", 0, 0, "");
        goto done;
    }
    
    paramsArray[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"ffdhe2048", 0);
    paramsArray[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(dompCtx) != 1)
    {
        LOG3(logMessage, "FAIL", "initialize domain parameter context", 0, 0, "");
        goto done;
    }
    if (EVP_PKEY_CTX_set_params(dompCtx, paramsArray) != 1)
    {
        LOG3(logMessage, "FAIL", "set parameters to domain parameter context", 0, 0, "");
        goto done;
    }
    if (EVP_PKEY_generate(dompCtx, &domainParams) != 1)
    {
        LOG3(logMessage, "FAIL", "generate DH domain parameters", 0, 0, "EVP_PKEY_generate");
        goto done;
    }
    if (!EVP_PKEY_get_bn_param(domainParams, OSSL_PKEY_PARAM_FFC_P, &pBNPrime))
    {
        LOG3(logMessage, "FAIL", "get Prime BIGNUM format", 0, 0, "");
        goto done;
    }
    if (!EVP_PKEY_get_bn_param(domainParams, OSSL_PKEY_PARAM_FFC_G, &pBNGenerator))
    {
        LOG3(logMessage, "FAIL", "get Generator BIGNUM format", 0, 0, "");
        goto done;
    }
    if (!EVP_PKEY_get_bn_param(domainParams, OSSL_PKEY_PARAM_FFC_Q, &pBNQ))
    {
        LOG3(logMessage, "FAIL", "get q BIGNUM format", 0, 0, "");
        goto done;
    }
    
    p->pszDhPrimeAndGeneratorInBinary = DhDomainBignumToBinary(pBNPrime, pBNGenerator);
    if (p->pszDhPrimeAndGeneratorInBinary == NULL)
    {
        LOG3(logMessage, "FAIL", "Convert Prime and Generator to binary", 0, 0, "");
        goto done;
    }

    success = true;
    
    /* if we want to test not-well-defined DH domain (i.e. not named groups)
    * I can either have the underlying algorithm search for proper p,g,q
    * or I can hard code their value. Searching p,g,q is slow when their length is 2048 bits.
    * In order to save time (by cheating a little) in testing non-named groups, I can display p,g,q's values
    * here and save them then hard code their value.
    {
        char* hexPrime = BN_bn2hex(pBNPrime);
        char* hexGenerator = BN_bn2hex(pBNGenerator);
        char* hexQ = BN_bn2hex(pBNQ);
        std::cout << hexPrime << "\n\n";
        std::cout << hexGenerator << "\n\n";
        std::cout << hexQ << "\n\n";
        OPENSSL_free(hexPrime);
        OPENSSL_free(hexGenerator);
        OPENSSL_free(hexQ);
    }
    */

done:

    if (dompCtx)
        EVP_PKEY_CTX_free(dompCtx);

    if (!success)
    {
        if (domainParams)
            EVP_PKEY_free(domainParams);
        if (pBNGenerator)
            BN_free(pBNGenerator);
        if (pBNPrime)
            BN_free(pBNPrime);
        if (pBNQ)
            BN_free(pBNQ);
        if (p->pszDhPrimeAndGeneratorInBinary)
            free(p->pszDhPrimeAndGeneratorInBinary);
    }
    else
    {
        p->pBNGenerator = pBNGenerator;
        p->pBNPrime = pBNPrime;
        if (pBNQ)
            BN_free(pBNQ);
        p->dlDomain = domainParams;
    }
    return success;
}

static bool DhInitialize_DL_BobRespond(DHState* p)
{
    EVP_PKEY* domainParams = NULL;
    EVP_PKEY_CTX* dompCtx = NULL;

    BIGNUM* pBNPrime = NULL, * pBNGenerator = NULL;

    OSSL_PARAM_BLD* paramBuild = NULL;
    OSSL_PARAM* params = NULL;

    bool success = false;

    bool r;
    r = DhDomainBinaryToBignum(p->pszDhPrimeAndGeneratorInBinary, &pBNPrime, &pBNGenerator);
    if (r == false || pBNPrime == NULL || pBNGenerator == NULL)
    {
        LOG3(logMessage, "FAIL", "Parse remote DH parameters", 0, 0, "");
        goto done;
    }

    paramBuild = OSSL_PARAM_BLD_new();
    if (!paramBuild)
    {
        LOG3(logMessage, "FAIL", "Create parameters builder", 0, 0, "");
        goto done;
    }
    if (//!OSSL_PARAM_BLD_push_utf8_string(paramBuild, OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0) ||
        !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, pBNPrime) ||
        !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, pBNGenerator))
    {
        LOG3(logMessage, "FAIL", "Push parameters", 0, 0, "");
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(paramBuild);
    if (!params)
    {
        LOG3(logMessage, "FAIL", "Build parameters", 0, 0, "");
        goto done;
    }
    dompCtx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
    if (!dompCtx)
    {
        LOG3(logMessage, "FAIL", "Create new domain parameters context", 0, 0, "");
        goto done;
    }
    if (EVP_PKEY_fromdata_init(dompCtx) <= 0)
    {
        LOG3(logMessage, "FAIL", "Initialize domain parameters context", 0, 0, "EVP_PKEY_fromdata_init fail");
        goto done;
    }
    if (EVP_PKEY_fromdata(dompCtx, &domainParams, EVP_PKEY_KEY_PARAMETERS, params) <= 0)
    {
        LOG3(logMessage, "FAIL", "Materialize DH domain parameters", 0, 0, "EVP_PKEY_fromdata");
        goto done;
    }
    
    success = true;

done:

    if (params)
        OSSL_PARAM_free(params);
    if (paramBuild)
        OSSL_PARAM_BLD_free(paramBuild);
    if (dompCtx)
        EVP_PKEY_CTX_free(dompCtx);

    if (!success)
    {
        if (domainParams)
            EVP_PKEY_free(domainParams);
        if (pBNGenerator)
            BN_free(pBNGenerator);
        if (pBNPrime)
            BN_free(pBNPrime);
        if (p->pszDhPrimeAndGeneratorInBinary)
            free(p->pszDhPrimeAndGeneratorInBinary);
    }
    else
    {
        p->pBNGenerator = pBNGenerator;
        p->pBNPrime = pBNPrime;
        p->dlDomain = domainParams;
    }
    return success;
}

static bool DhInitialize_DL(DHState *dhState)
{
    EVP_PKEY *keyPair = NULL;
    EVP_PKEY_CTX *keyPairCtx = NULL;

    BIGNUM* pBNPubKey = NULL;

    bool success = false;
    
    bool test_unified = false;

    if (test_unified)
    {
        if (!DhInitialize_DL_liyk(dhState))
        {
            goto done;
        }
    }
    else
    {
        if (dhState->pszDhPrimeAndGeneratorInBinary == NULL)
        {
            // Alice initiating key exchange
            if (!DhInitialize_DL_AliceInitiate(dhState))
            {
                goto done;
            }
        }
        else
        {
            // Bob responding to DH
            // This response is not the key agreement step yet. This is just to set up the finite field parameters
            if (!DhInitialize_DL_BobRespond(dhState))
            {
                goto done;
            }
        }
    }

    keyPairCtx = EVP_PKEY_CTX_new_from_pkey(NULL, dhState->dlDomain, NULL);
    if (keyPairCtx == NULL)
    {
        LOG3(logMessage, "FAIL", "Create new key pair", 0, 0, "EVP_PKEY_CTX_new_from_pkey");
        goto done;
    }

    if (EVP_PKEY_keygen_init(keyPairCtx) != 1)
    {
        LOG3(logMessage, "FAIL", "Initialize key pair context", 0, 0, "EVP_PKEY_keygen_init");
        goto done;
    }

    if (EVP_PKEY_generate(keyPairCtx, &keyPair) != 1)
    {
        LOG3(logMessage, "FAIL", "generate key pair", 0, 0, "EVP_PKEY_generate");
        goto done;
    }

    if (!EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PUB_KEY, &pBNPubKey))
    {
        LOG3(logMessage, "FAIL", "Get public key from key pair", 0, 0, "");
        goto done;
    }
    //if (!EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_PRIV_KEY, &pBNPriKey))
    //{
    //    LOG3(logMessage, "FAIL", "Get Private key from key pair", 0, 0, "");
    //    goto done;
    //}

    success = true;
    
    done:

    if (keyPairCtx)
        EVP_PKEY_CTX_free(keyPairCtx);
    if (!success)
    {
        if (pBNPubKey)
            BN_free(pBNPubKey);
        if (keyPair)
            EVP_PKEY_free(keyPair);
    }
    else
    {
        dhState->pBNPubKey = pBNPubKey;
        dhState->keyPair = keyPair;
    }
    return success;
}

static bool DhInitialize_EC(DHState *dhState)
{
    EVP_PKEY *pkey = NULL;
    //BIGNUM *pBNPubKey = NULL, *pBNPriKey = NULL;
    bool success = false;

    pkey = generate_EC_keypair_curve_keypair_separate();
    if (pkey == NULL)
    {
        goto done;
    }

    // EC public key is not BIGNUM!!! It is the x, y coordinates of a point on a plane.
    
    //if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pBNPubKey) != 1)
    //{
    //    goto done;
    //}
    //if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &pBNPriKey) != 1)
    //{
    //    goto done;
    //}


    // This comment is incorrect!!!

    // EVP_PKEY_get_octet_params appears be better when the eventual output we want is bytes array,
    // but that requires the knowledge of the key size so that the bytes array is already allocated.
    // EVP_PKEY_get_params can also work, but it requires two successive calls, first the output data
    // field set to null so that it only gets the length.
    // So after considering the other two alternatives, storing a BIGNUM is still the better option.

    success = true;
    
    done:

    if (success)
    {
        dhState->ecKeyPair = pkey;
        //dhState->pBNPriKey = pBNPriKey;
        //dhState->pBNPubKey = pBNPubKey;
    }
    else
    {
        if (pkey)
            EVP_PKEY_free(pkey);
        //if (pBNPriKey)
        //    BN_free(pBNPriKey);
        //if (pBNPubKey)
        //    BN_free(pBNPubKey);
    }
    return success;
}

DHState *DhInitialize(int dhtype, char *pszRemotePartyParams)
{
    DHState *dhState = DhAllocAndDuplicateInput(dhtype, pszRemotePartyParams);

    if (dhState == NULL)
        return NULL;
    
    dhState->dhtype = dhtype;

    bool test_combined_domain_and_keypair = false;

    if (dhtype == 1 || dhtype == 2)
    {
        if (test_combined_domain_and_keypair)
        {
            if (!DhInitialize_DL_liyk(dhState))
            {
                OPENSSL_free(dhState);
                return NULL;
            }
        }
        else
        {
            if (!DhInitialize_DL(dhState))
            {
                OPENSSL_free(dhState);
                return NULL;
            }
        }
    }
    else if (dhtype == com_adaptiva_fips_CryptoConstants_DHEC256)
    {
        if (!DhInitialize_EC(dhState))
        {
            OPENSSL_free(dhState);
            return NULL;
        }
    }
    return dhState;
}

char* DhGetInitializationParameters(DHState *pState)
{
    if (pState == NULL || pState->pszDhPrimeAndGeneratorInBinary == NULL)
        return NULL;

    return _strdup(pState->pszDhPrimeAndGeneratorInBinary);
}

static byte* DhGetPublicKey_DL(DHState* pState, int* pnPublicKeyLength)
{
    if (pState->pBNPubKey == NULL)
        return NULL;

    int nLength = BN_num_bytes(pState->pBNPubKey);
    byte* pPubKeyBuffer = (byte*)OPENSSL_malloc(nLength);
    if (pPubKeyBuffer == NULL)
        return NULL;

    nLength = BN_bn2bin(pState->pBNPubKey, pPubKeyBuffer);

    *pnPublicKeyLength = nLength;
    return pPubKeyBuffer;
}

static byte* DhGetPublicKey_EC(DHState* pState, int* pnPublicKeyLength)
{
    byte* pubkey = NULL;
    size_t actualPubKeyLen;
    size_t estimatePubKeyLen = 65;
    pubkey = (byte*)malloc(estimatePubKeyLen);
    EVP_PKEY_get_octet_string_param(pState->ecKeyPair, OSSL_PKEY_PARAM_PUB_KEY, pubkey, estimatePubKeyLen, &actualPubKeyLen);
    if (actualPubKeyLen != estimatePubKeyLen)
    {
        return NULL;
    }
    *pnPublicKeyLength = actualPubKeyLen;
    return pubkey;
}

byte* DhGetPublicKey(DHState *pState, int *pnPublicKeyLength)
{
    if (pState == NULL || pnPublicKeyLength == NULL)
        return NULL;

    if (pState->dhtype == 1 || pState->dhtype == 2)
        return DhGetPublicKey_DL(pState, pnPublicKeyLength);
    else if (pState->dhtype == 3)
        return DhGetPublicKey_EC(pState, pnPublicKeyLength);

    return NULL;
}

static bool deriveSecretDH(EVP_PKEY *peerKey, EVP_PKEY *selfKeyPair, byte **ppSecret, int *pnSecretLength)
{
    EVP_PKEY_CTX *derivationCtx;
    ENGINE *eng = NULL;
    byte *sec = NULL;
    size_t secLen;
    bool success = false;

    derivationCtx = EVP_PKEY_CTX_new_from_pkey(NULL, selfKeyPair, NULL);

    EVP_PKEY_derive_init(derivationCtx);

    /*
    * TODO:
    * Do I need to set these parameters
    * www.openssl.org/docs/manmaster/man7/EVP_KEYEXCH-ECDH.html
    * 
    *   params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad);
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                                 "X963KDF", 0);
        params[2] = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                                 "SHA1", 0);
        params[3] = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                            &out_len);
        params[4] = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                                  ukm, ukm_len);
        params[5] = OSSL_PARAM_construct_end();
        EVP_PKEY_CTX_set_params(dctx, params)
    *
    */

    EVP_PKEY_derive_set_peer(derivationCtx, peerKey);

    EVP_PKEY_derive(derivationCtx, NULL, &secLen);

    sec = (byte*)OPENSSL_malloc(secLen);

    EVP_PKEY_derive(derivationCtx, sec, &secLen);

    success = true;
    *ppSecret = sec;
    *pnSecretLength = secLen;
    return success;
}

int DhCompleteHandshake(DHState *pState, byte *pRemotePublicKey, int nRemotePublicKeyLength)
{
    EVP_PKEY *peerKey;
    EVP_PKEY* selfKeyPair = NULL;
    // can't use EVP_PKEY_new_raw_public_key_ex to create peer key structure, because discrete log DH and ECDH don't support it
    if (pState->dhtype == 1 || pState->dhtype == com_adaptiva_fips_CryptoConstants_DH2048)
    {
        //peerKey = createPeerPKEY_DL_WithNamedGroup(pState->pBNPrime, pState->pBNGenerator, pRemotePublicKey, nRemotePublicKeyLength);

        // openssl <---> openssl, using named group is more convenient.
        // In case of crypto++(Alice) <---> openssl(Bob), openssl (as Bob) needs to build DH domain by importing
        // randomly selected Prime and Generator, because crypto++ doesn't use named group.
        // Because the need to inter-operate with Crypto++, we build DH domain by importing Prime and Generator.

        peerKey = createPeerPKEY_DL(pState->pBNPrime, pState->pBNGenerator, pRemotePublicKey, nRemotePublicKeyLength);

        selfKeyPair = pState->keyPair;
    }
    else
    {
        peerKey = createPeerPKEY_EC(pRemotePublicKey, nRemotePublicKeyLength);
        selfKeyPair = pState->ecKeyPair;
    }

    byte *sec;
    int secLen;
    if (!deriveSecretDH(peerKey, selfKeyPair, &sec, &secLen))
    {
        LOG3(logMessage, "FAIL", "Derive (agree on) DH shared secret", 0, 0, "");
        return 1;
    }

    pState->sharedSecret = sec;
    pState->nSharedSecretLength = secLen;
    pState->fHandshakeCompleted = true;

    return 0;
}

int DhRelease(DHState *pState)
{
    if (pState != NULL)
    {
        if (pState->pBNPrime)
            BN_free(pState->pBNPrime);
        if (pState->pBNGenerator)
            BN_free(pState->pBNGenerator);
        //if (pState->pBNPriKey != NULL)
        //    BN_free(pState->pBNPriKey);
        if (pState->pBNPubKey != NULL)
            BN_free(pState->pBNPubKey);
        if (pState->keyPair != NULL)
            EVP_PKEY_free(pState->keyPair);
        if (pState->ecKeyPair)
            EVP_PKEY_free(pState->ecKeyPair);
        if (pState->sharedSecret != NULL)
            OPENSSL_free(pState->sharedSecret);
        if (pState->pszDhPrimeAndGeneratorInBinary != NULL)
            zeroAndFreeBuffer(pState->pszDhPrimeAndGeneratorInBinary, strlen(pState->pszDhPrimeAndGeneratorInBinary));

        OPENSSL_free(pState);
    }
    return 1;
}

byte *DhGenerateAESKey(DHState *pState, int *pnAESKeyLength)
{
    byte *aesKeyInBinary = NULL;
    aesKeyInBinary = getSecureHash(com_adaptiva_fips_CryptoConstants_SECUREHASH_ALGORITHM_SHA256, pState->sharedSecret, pState->nSharedSecretLength, pnAESKeyLength);
    return aesKeyInBinary;
}






// =============================
// DER Encoding & Decoding EC Key
// =============================

static void derEncodeECPkey(byte **output, size_t *outputLen, EVP_PKEY *pkey, int publicOrPrivate)
{
    int r;
    OSSL_ENCODER_CTX *ctx = NULL;

    int selection = publicOrPrivate ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR;
    char const * output_struct = publicOrPrivate ? "SubjectPublicKeyInfo" : "PrivateKeyInfo";
    ctx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", output_struct, /*properties*/NULL);

    r = OSSL_ENCODER_to_data(ctx, output, outputLen);
    OSSL_ENCODER_CTX_free(ctx);
}

static void derDecodeECPkey(EVP_PKEY **ppPkey, byte const *encodedKey, size_t encodedKeyLen, int publicOrPrivate)
{
    int r;
    OSSL_DECODER_CTX *ctx = NULL;

    int selection = publicOrPrivate ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR;
    char const * input_struct = publicOrPrivate ? "SubjectPublicKeyInfo" : "PrivateKeyInfo";

    ctx = OSSL_DECODER_CTX_new_for_pkey(ppPkey, "DER", input_struct, "EC", selection, /*lib context*/NULL, /*properties*/NULL);
    r = OSSL_DECODER_from_data(ctx, &encodedKey, &encodedKeyLen);
    OSSL_DECODER_CTX_free(ctx);
}


// =============================================================
//  lightweight wrapper around EC public/private key schema
// =============================================================

static int DsaGenerateKeyPairInPlainBinary(byte **ppPriKey, int *pnPriKeyLen, byte **ppPubKey, int *pnPubKeyLen)
{
    EVP_PKEY *curve = NULL;
    EVP_PKEY *pkey = NULL;

    OSSL_PARAM params[4];
    OSSL_PARAM *p = params;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)SN_X9_62_prime256v1, 0);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, (char*)"prime-field", 0);
    *p = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX *curveCtx = NULL, *keyCtx = NULL;

    curveCtx = EVP_PKEY_CTX_new_from_name(/* lib context */ NULL, "EC", /* prop query */ NULL);

    EVP_PKEY_keygen_init(curveCtx);

    EVP_PKEY_CTX_set_params(curveCtx, params);

    EVP_PKEY_generate(curveCtx, &curve);

    keyCtx = EVP_PKEY_CTX_new_from_pkey(/* lib context */ NULL, curve, /*prop query*/ NULL);
    EVP_PKEY_keygen_init(keyCtx);
    EVP_PKEY_generate(keyCtx, &pkey);

    BIGNUM *pBNPubKey, *pBNPriKey;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &pBNPubKey);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &pBNPriKey);

    int len = 0;

    len = BN_num_bytes(pBNPriKey);
    *ppPriKey = (byte*)OPENSSL_zalloc(len);
    len = BN_bn2bin(pBNPriKey, *ppPriKey);

    len = BN_num_bytes(pBNPubKey);
    *ppPubKey = (byte*)OPENSSL_zalloc(len);
    len = BN_bn2bin(pBNPubKey, *ppPubKey);

    // EVP_PKEY_get_octet_params appears to make it easier which fills a binary array directly.
    // but that requires the knowledge of the key size so that the binary array is ready to be filled.
    // EVP_PKEY_get_params can also work, but it requires two successive calls, first the output data
    // field set to null so that it only gets the length.

    EVP_PKEY_CTX_free(curveCtx);
    EVP_PKEY_CTX_free(keyCtx);
    EVP_PKEY_free(curve);
    EVP_PKEY_free(pkey);
    return 1;
}

int DsaGenerateKeyPair(byte **ppPriKey, int *pnPriKeyLen, byte **ppPubKey, int *pnPubKeyLen)
{
    EVP_PKEY* pkey = NULL; 
    pkey = generate_EC_keypair_curve_keypair_separate();

    size_t priLen, pubLen;

    //derEncodeECPkey(ppPriKey, (size_t*)pnPriKeyLen, pkey, /*public or private*/false);
    //derEncodeECPkey(ppPubKey, (size_t*)pnPubKeyLen, pkey, /*public or private*/true);
    // pnPriKeyLen and pnPubKeyLen are pointers to int, if I directly cast them to pointers to size_t
    // the compiler will think they occupy more space on the stack. If there are another dynamically allocated
    // area next to them, for example:
    // |---------------------------------------|-------------|
    //   malloc'ed memory                       pnPriKeyLen
    // 
    // If pnPriKeyLen's size is thought to have become bigger:
    // |--------------------------------|-------.------------|
    //   malloc'ed memory               |
    //                                  |
    //                              wrong boundary
    //
    //
    // When I free the malloc'ed memory, the compiler will think that I have encroached on pnPriKeyLen's space.
    // This causes this exception:
    // Run-Time Check Failure #2 - Stack around the variable 'pubLen' was corrupted.

    derEncodeECPkey(ppPriKey, &priLen, pkey, /*public or private*/false);
    derEncodeECPkey(ppPubKey, &pubLen, pkey, /*public or private*/true);

    *pnPriKeyLen = (int)priLen;
    *pnPubKeyLen = (int)pubLen;

    return 1;
}



// ============================
//  ECDSA
// ============================

//b2b31575f8536b284410d01217f688be3a9faf4ba0ba3a9093f983e40d630ec7
//22a7a25b01403cff0d00b3b853d230f8e96ff832b15d4ccc75203cb65896a2d5

// 30
// 45
// 02
// 21
// 00 B2B31575F8536B284410D01217F688BE3A9FAF4BA0BA3A9093F983E40D630EC7
// 02
// 20
// 22A7A25B01403CFF0D00B3B853D230F8E96FF832B15D4CCC75203CB65896A2D5


byte* derEncodeEcdsaSignature(byte* sig, int* outputLen)
{

    size_t outLen;
    byte* out;

    byte* r = sig;
    byte* s = sig + 32;
    size_t rLen;
    size_t sLen;

    unsigned char r1 = *r;
    unsigned char s1 = *s;

    rLen = r1 >= 128 ? 33 : 32;
    sLen = s1 >= 128 ? 33 : 32;

    outLen = 6 + rLen + sLen;

    out = (byte*)malloc(outLen);
    byte* p = out;

    *p++ = 0x30;
    *p++ = outLen - 2;
    *p++ = 0x02;
    *p++ = rLen;
    if (r1 >= 128)
        *p++ = 0x0;
    memcpy(p, r, 0x20);
    p += 0x20;
    *p++ = 0x02;
    *p++ = sLen;
    if (s1 >= 128)
        *p++ = 0x0;
    memcpy(p, s, 0x20);

    *outputLen = (int)outLen;

    return out;
}

byte* derDecodeEcdsaSignature(byte* sig, int* outputLen)
{
    byte* out = (byte*)malloc(64);
    byte* r = out;
    byte* s = out + 32;

    byte* p = sig;

    p += 3;
    unsigned char rLen = *p;

    if (rLen == 0x20)
    {
        p++;
    }
    else if (rLen == 0x21)
    {
        p += 2;
    }
    memcpy(r, p, 0x20);
    p += 0x20;

    if (*p != 0x02)
        return NULL;

    p++;
    unsigned char sLen = *p;

    if (sLen == 0x20)
    {
        p++;
    }
    else if (sLen == 0x21)
    {
        p += 2;
    }
    memcpy(s, p, 0x20);

    *outputLen = 64;

    return out;
}


// OpenSSL always generates ECDSA signature in DER encoded format
static int generateDerEncodedEcdsaSignature(byte *pDataBuffer, int nDataBufferLength, byte *pPrivateKey, int nPrivateKeyLength, byte **ppSignature, int *pnSignatureLength)
{
    EVP_PKEY *pkey = NULL;

    derDecodeECPkey(&pkey, pPrivateKey, nPrivateKeyLength, /*publicOrPrivate*/false);

    EVP_MD_CTX *digestCtx = NULL;

    digestCtx = EVP_MD_CTX_create();

    EVP_DigestSignInit_ex(digestCtx, /* pkey ctx */NULL, "SHA512", /*lib context*/NULL, /* props */NULL, pkey, /* params */NULL);
    EVP_DigestSignUpdate(digestCtx, pDataBuffer, nDataBufferLength);

    size_t sig_len;
    EVP_DigestSignFinal(digestCtx, NULL, &sig_len);

    *ppSignature = (byte*)OPENSSL_zalloc(sig_len);

    EVP_DigestSignFinal(digestCtx, *ppSignature, &sig_len);

    EVP_MD_CTX_free(digestCtx);
    *pnSignatureLength = sig_len;
    EVP_PKEY_free(pkey);

    return 0;
}

// signature generated is in plain r|s concatenated format
int DsaGenerateSignature(byte* pDataBuffer, int nDataBufferLength, byte* pPrivateKey, int nPrivateKeyLength, byte** ppSignature, int* pnSignatureLength)
{
    byte* derEncodedSig = NULL;
    int derEncodedSigLen;
    int plainSigLen;
    byte* plainSig = NULL;

    generateDerEncodedEcdsaSignature(pDataBuffer, nDataBufferLength, pPrivateKey, nPrivateKeyLength, &derEncodedSig, &derEncodedSigLen);

    plainSig = derDecodeEcdsaSignature(derEncodedSig, &plainSigLen);

    free(derEncodedSig);

    *ppSignature = plainSig;
    *pnSignatureLength = plainSigLen;

    return 0;
}


// OpenSSL always assumes the input signature is in DER encoded format
static int verifyDerEncodedEcdsaSignature(byte *pDataBuffer, int nDataBufferLength, byte *pPublicKey, int nPublicKeyLength, byte *pSignature, int nSignatureLenght)
{
    EVP_PKEY *pkey = NULL;

    derDecodeECPkey(&pkey, pPublicKey, nPublicKeyLength, /*publicOrPrivate*/true);

    EVP_MD_CTX *digestCtx = NULL;

    digestCtx = EVP_MD_CTX_create();

    EVP_DigestVerifyInit_ex(digestCtx, /*pkey ctx*/NULL, "SHA512", /*lib context*/NULL, /* props */ NULL, pkey, /*params*/ NULL);

    EVP_DigestVerifyUpdate(digestCtx, pDataBuffer, nDataBufferLength);

    int isMatch = EVP_DigestVerifyFinal(digestCtx, pSignature, nSignatureLenght);

    EVP_MD_CTX_free(digestCtx);
    EVP_PKEY_free(pkey);

    return isMatch == 1 ? 0 : -99;
}

// assuming signature is in plain r|s concatenated format
int DsaVerifySignature(byte* pDataBuffer, int nDataBufferLength, byte* pPublicKey, int nPublicKeyLength, byte* pSignature, int nSignatureLenght)
{
    byte* derEncodedSig;
    int derEncodedSigLen;
    
    derEncodedSig = derEncodeEcdsaSignature(pSignature, &derEncodedSigLen);
    
    int ret;
    ret = verifyDerEncodedEcdsaSignature(pDataBuffer, nDataBufferLength, pPublicKey, nPublicKeyLength, derEncodedSig, derEncodedSigLen);
    
    free(derEncodedSig);
    
    return ret;
}



// =======================
// ECIES
// =======================

static void incrementWord32 (unsigned char a[4])
{
    for (int i = 3; i >= 0; i--)
    {
        unsigned char b = a[i];
        if (b < 255)
        {
            a[i]++;
            for (int j = i+1; j < 4; j++)
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

static void xorbuf(byte* output, byte* input, byte* mask, int len)
{
    uint64_t i64, m64, o64;
    uint32_t i32, m32, o32;
    uint16_t i16, m16, o16;
    uint8_t i8, m8, o8;
    int filledLen = 0;
    byte *po = output;
    byte *pi = input;
    byte *pm = mask;
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

static byte* p1363KeyDerive(byte *sec, int secLen, int neededKeyLen)
{
    int r;
    // set up input to key stretching algorithm (repeatative SHA1)
    int nHashInputLen = secLen + 4;
    byte *pHashInput = (byte*)OPENSSL_malloc(nHashInputLen);
    memcpy(pHashInput, sec, secLen);

    byte *pCounterPosition = pHashInput + secLen;

    unsigned char pCounter[4] = {0, 0, 0, 1};

    // set up the SHA1 digest
    EVP_MD *sha1;
    EVP_MD_CTX *ctx;

    sha1 = EVP_MD_fetch(/*lib context*/NULL, "SHA1", /*properties*/NULL);
    ctx = EVP_MD_CTX_new();
    r = EVP_DigestInit(ctx, sha1);
    int nDigestLen = EVP_MD_get_size(sha1);
    byte *digest = (byte*)OPENSSL_malloc(nDigestLen);

    // create space for key
    byte *pCipherKey = (byte*)OPENSSL_malloc(neededKeyLen);
    
    // stretch the shared secret to generate key
    int nFilledLen = 0;
    byte *p = pCipherKey;
    while (nFilledLen < neededKeyLen)
    {
        memcpy(pCounterPosition, pCounter, sizeof(pCounter));
        r = EVP_DigestUpdate(ctx, pHashInput, nHashInputLen);
        r = EVP_DigestFinal(ctx, digest, (unsigned int*) & nDigestLen);
        int thisIterationFilledLen = min(nDigestLen, neededKeyLen - nFilledLen);
        memcpy(p, digest, thisIterationFilledLen);
        p += thisIterationFilledLen;
        nFilledLen += thisIterationFilledLen;
        memset(digest, 0, nDigestLen);
        r = EVP_DigestInit(ctx, sha1);
        incrementWord32(pCounter);
    }

    OPENSSL_free(pHashInput);
    OPENSSL_free(digest);
    EVP_MD_free(sha1);
    EVP_MD_CTX_free(ctx);

    return pCipherKey;
}

static byte *computeHmacSha1(byte *key, int keyLen, byte *pData, int dataLen, int *outputLen)
{
    int r;
    EVP_MAC *hmac = NULL;
    EVP_MAC_CTX *hmacCtx = NULL;

    hmac = EVP_MAC_fetch(/*lib context*/NULL, "HMAC", /*properties*/ NULL);
    hmacCtx = EVP_MAC_CTX_new(hmac);

    OSSL_PARAM params[3];
    OSSL_PARAM *pParams = params;
    *pParams++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char*)"SHA1", 4);
    *pParams = OSSL_PARAM_construct_end();

    r = EVP_MAC_init(hmacCtx, key, keyLen, params);

    r = EVP_MAC_update(hmacCtx, pData, dataLen);

    size_t hmacOutputLen;
    r = EVP_MAC_final(hmacCtx, NULL, &hmacOutputLen, 0); // output length should be 20 bytes, because of SHA1

    byte *hmacOutput = (byte*)OPENSSL_malloc(hmacOutputLen);
    r = EVP_MAC_final(hmacCtx, hmacOutput, &hmacOutputLen, hmacOutputLen);

    *outputLen = hmacOutputLen;
    return hmacOutput;
}

static byte* eciesEncryptBuffer(byte* pPublicKey, int nPublicKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize)
{
    // get self and peer's keys ready
    EVP_PKEY *peerKey;
    derDecodeECPkey(&peerKey, pPublicKey, nPublicKeyLength, /*publicOrPrivate*/true);

    EVP_PKEY *selfKeyPair = NULL;
    selfKeyPair = generate_EC_keypair_single_context();

    // derive a secret
    byte *sec;
    int secLen;
    deriveSecretDH(peerKey, selfKeyPair, &sec, &secLen);

    // get self public key
    // must not get it in BIGNUM format, because public key is a point on a curve
    // it's essentially the coordinates, it's not a big number after all.
    // private key can be retrieved in BIGNUM format.
    /*
    BIGNUM *pBNSelfPubKey = NULL;
    EVP_PKEY_get_bn_param(selfKeyPair, OSSL_PKEY_PARAM_PUB_KEY, &pBNSelfPubKey);
    int nSelfPubKeyLen;
    nSelfPubKeyLen = BN_num_bytes(pBNSelfPubKey);
    byte* pBinarySelfPubKey = (byte*)OPENSSL_malloc(nSelfPubKeyLen);
    nSelfPubKeyLen = BN_bn2bin(pBNSelfPubKey, pBinarySelfPubKey);
    */
    byte selfPubKey[65];
    size_t selfPubKeyLen;
    EVP_PKEY_get_octet_string_param(selfKeyPair, OSSL_PKEY_PARAM_PUB_KEY, selfPubKey, sizeof(selfPubKey), &selfPubKeyLen);
    if (selfPubKeyLen != 65)
    {
        return NULL;
    }

    // stretch the shared secret to create encryption key and HMAC key
    int hmacKeyLen = 16;
    int nKeyLen = nDataBufferLength + hmacKeyLen; // data encryption key and HMAC key
    byte *pCipherKey = p1363KeyDerive(sec, secLen, nKeyLen);

    // pCipherKey is ready, XOR encrypting
    byte *pEncryptedDataPortion = (byte*)OPENSSL_malloc(nDataBufferLength);
    xorbuf(pEncryptedDataPortion, pDataBuffer, pCipherKey, nDataBufferLength);

    // compute HMAC
    byte *pHmacKey = pCipherKey + nDataBufferLength;
    int knownHmacOutputLen = 20;
    int hmacOutputLen;
    byte *hmacOutput = computeHmacSha1(pHmacKey, hmacKeyLen, pEncryptedDataPortion, nDataBufferLength, &hmacOutputLen);
    if (hmacOutputLen != knownHmacOutputLen)
    {
        return NULL;
    }

    // =============================
    // everything is ready, assemble

    // create space for final output
    int nTotalOutputSize = selfPubKeyLen + nDataBufferLength + hmacOutputLen; // output of HMAC(SHA1) is 20 bytes
    byte *pOutput = (byte*)OPENSSL_malloc(nTotalOutputSize);

    // assemble
    byte *pOutputStart = pOutput;
    memcpy(pOutput, selfPubKey, selfPubKeyLen);
    pOutput += selfPubKeyLen;

    memcpy(pOutput, pEncryptedDataPortion, nDataBufferLength);
    pOutput += nDataBufferLength;

    memcpy(pOutput, hmacOutput, hmacOutputLen);

    // free intermediate memory
    OPENSSL_free(sec);
    //OPENSSL_free(pBinarySelfPubKey);
    OPENSSL_free(pEncryptedDataPortion);
    OPENSSL_free(pCipherKey);
    OPENSSL_free(hmacOutput);
    EVP_PKEY_free(peerKey);
    EVP_PKEY_free(selfKeyPair);
    //BN_free(pBNSelfPubKey);

    *pnEncryptedBufferSize = nTotalOutputSize;
    return pOutputStart;
}

static byte* eciesDecryptBuffer(byte* pPrivateKey, int nPrivateKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize)
{
    // get self and peer's keys ready
    EVP_PKEY *selfKey;
    EVP_PKEY *peerKey;

    derDecodeECPkey(&selfKey, pPrivateKey, nPrivateKeyLength, /*publicOrPrivate*/false);
    
    byte *pRemotePubKey = pDataBuffer;
    int nRemotePubKeyLen = 65;

    peerKey = createPkeyWithOneKey_EC_combined_curve_keypair(pRemotePubKey, nRemotePubKeyLen, /*is public*/true);

    // derive a secret
    byte *sec;
    int secLen;
    deriveSecretDH(peerKey, selfKey, &sec, &secLen);

    // derive keys for encryption and HMAC
    int hmacKeyLen = 16;
    int knownHmacOutputLen = 20;
    int needKeyLen = nDataBufferLength - nRemotePubKeyLen - knownHmacOutputLen + hmacKeyLen;
    byte *key = p1363KeyDerive(sec, secLen, needKeyLen);

    // locate the start of cipher text
    byte *pCipher = pDataBuffer + nRemotePubKeyLen;
    int nCipherTextLen = nDataBufferLength - nRemotePubKeyLen - knownHmacOutputLen;

    // verify HMAC
    byte *hmacKey = key + nCipherTextLen;
    int hmacOutputLen;
    byte *pComputedHmacTag = computeHmacSha1(hmacKey, hmacKeyLen, pCipher, nCipherTextLen, &hmacOutputLen);

    byte *pReceivedHmacTag = pDataBuffer + nRemotePubKeyLen + nCipherTextLen;

    if (hmacOutputLen != knownHmacOutputLen || memcmp(pComputedHmacTag, pReceivedHmacTag, hmacOutputLen) != 0)
    {
        // HMAC authentication failed
        return NULL;
    }

    // create space for decrypted output
    byte *pClearText = (byte*)OPENSSL_malloc(nCipherTextLen);
    xorbuf(pClearText, pCipher, key, nCipherTextLen);
    *pnDecryptedBufferSize = nCipherTextLen;

    // free intermediate memory
    EVP_PKEY_free(peerKey);
    EVP_PKEY_free(selfKey);
    OPENSSL_free(sec);
    OPENSSL_free(key);
    OPENSSL_free(pComputedHmacTag);

    return pClearText;
}

byte* DsaEncryptBuffer(byte* pPublicKey, int nPublicKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize)
{
    return eciesEncryptBuffer(pPublicKey, nPublicKeyLength, pDataBuffer, nDataBufferLength, pnEncryptedBufferSize);
}

byte* DsaDecryptBuffer(byte* pPrivateKey, int nPrivateKeyLength, byte* pDataBuffer, int nDataBufferLength, int* pnDecryptedBufferSize)
{
    return eciesDecryptBuffer(pPrivateKey, nPrivateKeyLength, pDataBuffer, nDataBufferLength, pnDecryptedBufferSize);
}

}