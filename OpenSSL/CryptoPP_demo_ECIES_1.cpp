#include "osrng.h"
#include "integer.h"
//#include "nbtheory.h"
#include "secblock.h"
//#include "asn.h"
//#include "oids.h"
#include "eccrypto.h"
//#include "modes.h"
#include "filters.h"

USING_NAMESPACE(CryptoPP)

typedef unsigned char BYTE;

namespace CRYPTOPP_DEMO {
 
    static AutoSeededRandomPool _grng;

    BYTE dataBuffer[] = {
        0x40, 0xf8, 0xfc, 0x9e, 0xc1, 0xc4, 0x87, 0x17,
        0xa3, 0x4d, 0xc7, 0xb1, 0x93, 0xb9, 0xec, 0x0c,
        0x27, 0x4b, 0x43, 0x91, 0x8b, 0xfb, 0x4c, 0x8c,
        0x26, 0x1a, 0xd0, 0x8e, 0x7e, 0x4c, 0xa7, 0x36
    };

    BYTE* ECIES_encrypt_test(BYTE* pPublicKey, int nPublicKeyLength, BYTE* pDataBuffer, int nDataBufferLength, int* pnEncryptedBufferSize)
    {
        BYTE* pRetVal = NULL;

        ECIES<ECP>::Encryptor encryptor;

        StringSource ss(pPublicKey, nPublicKeyLength, true);
        encryptor.AccessPublicKey().Load(ss); // public key must be DER encoded, "Load" does BER decode first

        encryptor.GetPublicKey().ThrowIfInvalid(_grng, 3);

        size_t nEncrytedBufferSize;

        if ((nEncrytedBufferSize = encryptor.CiphertextLength(nDataBufferLength)) == 0)
            goto done;

        if ((pRetVal = (BYTE*)malloc(nEncrytedBufferSize)) == NULL)
            goto done;

        encryptor.Encrypt(_grng, pDataBuffer, nDataBufferLength, pRetVal);
        *pnEncryptedBufferSize = nEncrytedBufferSize;

    done:
        return pRetVal;
    }


    int hexCharToDec(char c)
    {
        if (48 <= c && c <= 57)
            return c - 48;
        else if (65 <= c && c <= 70)
            return c - 55;
        else if (97 <= c && c <= 102)
            return c - 87;
    }

    unsigned char* asciiHexToBinary(char const * p, int len, int* outputLen)
    {
        int l = len / 2;
        unsigned char* out = (unsigned char*)malloc(l);

        int v1, v2;
        for (int i = 0, j = 0; i <= len-2; i += 2, j++)
        {
            char c1 = p[i];
            char c2 = p[i + 1];
            v1 = hexCharToDec(c1);
            v2 = hexCharToDec(c2);
            unsigned char k = v1 * 16 + v2;
            out[j] = k;
        }
        *outputLen = l;
        return out;
    }

    void demo_ECIES_encrypt1()
    {
        /*
        * An example public key:
        *
        *   x: 9e4dd5d7b8759441bc365890b6a5b5d38ab78f3529ce294ef9c9c1c6388df5e6
        *   y: 81d4abbb9c096356507a5574dc8c45a347a01d94c41f510a026fca6d9a21c058
        */

        // public key must be DER encoded
        // A DER encoded public key is 311 bytes long

        char const* pubKeyInHexString = "308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF30440420FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC04205AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B0441046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5022100FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC6325510201010342000483BF30F14219155ECAF4ED54E83ACFCC54012D73EBED96E4D1C130301842AF142EE3D249C33A44A1039346E4CD149ED73B4D7E7DC9EA4D28C56523B7E64E3230";
        int outputLen;
        BYTE* publicKey = asciiHexToBinary(pubKeyInHexString, 622, &outputLen);

        int nEncryptedBufferSize;

        BYTE* cipher = ECIES_encrypt_test(publicKey, outputLen, dataBuffer, sizeof(dataBuffer), &nEncryptedBufferSize);
        // nEncryptedBufferSize = 65 + sizeof(dataBuffer) + 20

        free(publicKey);
        free(cipher);
    }

    void demo_ECIES_encrypt2()
    {
        // borrow this encoded bytes array from OpenSSL demo code
        unsigned char pub_key_der[] = {
            0x30, 0x82, 0x01, 0x4b, 0x30, 0x82, 0x01, 0x03, 0x06, 0x07, 0x2a, 0x86,
            0x48, 0xce, 0x3d, 0x02, 0x01, 0x30, 0x81, 0xf7, 0x02, 0x01, 0x01, 0x30,
            0x2c, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x01, 0x01, 0x02, 0x21,
            0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x30, 0x5b, 0x04,
            0x20, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x04, 0x20, 0x5a,
            0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76,
            0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b,
            0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b, 0x03, 0x15, 0x00, 0xc4, 0x9d,
            0x36, 0x08, 0x86, 0xe7, 0x04, 0x93, 0x6a, 0x66, 0x78, 0xe1, 0x13, 0x9d,
            0x26, 0xb7, 0x81, 0x9f, 0x7e, 0x90, 0x04, 0x41, 0x04, 0x6b, 0x17, 0xd1,
            0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
            0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33,
            0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
            0xf5, 0x02, 0x21, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
            0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
            0x02, 0x01, 0x01, 0x03, 0x42, 0x00, 0x04, 0x4f, 0xe7, 0x7b, 0xb6, 0xbb,
            0x54, 0x42, 0x39, 0xed, 0x5d, 0xe5, 0x40, 0xc8, 0xd8, 0x71, 0xca, 0x6d,
            0x83, 0x71, 0xd1, 0x88, 0x2a, 0x65, 0x00, 0x6c, 0xc6, 0x2f, 0x01, 0x31,
            0x49, 0xbe, 0x76, 0x7a, 0x67, 0x6a, 0x28, 0x33, 0xc7, 0x5b, 0xb9, 0x24,
            0x45, 0x24, 0x6e, 0xf0, 0x6d, 0x2f, 0x34, 0x06, 0x53, 0x73, 0x6a, 0xff,
            0x90, 0x90, 0xc1, 0x6d, 0x9b, 0x94, 0x0d, 0x0e, 0x1f, 0x95, 0x65,
        };
        int nEncryptedBufferSize;
        BYTE* cipherText = ECIES_encrypt_test(pub_key_der, sizeof(pub_key_der), dataBuffer, sizeof(dataBuffer), &nEncryptedBufferSize);
        free(cipherText);
    }
}