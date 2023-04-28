#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "aes.h"
using CryptoPP::AES;

#include "eax.h"
using CryptoPP::EAX;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

namespace CRYPTOPP_DEMO {

    int demo_EAX()
    {
        string plaintext = "Encrypted data";
        string ciphertext, recovered;

        try {

            ////////////////////////////////////////////////
            // Generate keys
            AutoSeededRandomPool rng;

            byte key[AES::DEFAULT_KEYLENGTH];
            rng.GenerateBlock(key, sizeof(key));

            byte iv[AES::BLOCKSIZE * 16];
            rng.GenerateBlock(iv, sizeof(iv));

            ////////////////////////////////////////////////
            // Encrpytion
            EAX< AES >::Encryption enc;
            enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

            StringSource(plaintext, true,
                new AuthenticatedEncryptionFilter(enc,
                    new StringSink(ciphertext)
                )  // AuthenticatedEncryptionFilter
            ); // StringSource

            ////////////////////////////////////////////////
            // Tamper
            // ciphertext[0] |= 0x0F;

            ////////////////////////////////////////////////
            // Decrpytion
            EAX< AES >::Decryption dec;
            dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

            ArraySource((byte*)ciphertext.data(), ciphertext.size(), true,
                new AuthenticatedDecryptionFilter(dec,
                    new StringSink(recovered)
                ) // AuthenticatedDecryptionFilter
            ); //ArraySource

            assert(plaintext == recovered);
            cout << "Recovered original message" << endl;

        } // try

        catch (CryptoPP::Exception& e)
        {
            std::cerr << "Error: " << e.what() << endl;
        }

        return 0;
    }
}
