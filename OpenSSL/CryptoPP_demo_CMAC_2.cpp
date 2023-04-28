// g++ -O1 -g3 -Wall -Wextra -I/usr/local/include cmac-sp800-38b.cpp /usr/local/lib/libcryptopp.a -o cmac.exe

#include <iostream>
using namespace std;

#include "filters.h"
#include "cmac.h"
#include "aes.h"
#include "hex.h"

using namespace CryptoPP;


#define UNUSED(x) ((void)x)

namespace CRYPTOPP_DEMO {

    // forward declaration:
    string HexDecode(const string& data);

    int demo_CMAC_2()
    {
        //UNUSED(argc); UNUSED(argv);

        string key, message, mac;

        CMAC< AES > cmac;
        const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 1" << endl;

        key = HexDecode("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        message = HexDecode("");
        mac = HexDecode("bb1d6929 e9593728 7fa37d12 9b756746");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 2" << endl;

        key = HexDecode("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a");
        mac = HexDecode("070a16b4 6b4d4144 f79bdd9d d04a287c");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 3" << endl;

        key = HexDecode("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411");
        mac = HexDecode("dfa66747 de9ae630 30ca3261 1497c827");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 4" << endl;

        key = HexDecode("2b7e1516 28aed2a6 abf71588 09cf4f3c");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710");
        mac = HexDecode("51f0bebf 7e3b9d92 fc497417 79363cfe");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 5" << endl;

        key = HexDecode("8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b");
        message = HexDecode("");
        mac = HexDecode("d17ddf46 adaacde5 31cac483 de7a9367");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 6" << endl;

        key = HexDecode("8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a");
        mac = HexDecode("9e99a7bf 31e71090 0662f65e 617c5184");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 7" << endl;

        key = HexDecode("8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411");
        mac = HexDecode("8a1de5be 2eb31aad 089a82e6 ee908b0e");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 8" << endl;

        key = HexDecode("8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710");
        mac = HexDecode("a1d5df0e ed790f79 4d775896 59f39a11");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 9" << endl;

        key = HexDecode("603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a");
        mac = HexDecode("28a7023f 452e8f82 bd4bf28d 8c37c35c");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 10" << endl;

        key = HexDecode("603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4");
        message = HexDecode("");
        mac = HexDecode("028962f6 1b7bf89e fc6b551f 4667d983");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 11" << endl;

        key = HexDecode("603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411");
        mac = HexDecode("aaf3d8f1 de5640c2 32f5b169 b9c911e6");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        // ***************************************************************************************

        cout << "NIST SP 800-38B, Example 12" << endl;

        key = HexDecode("603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4");
        message = HexDecode("6bc1bee2 2e409f96 e93d7e11 7393172a ae2d8a57 1e03ac9c 9eb76fac 45af8e51" \
            "30c81c46 a35ce411 e5fbc119 1a0a52ef f69f2445 df4f9b17 ad2b417b e66c3710");
        mac = HexDecode("e1992190 549f6ed5 696a2c05 6c315410");

        cmac.SetKey((const byte*)key.data(), key.size());

        try
        {
            StringSource ss(message + mac, true,
                new HashVerificationFilter(cmac, NULL, flags, mac.size())
            ); // StringSource
        }
        catch (const CryptoPP::Exception& e)
        {
            cerr << "  Failed: " << e.what() << endl;
        }

        return 0;
    }

    string HexDecode(const string& data)
    {
        string result;
        StringSource ss(data, true /*pump all*/,
            new HexDecoder(
                new StringSink(result)
            ) // HexDecoder
        ); // StringSource

        return result;

    }

}