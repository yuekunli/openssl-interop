// g++ -DDEBUG=1 -g3 -O0 -Wall -Wextra cryptopp-ecies-test.cpp -o cryptopp-ecies-test.exe -lcryptopp
// g++ -DNDEBUG=1 -g3 -O2 -Wall -Wextra cryptopp-ecies-test.cpp -o cryptopp-ecies-test.exe -lcryptopp

#include <iostream>
using std::ostream;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <hex.h>
using CryptoPP::HexEncoder;

#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <integer.h>
using CryptoPP::Integer;

#include <pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include <eccrypto.h>
using CryptoPP::ECP;    // Prime field
using CryptoPP::EC2N;   // Binary field
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <pubkey.h>
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include <asn.h>
#include <oids.h>
namespace ASN1 = CryptoPP::ASN1;

#include <cryptlib.h>
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;

namespace CRYPTOPP_DEMO {

    void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
    void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out = cout);

    void SavePrivateKey(const PrivateKey& key, const string& file = "ecies.private.key");
    void SavePublicKey(const PublicKey& key, const string& file = "ecies.public.key");

    void LoadPrivateKey(PrivateKey& key, const string& file = "ecies.private.key");
    void LoadPublicKey(PublicKey& key, const string& file = "ecies.public.key");

    static const string message("Now is the time for all good men to come to the aide of their country.");

    void demo_ECIES_2()
    {
        AutoSeededRandomPool prng;

        /////////////////////////////////////////////////
        // Part one - generate keys

        ECIES<ECP>::Decryptor d0(prng, ASN1::secp256r1());
        PrintPrivateKey(d0.GetKey());

        ECIES<ECP>::Encryptor e0(d0);
        PrintPublicKey(e0.GetKey());

        // This crashes due to NotImplemented exception, but it should work since we are 
        // trying to generate a random private key (private exponent), and not a curve.
        // http://sourceforge.net/tracker/?func=detail&aid=3598113&group_id=6152&atid=356152
        //ECIES<ECP>::Decryptor d3;
        //d3.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256r1());
        //d3.AccessKey().GenerateRandom(prng, g_nullNameValuePairs);

        // Do this instead if desired or required
        //ECIES<ECP>::Decryptor d4;
        //d4.AccessKey().AccessGroupParameters().Initialize(prng, ASN1::secp256r1());

        // Do this instead if desired or required
        //ECIES<ECP>::Decryptor d5;
        //d5.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256r1());
        //Integer x(prng, Integer::One(), d5.AccessKey().GetGroupParameters().GetSubgroupOrder()-1);
        //d5.AccessKey().SetPrivateExponent(x);
        //PrintPrivateKey(d5.GetKey());

        /////////////////////////////////////////////////
        // Part two - save keys
        //   Get* returns a const reference

        SavePrivateKey(d0.GetPrivateKey());
        SavePublicKey(e0.GetPublicKey());

        /////////////////////////////////////////////////
        // Part three - load keys
        //   Access* returns a non-const reference

        ECIES<ECP>::Decryptor d1;
        LoadPrivateKey(d1.AccessPrivateKey());
        d1.GetPrivateKey().ThrowIfInvalid(prng, 3);

        ECIES<ECP>::Encryptor e1;
        LoadPublicKey(e1.AccessPublicKey());
        e1.GetPublicKey().ThrowIfInvalid(prng, 3);

        /////////////////////////////////////////////////
        // Part four - encrypt/decrypt with e0/d1

        string em0; // encrypted message
        StringSource ss1(message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0)));
        string dm0; // decrypted message
        StringSource ss2(em0, true, new PK_DecryptorFilter(prng, d1, new StringSink(dm0)));


        //string encoded; // encoded (pretty print)
        //StringSource ss3(em0, true, new HexEncoder(new StringSink(encoded)));

        //cout << "Ciphertext (" << encoded.size()/2 << "):" << endl << "  ";
        //cout << encoded << endl;
        //cout << "Recovered:" << endl << "  ";
        cout << dm0 << endl;

        /////////////////////////////////////////////////
        // Part five - encrypt/decrypt with e1/d0

        string em1; // encrypted message
        StringSource ss4(message, true, new PK_EncryptorFilter(prng, e1, new StringSink(em1)));
        string dm1; // decrypted message
        StringSource ss5(em1, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm1)));

        //StringSource ss6(em1, true, new HexEncoder(new StringSink(encoded)));

        //cout << "Ciphertext (" << encoded.size()/2 << "):" << endl << "  ";
        //cout << encoded << endl;
        //cout << "Recovered:" << endl << "  ";
        cout << dm1 << endl;
    }

    void SavePrivateKey(const PrivateKey& key, const string& file)
    {
        FileSink sink(file.c_str());
        key.Save(sink);
    }

    void SavePublicKey(const PublicKey& key, const string& file)
    {
        FileSink sink(file.c_str());
        key.Save(sink);
    }

    void LoadPrivateKey(PrivateKey& key, const string& file)
    {
        FileSource source(file.c_str(), true);
        key.Load(source);
    }

    void LoadPublicKey(PublicKey& key, const string& file)
    {
        FileSource source(file.c_str(), true);
        key.Load(source);
    }

    void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
    {
        const std::ios_base::fmtflags flags = out.flags();

        // Group parameters
        const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
        // Base precomputation
        const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
        // Public Key (just do the exponentiation)
        const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());

        out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
        out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

        out << "Coefficients" << endl;
        out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
        out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

        out << "Base Point" << endl;
        out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
        out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

        out << "Public Point" << endl;
        out << "  x: " << std::hex << point.x << endl;
        out << "  y: " << std::hex << point.y << endl;

        out << "Private Exponent (multiplicand): " << endl;
        out << "  " << std::hex << key.GetPrivateExponent() << endl;

        out << endl;
        out.flags(flags);
    }

    void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out)
    {
        const std::ios_base::fmtflags flags = out.flags();

        // Group parameters
        const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
        // Public key
        const ECPPoint& point = key.GetPublicElement();

        out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
        out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

        out << "Coefficients" << endl;
        out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
        out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

        out << "Base Point" << endl;
        out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
        out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

        out << "Public Point" << endl;
        out << "  x: " << std::hex << point.x << endl;
        out << "  y: " << std::hex << point.y << endl;

        out << endl;
        out.flags(flags);
    }
}