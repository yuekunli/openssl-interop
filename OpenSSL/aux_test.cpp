#include<iostream>

typedef unsigned char byte;

namespace ADAPTIVA_AUX {
    char* base32Encode(byte* p, size_t l);
    byte* base32Decode(char* pszIn, int* outSize);
}

namespace ADAPTIVA_AUX2 {
    char* base32Encode(byte* p, size_t l);
    byte* base32Decode(char* pszIn, int* outSize);
}

namespace AUX_TEST {
    char const* clearText =
        "Kirkland is a city in King County, Washington, United States. "
        "A suburb east of Seattle, its population was 92,175 in the 2020 U.S. census "
        "which made it the sixth largest city in the county and "
        "the twelfth largest in the state.\n"
        "The city\'s downtown waterfront has restaurants, art galleries, "
        "a performing arts center, public parks, beaches, and a collection "
        "of public art, primarily bronze sculptures.\n"
        "Kirkland was the original home of the Seattle Seahawks; "
        "the NFL team\'s headquarters and training facility were located "
        "at the Lake Washington Shipyard (now Carillon Point) along Lake Washington "
        "for their first ten seasons (1976–85), then at nearby Northwest University "
        "through 2007. Warehouse chain Costco previously had its headquarters in Kirkland. "
        "While Costco is now headquartered in Issaquah, the city is the namesake of "
        "its \"Kirkland Signature\" store brand.";

    void test1()
    {
        char const * p = clearText;

        char* afterEncoding = ADAPTIVA_AUX::base32Encode((byte*)p, strlen(p)+1);

        std::cout << afterEncoding << std::endl;

        int decodedSize;
        byte* afterDecoding = ADAPTIVA_AUX::base32Decode(afterEncoding, &decodedSize);

        std::cout << (char*)afterDecoding << "    " << decodedSize << std::endl;
        free(afterEncoding);
        free(afterDecoding);
    }

    void test2()
    {
        char const* p = clearText;

        char* afterEncoding = ADAPTIVA_AUX2::base32Encode((byte*)p, strlen(p)+1);

        std::cout << afterEncoding << std::endl;

        int decodedSize;
        byte* afterDecoding = ADAPTIVA_AUX2::base32Decode(afterEncoding, &decodedSize);

        std::cout << (char*)afterDecoding << "    " << decodedSize << std::endl;
        free(afterEncoding);
        free(afterDecoding);
    }
}