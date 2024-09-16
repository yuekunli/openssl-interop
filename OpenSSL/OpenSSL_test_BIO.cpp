// OpenSSL headers
#include <openssl/bio.h>

// C/C++ headers
#include <string>
#include <iostream>


namespace OPENSSL_BIO_TEST {

    void read_from_BIO()
    {
        BIO* pBIO = BIO_new(BIO_s_mem());

        unsigned char* p = (unsigned char*)malloc(100);

        for (int i = 0; i < 100; i++)
            *(p + i) = (unsigned char)i;

        BIO_write(pBIO, p, 100);

        memset(p, 0, 100);

        size_t readbytes = 0;

        BIO_read_ex(pBIO, p, 70, &readbytes);

        memset(p, 0, 100);

        BIO_read_ex(pBIO, p, 70, &readbytes);

        std::cout << readbytes << std::endl;

        std::cout << (int)(p[0]) << " " << (int)(p[29]) << "\n";

        free(p);

        BIO_set_flags(pBIO, BIO_FLAGS_MEM_RDONLY);
        BIO_free(pBIO);
    }


    void set_BIO_position()
    {
        BIO* pBIO = BIO_new(BIO_s_mem());

        unsigned char* p = (unsigned char*)malloc(100);

        for (int i = 0; i < 100; i++)
            *(p + i) = (unsigned char)i;

        BIO_write(pBIO, p, 100);

        memset(p, 0, 100);

        BIO_seek(pBIO, 66);

        size_t readbytes = 0;

        BIO_read_ex(pBIO, p, 100, &readbytes);

        std::cout << readbytes << std::endl;

        std::cout << (int)(p[0]) << " " << (int)(p[29]) << "\n";

        free(p);

        BIO_set_flags(pBIO, BIO_FLAGS_MEM_RDONLY);
        BIO_free(pBIO);
    }
}