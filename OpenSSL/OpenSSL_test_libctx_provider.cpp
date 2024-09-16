
#include<openssl/crypto.h>
#include <openssl/provider.h>

#include <stdexcept>

namespace OPENSSL_LIBCTX_PROVIDER_TEST {

    OSSL_LIB_CTX* fips_libctx = NULL;
    OSSL_PROVIDER* base = NULL;
    OSSL_PROVIDER* fips = NULL;

    void initialize_fips_libctx()
    {
        if (fips_libctx != NULL)
            return;

        fips_libctx = OSSL_LIB_CTX_new();
        if (fips_libctx == NULL)
        {
            throw std::runtime_error("FAIL. Create new lib context");
        }
        if (!OSSL_LIB_CTX_load_config(fips_libctx, "C:\\temp\\openssl.cnf"))
        {
            OSSL_LIB_CTX_free(fips_libctx);
            fips_libctx = NULL;
            throw std::runtime_error("FAIL. Load config file for FIPS lib context");
            return;
        }

        base = OSSL_PROVIDER_load(fips_libctx, "base");
        if (base == NULL)
        {
            throw std::runtime_error("FAIL. Load base provider");
            return;
        }

        if (!OSSL_PROVIDER_set_default_search_path(fips_libctx, "C:\\temp"))
        {
            throw std::runtime_error("FAIL. set default search path for provider dll");
            return;
        }
        /*
        * It's possible to not call set_default_search_path and then give a full path to OSSL_PROVIDER_load.
        * However, if I call load in such way: OSSL_PROVIDER_load(fips_libctx, "C:\\temp\\fips.dll");
        * The dll will be loaded without problem, but it can't pass self test.
        * In that way, the provider's name is literally identified as "C:\temp\fips.dll".
        * And if in the config file I have a provider called "fips", these two won't be deemed the same.
        * The fips' provider's module-mac should be present in the config file, than the self test will
        * check that module-mac. But if the config file says the module-mac belongs to a provider called "fips",
        * and I loaded a provider called "C:\temp\fips.dll". The one I loaded won't be treated same as the one
        * owning that module-mac.
        */

        fips = OSSL_PROVIDER_load(fips_libctx, "fips2");
        if (fips == NULL)
        {
            throw std::runtime_error("FAIL. Load FIPS provider");
            return;
        }
    }

    void cleanup_fips_libctx()
    {
        if (base != NULL)
        {
            OSSL_PROVIDER_unload(base);
            base = NULL;
        }
        if (fips != NULL)
        {
            OSSL_PROVIDER_unload(fips);
            fips = NULL;
        }

        if (fips_libctx != NULL)
            OSSL_LIB_CTX_free(fips_libctx);

        fips_libctx = NULL;
    }


}