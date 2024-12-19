#include<iostream>

#include<openssl/ecdsa.h>
#include<openssl/evp.h>
#include<openssl/core_names.h>
#include<openssl/encoder.h>
#include<openssl/decoder.h>

namespace OPENSSL_ECDSA_SIG_CONVERT {

	/**
	* The purpose of this file is to experiment with this set of APIs:
	* ECDSA_SIG_new
	* ECDSA_SIG_free
	* ECDSA_SIG_get0
	* ECDSA_SIG_set0
	* The functionality of this set APIs is to convert between the raw 'r' and 's' of an ECDSA signature
	* and the DER encoded format of a signature and an internal object of a signature
	* 
	*                                    raw 'r' 's' number
	*                                            / \
	*                                           /   \
	*                                          /     \
	*                                         /       \
	*                                        /         \
	*          DER byte array of a signature ---------- internal object of a signature
	* 
	* 
	*/

	/*
	* Generate a signature using EVP_DigestSign_... family of APIs, this signature is DER encoded.
	* Use my makeshift APIs to convert the signature to raw 'r' 's' numbers
	* Use OpenSSL APIs to convert raw 'r' 's' numbers to DER byte array
	* Use the DER byte array and the public key to verify the signature
	* 
	* 
	* Generate a signature using EVP_DigestSign_... family of APIs, this signature is DER encoded.
	* Use OpenSSL APIs to convert DER array to raw 'r' 's' numbers
	* Using my makeshift APIs to convert raw 'r' 's' numbers to DER encoded array
	* Use the DER array and the public key to verify the signature
	*/

    typedef unsigned char byte;



    static const char* hamlet_1 =
        "To be, or not to be, that is the question,\n"
        "Whether tis nobler in the minde to suffer\n"
        "The slings and arrowes of outragious fortune,\n"
        "Or to take Armes again in a sea of troubles,\n"
        ;


    //==============================================
    // My makeshift DER encode/decode of signature
    //==============================================

    static byte* findLengthAndStart(byte* input, int* length)
    {
        unsigned char v = *input;
        int skip = 0;
        while (v == 0)
        {
            input++;
            skip++;
            v = *input;
        }
        int original_length = *length;
        *length = original_length - skip;
        return input;
    }

    static byte* derEncodeEcdsaSignature(byte* sig, int* outputLen)
    {
        size_t outLen;
        byte* out;

        int l = 32;
        byte* r = findLengthAndStart(sig, &l);
        size_t rLen_after_removing_leading_zero = l;
        l = 32;
        byte* s = findLengthAndStart(sig + 32, &l);
        size_t sLen_after_removing_leading_zero = l;

        unsigned char r1 = *r;
        unsigned char s1 = *s;

        size_t rLen = r1 >= 128 ? rLen_after_removing_leading_zero + 1 : rLen_after_removing_leading_zero;
        size_t sLen = s1 >= 128 ? sLen_after_removing_leading_zero + 1 : sLen_after_removing_leading_zero;

        outLen = 6 + rLen + sLen;

        out = (byte*)malloc(outLen);
        byte* p = out;

        *p++ = 0x30;
        *p++ = outLen - 2;
        *p++ = 0x02;
        *p++ = rLen;
        if (r1 >= 128)
            *p++ = 0x0;
        memcpy(p, r, rLen_after_removing_leading_zero);
        p += rLen_after_removing_leading_zero;
        *p++ = 0x02;
        *p++ = sLen;
        if (s1 >= 128)
            *p++ = 0x0;
        memcpy(p, s, sLen_after_removing_leading_zero);

        *outputLen = (int)outLen;

        return out;
    }


    static byte* derDecodeEcdsaSignature(byte* sig, int* outputLen)
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
            memcpy(r, p, 0x20);
            p += 0x20;
        }
        else if (rLen == 0x21)
        {
            p += 2;
            memcpy(r, p, 0x20);
            p += 0x20;
        }
        else if (rLen < 0x20)
        {
            int prepend = 0x20 - rLen;
            p++;
            for (int i = 0; i < prepend; i++)
                *r++ = 0;
            memcpy(r, p, rLen);
            p += rLen;
        }

        if (*p != 0x02)
            return NULL;

        p++;
        unsigned char sLen = *p;

        if (sLen == 0x20)
        {
            p++;
            memcpy(s, p, 0x20);
        }
        else if (sLen == 0x21)
        {
            p += 2;
            memcpy(s, p, 0x20);
        }
        else if (sLen < 0x20)
        {
            int prepend = 0x20 - sLen;
            p++;
            for (int i = 0; i < prepend; i++)
                *s++ = 0;
            memcpy(s, p, sLen);
        }

        *outputLen = 64;

        return out;
    }


    static EVP_PKEY* generate_EC_keypair_single_context()
    {
        int r;

        EVP_PKEY* key = NULL;

        OSSL_PARAM params[2];

        EVP_PKEY_CTX* ctx = NULL;

        ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", /*properties*/NULL);

        r = EVP_PKEY_keygen_init(ctx);

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)SN_secp521r1, 0);

        params[1] = OSSL_PARAM_construct_end();

        r = EVP_PKEY_CTX_set_params(ctx, params);

        r = EVP_PKEY_generate(ctx, &key);

        return key;
    }

    void ecdsa_sig_generate_and_verify_keep_DER_format()
    {
        EVP_PKEY* key_pair = generate_EC_keypair_single_context();



        OSSL_PARAM* ossl_param_pub_key = NULL;

        EVP_PKEY_todata(key_pair, EVP_PKEY_PUBLIC_KEY, &ossl_param_pub_key);


        // ================ sign ==================

        EVP_MD_CTX* digest_and_sign_ctx = EVP_MD_CTX_create();

        EVP_DigestSignInit_ex(digest_and_sign_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, key_pair, NULL/*params*/);

        EVP_DigestSignUpdate(digest_and_sign_ctx, hamlet_1, strlen(hamlet_1));

        size_t sig_len;

        EVP_DigestSignFinal(digest_and_sign_ctx, NULL, &sig_len);
        // this call sets the maximum possible sigature length to sig_len.
        // in case of P-256 curve, 'r' and 's' are both 32-byte numbers, 
        // if their most significant bit is 1, one more 0x00 needs to be prepended.
        // So the maximum possible length happens in this case:
        // 
        // 30 (sequence of)
        // 46 (length)
        // 02 (integer)
        // 21 (length)
        // 00 ......r component in 2's complement
        // 02 (integer)
        // 32 (length)
        // 00 ......s component in 2's complement
        // 
        // sig_len after this call is 72, but for this particular signature, the real length may be 71 or 70
        // the next call to DigestSignFinal will set sig_len to the real length

        byte* sig = (byte*)OPENSSL_malloc(sig_len);

        EVP_DigestSignFinal(digest_and_sign_ctx, sig, &sig_len);

        BIO_dump_indent_fp(stdout, sig, sig_len, 2);


        // ============== Verify ===============

        EVP_PKEY_CTX* pub_key_reconstructed_ctx = NULL;

        EVP_PKEY* reconstructed_pub_key = NULL;

        pub_key_reconstructed_ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pub_key_reconstructed_ctx);

        EVP_PKEY_fromdata(pub_key_reconstructed_ctx, &reconstructed_pub_key, EVP_PKEY_PUBLIC_KEY, ossl_param_pub_key);


        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_create();

        EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_pub_key, NULL/*params*/);

        EVP_DigestVerifyUpdate(verify_ctx, hamlet_1, strlen(hamlet_1));

        EVP_DigestVerifyFinal(verify_ctx, sig, sig_len);

        // ================ clean up ==================

        EVP_PKEY_free(key_pair);
        EVP_PKEY_free(reconstructed_pub_key);
        EVP_PKEY_CTX_free(pub_key_reconstructed_ctx);
        EVP_MD_CTX_free(digest_and_sign_ctx);
        EVP_MD_CTX_free(verify_ctx);
    }


    void ecdsa_sig_generate_and_verify_makeshift_convert()
    {
        EVP_PKEY* key_pair = generate_EC_keypair_single_context();



        OSSL_PARAM* ossl_param_pub_key = NULL;

        EVP_PKEY_todata(key_pair, EVP_PKEY_PUBLIC_KEY, &ossl_param_pub_key);


        // ================ sign ==================

        EVP_MD_CTX* digest_and_sign_ctx = EVP_MD_CTX_create();

        EVP_DigestSignInit_ex(digest_and_sign_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, key_pair, NULL/*params*/);

        EVP_DigestSignUpdate(digest_and_sign_ctx, hamlet_1, strlen(hamlet_1));

        size_t sig_len;

        EVP_DigestSignFinal(digest_and_sign_ctx, NULL, &sig_len);

        byte* der_encoded_sig = (byte*)OPENSSL_malloc(sig_len);

        EVP_DigestSignFinal(digest_and_sign_ctx, der_encoded_sig, &sig_len);


        // ================ conversion =================

        int raw_sig_length = 0;

        byte* raw_sig = derDecodeEcdsaSignature(der_encoded_sig, &raw_sig_length);

        int reconstructed_der_sig_len = 0;

        byte* reconstructed_der_sig = derEncodeEcdsaSignature(raw_sig, &reconstructed_der_sig_len);

        // ============== Verify ===============

        EVP_PKEY_CTX* pub_key_reconstructed_ctx = NULL;

        EVP_PKEY* reconstructed_pub_key = NULL;

        pub_key_reconstructed_ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pub_key_reconstructed_ctx);

        EVP_PKEY_fromdata(pub_key_reconstructed_ctx, &reconstructed_pub_key, EVP_PKEY_PUBLIC_KEY, ossl_param_pub_key);


        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_create();

        EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_pub_key, NULL/*params*/);

        EVP_DigestVerifyUpdate(verify_ctx, hamlet_1, strlen(hamlet_1));

        EVP_DigestVerifyFinal(verify_ctx, reconstructed_der_sig, reconstructed_der_sig_len);

        // ================ clean up ==================

        EVP_PKEY_free(key_pair);
        EVP_PKEY_free(reconstructed_pub_key);
        EVP_PKEY_CTX_free(pub_key_reconstructed_ctx);
        EVP_MD_CTX_free(digest_and_sign_ctx);
        EVP_MD_CTX_free(verify_ctx);
        free(raw_sig);
        free(reconstructed_der_sig);
    }


    void ecdsa_sig_generate_and_verify__makeshift_der2raw__openssl_raw2der()
    {
        EVP_PKEY* key_pair = generate_EC_keypair_single_context();

        OSSL_PARAM* ossl_param_pub_key = NULL;

        EVP_PKEY_todata(key_pair, EVP_PKEY_PUBLIC_KEY, &ossl_param_pub_key);


        // ================ sign ==================

        EVP_MD_CTX* digest_and_sign_ctx = EVP_MD_CTX_create();

        EVP_DigestSignInit_ex(digest_and_sign_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, key_pair, NULL/*params*/);

        EVP_DigestSignUpdate(digest_and_sign_ctx, hamlet_1, strlen(hamlet_1));

        size_t sig_len;

        EVP_DigestSignFinal(digest_and_sign_ctx, NULL, &sig_len);

        byte* der_encoded_sig = (byte*)OPENSSL_malloc(sig_len);

        EVP_DigestSignFinal(digest_and_sign_ctx, der_encoded_sig, &sig_len);

        BIO_dump_indent_fp(stdout, der_encoded_sig, sig_len, 2);

        // ================ conversion =================

        int raw_sig_length = 0;

        byte* raw_sig = derDecodeEcdsaSignature(der_encoded_sig, &raw_sig_length);

        byte* r = raw_sig;
        byte* s = raw_sig + 32;

        ECDSA_SIG* obj = NULL;
        byte* reconstructed_der_sig = NULL;
        size_t reconstructed_der_sig_len = 0;

        BIGNUM* rbn = NULL, * sbn = NULL;

        obj = ECDSA_SIG_new();

        rbn = BN_bin2bn(r, 32, NULL);
        sbn = BN_bin2bn(s, 32, NULL);

        ECDSA_SIG_set0(obj, rbn, sbn);

        rbn = sbn = NULL;

        reconstructed_der_sig_len = i2d_ECDSA_SIG(obj, &reconstructed_der_sig);

        std::cout << "\n\n";

        BIO_dump_indent_fp(stdout, reconstructed_der_sig, reconstructed_der_sig_len, 2);

        // ============== Verify ===============

        EVP_PKEY_CTX* pub_key_reconstructed_ctx = NULL;

        EVP_PKEY* reconstructed_pub_key = NULL;

        pub_key_reconstructed_ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pub_key_reconstructed_ctx);

        EVP_PKEY_fromdata(pub_key_reconstructed_ctx, &reconstructed_pub_key, EVP_PKEY_PUBLIC_KEY, ossl_param_pub_key);


        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_create();

        EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_pub_key, NULL/*params*/);

        EVP_DigestVerifyUpdate(verify_ctx, hamlet_1, strlen(hamlet_1));

        EVP_DigestVerifyFinal(verify_ctx, reconstructed_der_sig, reconstructed_der_sig_len);

        // ================ clean up ==================

        EVP_PKEY_free(key_pair);
        EVP_PKEY_free(reconstructed_pub_key);
        EVP_PKEY_CTX_free(pub_key_reconstructed_ctx);
        EVP_MD_CTX_free(digest_and_sign_ctx);
        EVP_MD_CTX_free(verify_ctx);
        free(raw_sig);
        OPENSSL_free(reconstructed_der_sig);
        ECDSA_SIG_free(obj);
    }


    void ecdsa_sig_generate_and_verify__openssl_der2raw__makeshift_raw2der()
    {
        EVP_PKEY* key_pair = generate_EC_keypair_single_context();

        OSSL_PARAM* ossl_param_pub_key = NULL;

        EVP_PKEY_todata(key_pair, EVP_PKEY_PUBLIC_KEY, &ossl_param_pub_key);


        // ================ sign ==================

        EVP_MD_CTX* digest_and_sign_ctx = EVP_MD_CTX_create();

        EVP_DigestSignInit_ex(digest_and_sign_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, key_pair, NULL/*params*/);

        EVP_DigestSignUpdate(digest_and_sign_ctx, hamlet_1, strlen(hamlet_1));

        size_t sig_len;

        EVP_DigestSignFinal(digest_and_sign_ctx, NULL, &sig_len);

        byte* der_encoded_sig = (byte*)OPENSSL_malloc(sig_len);

        EVP_DigestSignFinal(digest_and_sign_ctx, der_encoded_sig, &sig_len);

        BIO_dump_indent_fp(stdout, der_encoded_sig, sig_len, 2);

        // ================ conversion =================

        byte const* dummy = der_encoded_sig;
        ECDSA_SIG* obj = d2i_ECDSA_SIG(NULL, &dummy, sig_len);

        BIGNUM const* rbn = NULL; BIGNUM const *sbn = NULL;

        rbn = ECDSA_SIG_get0_r(obj);
        sbn = ECDSA_SIG_get0_s(obj);

        int r_len = BN_num_bytes(rbn);
        int s_len = BN_num_bytes(sbn);
        byte* r = (byte*)malloc(r_len);
        byte* s = (byte*)malloc(s_len);

        BN_bn2binpad(rbn, r, r_len);
        BN_bn2binpad(sbn, s, s_len);
        
        byte* raw_sig = (byte*)malloc(r_len + s_len);
        memcpy(raw_sig, r, r_len);
        memcpy(raw_sig + r_len, s, s_len);

        
        int reconstructed_der_sig_len = 0;

        byte* reconstructed_der_sig = derEncodeEcdsaSignature(raw_sig, &reconstructed_der_sig_len);

        std::cout << "\n\n";

        BIO_dump_indent_fp(stdout, reconstructed_der_sig, reconstructed_der_sig_len, 2);

        // ============== Verify ===============

        EVP_PKEY_CTX* pub_key_reconstructed_ctx = NULL;

        EVP_PKEY* reconstructed_pub_key = NULL;

        pub_key_reconstructed_ctx = EVP_PKEY_CTX_new_from_name(NULL/*lib context*/, "EC", NULL/*prop queue*/);

        EVP_PKEY_fromdata_init(pub_key_reconstructed_ctx);

        EVP_PKEY_fromdata(pub_key_reconstructed_ctx, &reconstructed_pub_key, EVP_PKEY_PUBLIC_KEY, ossl_param_pub_key);


        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_create();

        EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_pub_key, NULL/*params*/);

        EVP_DigestVerifyUpdate(verify_ctx, hamlet_1, strlen(hamlet_1));

        EVP_DigestVerifyFinal(verify_ctx, reconstructed_der_sig, reconstructed_der_sig_len);

        // ================ clean up ==================

        EVP_PKEY_free(key_pair);
        EVP_PKEY_free(reconstructed_pub_key);
        EVP_PKEY_CTX_free(pub_key_reconstructed_ctx);
        EVP_MD_CTX_free(digest_and_sign_ctx);
        EVP_MD_CTX_free(verify_ctx);
        free(r);
        free(s);
        free(raw_sig);
        free(reconstructed_der_sig);
        ECDSA_SIG_free(obj);
        OPENSSL_free(der_encoded_sig);
    }


    void ecdsa_signature__convert_key_to_der__openssl_convert_sig()
    {
        // 1. generate key pair 

        EVP_PKEY* key_pair = generate_EC_keypair_single_context();

        // 2. convert keys to DER array

        // 2.1 EVP_PKEY --> DER encoded public key

        OSSL_ENCODER_CTX* pub_key_encoder_ctx = NULL;

        int selection = EVP_PKEY_PUBLIC_KEY;

        char const* pub_key_x509_struct_name = "SubjectPublicKeyInfo";

        pub_key_encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(key_pair, selection, "DER", pub_key_x509_struct_name, NULL/*prop queue*/);

        byte* pub_key_der = NULL;
        size_t pub_key_der_len = 0;

        OSSL_ENCODER_to_data(pub_key_encoder_ctx, &pub_key_der, &pub_key_der_len); // 2nd argument must be NULL in order to have this function allocat memory internally

        OSSL_ENCODER_CTX_free(pub_key_encoder_ctx);

        // 2.2 EVP_PKEY --> DER encoded key pair 

        OSSL_ENCODER_CTX* key_pair_encoder_ctx = NULL;

        selection = EVP_PKEY_KEYPAIR;

        char const* key_pair_pkcs8_struct_name = "PrivateKeyInfo";

        key_pair_encoder_ctx = OSSL_ENCODER_CTX_new_for_pkey(key_pair, selection, "DER", key_pair_pkcs8_struct_name, NULL/*prop queue*/);

        byte* key_pair_der = NULL;
        size_t key_pair_der_len = 0;

        OSSL_ENCODER_to_data(key_pair_encoder_ctx, &key_pair_der, &key_pair_der_len);  // 2nd argument must be NULL in order to have this function allocat memory internally

        OSSL_ENCODER_CTX_free(key_pair_encoder_ctx);

        EVP_PKEY_free(key_pair);

        // 3. Sign

        // 3.1 DER encoded key pair --> EVP_PKEY

        EVP_PKEY* reconstructed_key_pair;
        OSSL_DECODER_CTX* key_pair_decode_ctx;
        selection = EVP_PKEY_KEYPAIR;
        key_pair_decode_ctx = OSSL_DECODER_CTX_new_for_pkey(&reconstructed_key_pair, "DER", key_pair_pkcs8_struct_name, "EC", selection, NULL/*lib context*/, NULL/*prop queue*/);
        
        byte const* dummy = key_pair_der; // OSSL_DECODER_from_data modifies the pointer pointing at the der array, keey the original pointer value in order to free the memory later
        OSSL_DECODER_from_data(key_pair_decode_ctx, &dummy, &key_pair_der_len);
        OSSL_DECODER_CTX_free(key_pair_decode_ctx);

        OPENSSL_free(key_pair_der);  


        // 3.2 get the curve order (need this for signature format conversion later)

        BIGNUM* curve_order_bn = NULL;
        EVP_PKEY_get_bn_param(reconstructed_key_pair, OSSL_PKEY_PARAM_EC_ORDER, &curve_order_bn);
        int curve_order = BN_num_bytes(curve_order_bn);

        BN_free(curve_order_bn);

        // 3.3 sign using key pair, get DER encoded signature

        EVP_MD_CTX* digest_and_sign_ctx = EVP_MD_CTX_create();

        EVP_DigestSignInit_ex(digest_and_sign_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_key_pair, NULL/*params*/);

        EVP_DigestSignUpdate(digest_and_sign_ctx, hamlet_1, strlen(hamlet_1));

        size_t sig_len;

        EVP_DigestSignFinal(digest_and_sign_ctx, NULL, &sig_len);

        byte* der_encoded_sig = (byte*)OPENSSL_malloc(sig_len);

        EVP_DigestSignFinal(digest_and_sign_ctx, der_encoded_sig, &sig_len);

        BIO_dump_indent_fp(stdout, der_encoded_sig, sig_len, 2);

        EVP_PKEY_free(reconstructed_key_pair);

        EVP_MD_CTX_free(digest_and_sign_ctx);

        // 4. signature conversion   DER ---> object of ECDSA_SIG ---> Raw

        byte const* dummy3 = der_encoded_sig;
        ECDSA_SIG* obj = d2i_ECDSA_SIG(NULL, &dummy3, sig_len);

        BIGNUM const* rbn = NULL; BIGNUM const* sbn = NULL;

        rbn = ECDSA_SIG_get0_r(obj);
        sbn = ECDSA_SIG_get0_s(obj);

        int r_len = BN_num_bytes(rbn);
        int s_len = BN_num_bytes(sbn);

        byte* raw_sig = (byte*)malloc(curve_order * 2);

        BN_bn2binpad(rbn, raw_sig, curve_order);
        BN_bn2binpad(sbn, raw_sig+curve_order, curve_order);

        ECDSA_SIG_free(obj);
        OPENSSL_free(der_encoded_sig);
        
        // 5.  verify

        // 5.1 DER encoded public key --> EVP_PKEY

        EVP_PKEY* reconstructed_pub_key;
        OSSL_DECODER_CTX* pub_key_decode_ctx;
        selection = EVP_PKEY_PUBLIC_KEY;
        pub_key_decode_ctx = OSSL_DECODER_CTX_new_for_pkey(&reconstructed_pub_key, "DER", pub_key_x509_struct_name, "EC", selection, NULL/*lib context*/, NULL/*prop queue*/);
        byte const* dummy2 = pub_key_der;
        OSSL_DECODER_from_data(pub_key_decode_ctx, &dummy2, &pub_key_der_len);
        OSSL_DECODER_CTX_free(pub_key_decode_ctx);

        // 5.2 get the curve order (need this for signature format conversion later)

        BIGNUM* curve_order_bn_2 = NULL;

        EVP_PKEY_get_bn_param(reconstructed_pub_key, OSSL_PKEY_PARAM_EC_ORDER, &curve_order_bn_2);
        int curve_order_2 = BN_num_bytes(curve_order_bn_2);
        BN_free(curve_order_bn_2);

        // 5.3 Raw --> object of ECDSA_SIG --> DER

        byte*r = raw_sig;
        byte*s = raw_sig + curve_order_2;

        byte* reconstructed_der_sig = NULL;
        size_t reconstructed_der_sig_len = 0;

        BIGNUM* reconstruct_rbn = NULL, * reconstruct_sbn = NULL;

        obj = ECDSA_SIG_new();

        reconstruct_rbn = BN_bin2bn(r, curve_order_2, NULL);
        reconstruct_sbn = BN_bin2bn(s, curve_order_2, NULL);

        ECDSA_SIG_set0(obj, reconstruct_rbn, reconstruct_sbn);

        reconstruct_rbn = reconstruct_sbn = NULL;

        reconstructed_der_sig_len = i2d_ECDSA_SIG(obj, &reconstructed_der_sig);

        std::cout << "\n\n";

        BIO_dump_indent_fp(stdout, reconstructed_der_sig, reconstructed_der_sig_len, 2);

        ECDSA_SIG_free(obj);
        free(raw_sig);

        OPENSSL_free(pub_key_der);

        // 5.4 use public key to verify

        EVP_MD_CTX* verify_ctx = EVP_MD_CTX_create();

        EVP_DigestVerifyInit_ex(verify_ctx, NULL, "SHA512", NULL/*lib context*/, NULL/*prop queue*/, reconstructed_pub_key, NULL/*params*/);

        EVP_DigestVerifyUpdate(verify_ctx, hamlet_1, strlen(hamlet_1));

        EVP_DigestVerifyFinal(verify_ctx, reconstructed_der_sig, reconstructed_der_sig_len);

        EVP_MD_CTX_free(verify_ctx);
        EVP_PKEY_free(reconstructed_pub_key);
        OPENSSL_free(reconstructed_der_sig);
    }
}