#include <crypto.h>

unsigned char *gen_hmac(unsigned char *key, int key_len, unsigned char *data, int data_len) {

    unsigned char *result;
    if (HASH_SIZE == 32)
        result = HMAC(EVP_sha256(), key, key_len, data, data_len, NULL, NULL);
    else
        result = HMAC(EVP_sha512(), key, key_len, data, data_len, NULL, NULL);


    if (DEBUG) {
        printf("\nMAC Input Key: ");
        for (int i = 0; i < key_len; i++)
            printf("%02x", key[i]);

        printf("\nMAC Input Msg: ");
        for (int i = 0; i < data_len; i++)
            printf("%02x", data[i]);

        printf("\nMAC Computed: ");
        for (int i = 0; i < HASH_SIZE; i++)
            printf("%02x", result[i]);
    }

    return result;

}


unsigned char *derive_hkdf_key(unsigned char *key, int key_len) {

    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char *derived = malloc(HASH_SIZE);
    OSSL_PARAM params[5], *p = params;

    /* Find and allocate a context for the HKDF algorithm */
    if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
        error("EVP_KDF_fetch");
    }
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);    /* The kctx keeps a reference so this is safe */
    if (kctx == NULL) {
        error("EVP_KDF_CTX_new");
    }

    /* Build up the parameters for the derivation */
    if (HASH_SIZE == 32)
        *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha256", (size_t) 7);
    else
        *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha512", (size_t) 7);
    *p++ = OSSL_PARAM_construct_octet_string("salt", "salt", (size_t) 4);
    *p++ = OSSL_PARAM_construct_octet_string("key", key, (size_t) key_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", "dnssec", (size_t) 6);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        error("EVP_KDF_CTX_set_params");
    }

    /* Do the derivation */
    if (EVP_KDF_derive(kctx, derived, HASH_SIZE, NULL) <= 0) {
        error("EVP_KDF_derive");
    }

    if (DEBUG) {
        printf("\nKDF Input Key: ");
        for (int i = 0; i < key_len; i++)
            printf("%02x", key[i]);

        printf("\nKDF Derived Key: ");
        for (size_t i = 0; i < HASH_SIZE; ++i)
            printf("%02x", derived[i]);
    }

    EVP_KDF_CTX_free(kctx);

    return derived;

}