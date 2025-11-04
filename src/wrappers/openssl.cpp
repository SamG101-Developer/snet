module;
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

export module openssl;


export namespace openssl {
    using SSL = ::SSL;
    using SSL_CTX = ::SSL_CTX;
    using X509 = ::X509;
    using EVP_PKEY = ::EVP_PKEY;
    using EVP_CIPHER_CTX = ::EVP_CIPHER_CTX;
    using EVP_MD_CTX = ::EVP_MD_CTX;
    using BIO = ::BIO;
    using OSSL_PARAM = ::OSSL_PARAM;

    using ::X509_free;
    using ::X509_new;
    using ::X509_set_version;
    using ::X509_get_serialNumber;
    using ::X509_gmtime_adj;
    using ::X509_set_pubkey;
    using ::X509_getm_notBefore;
    using ::X509_getm_notAfter;
    using ::X509_get_issuer_name;
    using ::X509_NAME_add_entry_by_txt;
    using ::X509_set_subject_name;
    using ::X509_sign;
    using ::X509_verify;
    using ::X509_get_subject_name;
    using ::X509_NAME_get_index_by_NID;
    using ::X509_NAME_get_entry;
    using ::X509_NAME_ENTRY_get_data;
    using ::X509_get_pubkey;
    using ::i2d_X509;
    using ::d2i_X509;
    using ::d2i_AutoPrivateKey;
    using ::EVP_PKEY_get_raw_private_key;
    using ::EVP_PKEY_get_raw_public_key;
    using ::EVP_PKEY_new_raw_private_key_ex;
    using ::EVP_PKEY_new_raw_public_key_ex;

#undef MBSTRING_UTF8
    auto MBSTRING_UTF8 = MBSTRING_FLAG;
#undef MBSTRING_ASC
    auto MBSTRING_ASC = MBSTRING_FLAG | 1;

    using ::ASN1_INTEGER_set;
    using ::ASN1_STRING_length;
    using ::ASN1_STRING_get0_data;

    using ::OSSL_PARAM_construct_octet_string;
    using ::OSSL_PARAM_construct_int64;
    using ::OSSL_PARAM_construct_end;
    using ::OSSL_PARAM_locate;
    using ::OSSL_PARAM_get_int64;

    using ::EVP_PKEY_new;
    using ::EVP_PKEY_free;
    using ::EVP_PKEY_Q_keygen;
    using ::EVP_PKEY_CTX_new_from_pkey;

    using ::EVP_SIGNATURE_fetch;
    using ::EVP_PKEY_sign_message_init;
    using ::EVP_PKEY_sign;
    using ::EVP_SIGNATURE_free;
    using ::EVP_PKEY_CTX_free;

    using ::EVP_MD_CTX_new;
    using ::EVP_MD_get_size;

    using ::EVP_DigestInit_ex;
    using ::EVP_DigestUpdate;
    using ::EVP_DigestFinal_ex;
    using ::EVP_MD_CTX_free;

    using ::EVP_sha3_256;

    using ::EVP_PKEY_verify_message_init;
    using ::EVP_PKEY_verify;

    using ::EVP_PKEY_encapsulate_init;
    using ::EVP_PKEY_encapsulate;
    using ::EVP_PKEY_decapsulate_init;
    using ::EVP_PKEY_decapsulate;

    using ::EVP_CIPHER_CTX_new;
    using ::EVP_EncryptInit_ex;
    using ::EVP_EncryptUpdate;
    using ::EVP_EncryptFinal_ex;
    using ::EVP_CIPHER_CTX_ctrl;
    using ::EVP_CIPHER_CTX_set_key_length;
    using ::EVP_DecryptInit_ex;
    using ::EVP_DecryptUpdate;
    using ::EVP_DecryptFinal_ex;
    using ::EVP_CIPHER_CTX_free;

    using ::EVP_aes_256_ocb;
#undef EVP_CTRL_AEAD_SET_IVLEN
    auto EVP_CTRL_AEAD_SET_IVLEN = 0x9;
#undef EVP_CTRL_AEAD_GET_TAG
    auto EVP_CTRL_AEAD_GET_TAG = 0x10;
#undef EVP_CTRL_AEAD_SET_TAG
    auto EVP_CTRL_AEAD_SET_TAG = 0x11;

    using ::CRYPTO_memcmp;

    using ::i2d_PUBKEY;
    using ::i2d_PrivateKey;
    using ::d2i_PUBKEY;
    using ::d2i_PrivateKey;
    using ::OBJ_ln2nid;

    using ::RAND_priv_bytes;
    using ::RAND_bytes;

    auto OpenSSL_add_all_algorithms = [] { ::OPENSSL_add_all_algorithms_noconf(); };
    auto SSL_load_error_strings = [] { ::SSL_load_error_strings(); };
    auto SSL_library_init = [] { ::SSL_library_init(); };
    using ::CRYPTO_secure_malloc_init;
    using ::CRYPTO_secure_malloc_done;
    using ::OPENSSL_cleanse;
    auto OPENSSL_secure_free = [](void *ptr) { ::OPENSSL_secure_free(ptr); };

    auto OPENSSL_secure_malloc = [](const int num) { return ::CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE); };
}
