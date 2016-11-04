#include "php.h"
#include "php_openssl_filter.h"
#include <openssl/evp.h>

#if COMPILE_DL_OPENSSL_FILTER
ZEND_GET_MODULE(openssl_filter)
#endif

#define XSTR(s) STR(s)
#define STR(s) #s
#define PHP_OPENSSL_FILTER_ASSIGN_PARAM_STR_LEN(_param_name, _len_param_name) \
    do { \
        zval *tmpzval; \
        if ((tmpzval = zend_hash_str_find(Z_ARRVAL_P(filter_params), ZEND_STRL(XSTR(_param_name))))) { \
            if (Z_TYPE_P(tmpzval) == IS_STRING) { \
                _param_name = Z_STRVAL_P(tmpzval); \
                _len_param_name = Z_STRLEN_P(tmpzval); \
            } else {
                php_error_docref(NULL, E_WARNING, "Parameter " XSTR(_param_name) " must be string, ignoring"); \
            } \
        } \
    } while (0)
#define PHP_OPENSSL_FILTER_ASSIGN_PARAM_LONG_NATURAL(_param_name) \
    do { \
        zval *tmpzval; \
        if ((tmpzval = zend_hash_str_find(Z_ARRVAL_P(filter_params), ZEND_STRL(XSTR(_param_name))))) { \
            if (Z_TYPE_P(tmpzval) == IS_LONG && Z_LVAL_P(tmpzval) >= 0) { \
                _param_name = Z_STRVAL_P(tmpzval); \
            } else {
                php_error_docref(NULL, E_WARNING, "Parameter " XSTR(_param_name) " must be non-negative integer, ignoring"); \
            } \
        } \
    } while (0)

typedef struct _php_openssl_filter_data {
    EVP_CIPHER_CTX ctx;
    char persistent;
    char is_aead;
    int aead_get_tag_flag;
    int aead_set_tag_flag;
    int aead_ivlen_flag;
} php_openssl_filter_data;

static php_stream_filter_status_t php_openssl_filter(
    php_stream *stream,
    php_stream_filter *filter,
    php_stream_bucket_brigade *buckets_in,
    php_stream_bucket_brigade *buckets_out,
    size_t *bytes_consumed,
    int flags
    )
{
    php_openssl_filter_data *data;
    php_stream_filter_status_t exit_status = PSFS_FEED_ME;
    size_t consumed = 0;
    php_stream_bucket *src_bucket, *dst_bucket;
    char *src_buf, *dst_buf;
    int src_len, dst_len;

    if (!filter || !Z_PTR(filter->abstract)) {
        return PSFS_ERR_FATAL;
    }

    data = (php_openssl_filter_data *)(Z_PTR(filter->abstract));

    while (buckets_in->head) {
        src_bucket = buckets_in->head;
        src_buf = src_bucket->buf;
        src_len = src_bucket->buflen;
        dst_buf = pemalloc(src_len + data->ctx->key_len - 1, data->persistent);

        if (data->ctx->encrypt) {
            EVP_EncryptUpdate(&data->ctx, (unsigned char *)dst_buf, &dst_len, (unsigned char *)src_buf, src_len);
        } else {
            EVP_DecryptUpdate(&data->ctx, (unsigned char *)dst_buf, &dst_len, (unsigned char *)src_buf, src_len);
        }

        dst_bucket = php_stream_bucket_new(stream, dst_buf, dst_len, 1, data->persistent);
        php_stream_bucket_append(buckets_out, dst_bucket);

        consumed += src_len;
        php_stream_bucket_unlink(src_bucket);
        php_stream_bucket_delref(src_bucket);

        exit_status = PSFS_PASS_ON;
    }

    if (flags & PSFS_FLAG_FLUSH_CLOSE) {
        dst_buf = pemalloc(data->ctx->key_len, data->persistent);

        if (data->ctx->encrypt) {
            EVP_EncryptFinal_ex(&data->ctx, (unsigned char *)dst_buf, &dst_len);
        } else {
            EVP_DecryptFinal_ex(&data->ctx, (unsigned char *)dst_buf, &dst_len);
        }

        dst_bucket = php_stream_bucket_new(stream, dst_buf, dst_len, 1, data->persistent);
        php_stream_bucket_append(buckets_out, dst_bucket);

        exit_status = PSFS_PASS_ON;
    }

    if (bytes_consumed) {
        *bytes_consumed = consumed;
    }

    return exit_status;
}

static void php_openssl_filter_dtor(php_stream_filter *filter)
{
    if (!filter || !Z_PTR(filter->abstract)) {
        return;
    }
    php_openssl_filter_data *data = (php_openssl_filter_data *) Z_PTR(filter->abstract);
    EVP_CIPHER_CTX_cleanup(&data->ctx);
    pefree(data, data->persistent);
}

static php_stream_filter_ops php_openssl_filter_ops = {
    php_openssl_filter,
    php_openssl_filter_dtor,
    "openssl.*"
};

static php_stream_filter *php_openssl_filter_create(const char *filter_name, zval *filter_params, uint8_t persistent)
{
    const char encrypt;
    const EVP_CIPHER *cipher_type;

    char *password = NULL, *iv = NULL, *aad = NULL, *tag = NULL;
    size_t password_len = 0, iv_len = 0, aad_len = 0, tag_len = 16;

    php_openssl_filter_data *data;

    cipher_type = EVP_get_cipherbyname(filter_name + sizeof("openssl_**crypt.") - 1);
    if (!cipher_type) {
        php_error_docref(NULL, E_WARNING, "Unknown cipher algorithm");
        return NULL;
    }
    if (filter_params) {
        if (Z_TYPE_P(filter_params) != IS_ARRAY) {
            php_error_docref(NULL, E_WARNING, "Filter parameters for %s must be an array, ignoring", filter_name);
        } else {
            PHP_OPENSSL_FILTER_ASSIGN_PARAM_STR_LEN(password, password_len);
            PHP_OPENSSL_FILTER_ASSIGN_PARAM_STR_LEN(iv, iv_len);
            PHP_OPENSSL_FILTER_ASSIGN_PARAM_STR_LEN(aad, aad_len);
            PHP_OPENSSL_FILTER_ASSIGN_PARAM_LONG_NATURAL(tag);
            PHP_OPENSSL_FILTER_ASSIGN_PARAM_LONG_NATURAL(tag);
        }
    }

    encrypt = filter_name[sizeof("openssl_") - 1] == 'e';
    data = pemalloc(sizeof(php_openssl_filter_data), persistent);

    switch (EVP_CIPHER_mode(cipher_type)) {
#ifdef EVP_CIPH_GCM_MODE
        case EVP_CIPH_GCM_MODE:
            data->is_aead = 1;
            data->aead_get_tag_flag = EVP_CTRL_GCM_GET_TAG;
            data->aead_set_tag_flag = EVP_CTRL_GCM_SET_TAG;
            data->aead_ivlen_flag = EVP_CTRL_GCM_SET_IVLEN;
            break;
#endif
#ifdef EVP_CIPH_CCM_MODE
        case EVP_CIPH_CCM_MODE:
            php_error_docref(NULL, E_WARNING, "Currently CCM mode is unsupported");
            return NULL;
#endif
        default:
            memset(mode, 0, sizeof(struct php_openssl_cipher_mode));
    }

    EVP_CIPHER_CTX_init(ctx);
    if (encrypt) {
        EVP_EncryptInit_ex(ctx,method,NULL,(unsigned char *)key, iv);
    } else {
        EVP_DecryptInit_ex(ctx,method,NULL,(unsigned char *)key,iv);
    }

    data = pemalloc(sizeof(php_openssl_filter_data, persistent));
}

static php_stream_filter_factory php_openssl_filter_factory = {
    php_openssl_filter_create
};

PHP_MINIT_FUNCTION(openssl_filter)
{
    php_stream_filter_register_factory("openssl.encrypt.*", &php_openssl_filter_factory);
    php_stream_filter_register_factory("openssl.decrypt.*", &php_openssl_filter_factory);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(openssl_filter)
{
    php_stream_filter_unregister_factory("openssl.encrypt.*", &php_openssl_filter_factory);
    php_stream_filter_unregister_factory("openssl.decrypt.*", &php_openssl_filter_factory);
    return SUCCESS;
}
