#include "php.h"
#include "php_openssl_filter.h"
#include <openssl/evp.h>

#if COMPILE_DL_OPENSSL_FILTER
ZEND_GET_MODULE(openssl_filter)
#endif

typedef struct _php_openssl_filter_data {
    EVP_CIPHER_CTX ctx;
    char persistent;
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

static php_stream_filter *php_openssl_filter_create(const char *filtername, zval *filterparams, uint8_t persistent)
{
    EVP_CIPHER_CTX *ctx;
    const char encrypt;
    char *data, *method, *password, *iv = "", *add = "";
    size_t data_len, method_len, password_len, iv_len = 0, aad_len = 0;
    const EVP_CIPHER *cipher_type;
    EVP_CIPHER_CTX *cipher_ctx;
    zval *tmpzval;

    if (!filterparams || Z_TYPE_P(filterparams) != IS_ARRAY) {
        php_error_docref(NULL, E_WARNING, "Filter parameters for %s must be an array", filtername);
        return NULL;
    }

    if ((tmpzval = zend_hash_str_find(Z_ARRVAL_P(filterparams), ZEND_STRL("mode")))) {
        if (Z_TYPE_P(tmpzval) == IS_STRING) {
            mode = Z_STRVAL_P(tmpzval);
        } else {
            php_error_docref(NULL, E_WARNING, "mode is not a string, ignoring");
        }
    }


    EVP_CIPHER_CTX_init(ctx);
    if (encrypt) {
        EVP_EncryptInit_ex(ctx,method,NULL,(unsigned char *)key, iv);
    } else {
        EVP_DecryptInit_ex(ctx,method,NULL,(unsigned char *)key,iv);
    }
    encrypt = filtername[8] == 'e';
    php_openssl_filter_data *data;

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
