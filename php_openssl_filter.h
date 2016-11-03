#ifndef PHP_OPENSSL_FILTER_H
#define PHP_OPENSSL_FILTER_H

extern php_stream_filter_factory php_openssl_filter_factory;

PHP_MINIT_FUNCTION(openssl_filter);
PHP_MSHUTDOWN_FUNCTION(openssl_filter);
PHP_MINFO_FUNCTION(openssl_filter);

#endif
