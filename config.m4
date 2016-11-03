PHP_ARG_WITH(openssl-filter, for openssl stream filter support,
[  --with-openssl-filter[=DIR]      Include openssl stream filter support])

if test "$PHP_OPENSSL_FILTER" != "no"; then
  PHP_NEW_EXTENSION(openssl_filter, openssl_filter.c, $ext_shared)
fi
