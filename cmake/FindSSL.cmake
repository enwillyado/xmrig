find_path(
    OPENSSL_INCLUDE_DIR
    NAMES openssl.h
    PATHS "${XMRIG_DEPS}" ENV "XMRIG_DEPS"
    PATH_SUFFIXES "include"
    NO_DEFAULT_PATH
)

find_path(OPENSSL_INCLUDE_DIR NAMES openssl.h)

find_library(
    OPENSSL_LIBRARY
    NAMES libssl.a openssl libssl
    PATHS "${XMRIG_DEPS}" ENV "XMRIG_DEPS"
    PATH_SUFFIXES "lib"
    NO_DEFAULT_PATH
)

find_library(OPENSSL_LIBRARY NAMES livopenssl.a openssl libssl)

find_library(
    CRYPTO_LIBRARY
    NAMES libcrypto.a crypto libcrypto
    PATHS "${XMRIG_DEPS}" ENV "XMRIG_DEPS"
    PATH_SUFFIXES "lib"
    NO_DEFAULT_PATH
)

find_library(CRYPTO_LIBRARY NAMES livopenssl.a openssl libssl)

set(OPENSSL_LIBRARIES ${OPENSSL_LIBRARY} ${CRYPTO_LIBRARY})
set(OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OPENSSL_INCLUDE_DIR DEFAULT_MSG OPENSSL_LIBRARY CRYPTO_LIBRARY OPENSSL_INCLUDE_DIR)
