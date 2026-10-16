/* mbedTLS configuration for the HTTPS victim.
 *
 * A TLS 1.2 server with an RSA certificate. The one deliberate narrowing is the
 * ciphersuite list: only AES-128-CBC-SHA256 is enabled, so the session key is
 * AES-128 and the record layer is CBC. That is a realistic choice (it is what a
 * constrained device pins to keep the build small) and it makes the reduction
 * exact -- under CBC the attacker gets the AES input and output together.
 *
 * MBEDTLS_AES_ROM_TABLES is deliberately NOT set here, matching mbedTLS's own
 * shipped config.h: the default computes the AES tables into RAM and this
 * attack cannot see them. The Makefile's ROMTABLES=1 defines it instead, which
 * is the RAM-saving build real MCU projects use. See ../../snmpv3/README.md.
 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* Platform: no filesystem, no OS, no time. */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
/* Give mbedTLS its own fixed pool instead of newlib malloc. This is the
 * ordinary MCU configuration -- a bare-metal build usually has no real heap
 * -- and it makes allocation behaviour observable and bounded rather than
 * dependent on sbrk and fragmentation. */
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_DEPRECATED_REMOVED

/* Symmetric: the cipher under test, and the MAC. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C

/* Asymmetric, for the handshake only. */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_ASN1_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* X.509 for the server certificate. */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* RNG. There is no entropy source on this board, so the seed is supplied by
 * the application -- see https_server.c. A real product uses its RNG
 * peripheral; nothing about the timing channel depends on this. */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* TLS 1.2 server, one ciphersuite. */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_MAX_CONTENT_LEN 2048
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_SSL_CIPHERSUITES  MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256

#define MBEDTLS_ERROR_C

/* Debug build only. altcp_tls installs mbedTLS's debug callback whenever
 * ALTCP_MBEDTLS_DEBUG is on, but mbedTLS only *calls* it when MBEDTLS_DEBUG_C
 * is compiled in and a threshold is set -- without both, every record-layer
 * error is invisible. altcp_tls itself logs only CLOSE_NOTIFY and CONN_RESET
 * and silently swallows everything else, so this hook is the only way to see
 * why a session dies. */
#ifdef VICTIM_LWIP_DEBUG
#define MBEDTLS_DEBUG_C
#endif

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
