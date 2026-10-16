/* mbedTLS configuration for the SNMPv3 victim.
 *
 * Only what lwIP's snmpv3_mbedtls.c actually calls: AES through the generic
 * cipher layer (AES-128-CFB128 is SNMPv3's privacy algorithm, RFC 3826) and
 * MD5/SHA1 through the message-digest layer (RFC 3414 key localization).
 *
 * MBEDTLS_AES_ROM_TABLES is deliberately NOT set here. It is commented out in
 * mbedTLS's own shipped config.h too, so this file matches the upstream default
 * and the AES tables are computed into RAM at startup. The Makefile's
 * ROMTABLES=1 defines it on the command line instead, which is the realistic
 * MCU build that puts them back in flash.
 */
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CFB
/* lwIP's backend calls mbedtls_cipher_set_padding_mode() unconditionally,
 * which the cipher layer only compiles with a padded mode present. */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C

/* No filesystem, no network, no RNG on this target -- the SNMPv3 backend needs
 * none of them. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_PLATFORM_C

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
