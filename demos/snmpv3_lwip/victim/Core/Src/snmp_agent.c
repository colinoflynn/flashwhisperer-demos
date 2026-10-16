/* SNMPv3 victim: lwIP's own SNMP agent, configured the ordinary way.
 *
 * Nothing here is an attack aid. The agent, its MIB-2 implementation, the v3
 * User Security Model and the mbedTLS crypto backend are all upstream lwIP and
 * mbedTLS sources compiled as they ship. This file supplies exactly what lwIP
 * documents an application must supply: the engine identity and the user
 * database (snmpv3.h -- "the following callback functions must be implemented
 * by the application").
 *
 * The security posture is the standard one: authPriv, HMAC-SHA-1 for
 * authentication and AES-128-CFB128 for privacy (RFC 3826). Both keys are
 * *localized* from passphrases against the engine ID exactly as RFC 3414 s2.6
 * specifies, using lwIP's own snmpv3_password_to_key_sha(). That is what makes
 * the privacy key a device-lifetime secret: it changes only when someone
 * changes the passphrase.
 *
 * What leaks is the response encryption. CFB128 keystream block n is
 * E(K, IV) for n = 1 and E(K, C_{n-1}) after that, and the IV is
 * engineBoots || engineTime || privParam -- all three sent in the clear in
 * every response -- so an observer reconstructs the AES input exactly, and
 * recovers the AES output as P ^ C wherever it knows the plaintext. Response
 * plaintext is ASN.1 BER over standard MIB-2 scalars, which is predictable.
 */
#include <string.h>

#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_mib2.h"
#include "lwip/apps/snmpv3.h"
#include "lwip/sys.h"

#include "main.h"
#include "snmp_agent.h"

#define NEWLINE "\r\n"

/* The engine ID. RFC 3411 format: enterprise number with the high bit set,
 * then a format byte and the identifier. Fixed at manufacture in real devices,
 * which is the point -- key localization is bound to it. */
static const char engine_id[] = "\x80\x00\x1f\x88\x80\x5f\x2d\x4f\x60";
static u32_t engine_boots = 1;

/* The one configured user. Passphrases, not keys: the agent localizes them. */
#define SNMP_USER      "victim"
#define SNMP_AUTH_PASS "authpassword"
#define SNMP_PRIV_PASS "privpassword"

/* ------------------------------------------------------------------ v3 --- */

void snmpv3_get_engine_id(const char **id, u8_t *len)
{
  *id  = engine_id;
  *len = (u8_t)(sizeof(engine_id) - 1);
}

err_t snmpv3_set_engine_id(const char *id, u8_t len)
{
  LWIP_UNUSED_ARG(id);
  LWIP_UNUSED_ARG(len);
  return ERR_OK;            /* fixed identity: accept and ignore */
}

u32_t snmpv3_get_engine_boots(void)
{
  return engine_boots;
}

void snmpv3_set_engine_boots(u32_t boots)
{
  engine_boots = boots;
}

u32_t snmpv3_get_engine_time(void)
{
  return sys_now() / 1000;
}

void snmpv3_reset_engine_time(void)
{
}

u8_t snmpv3_get_amount_of_users(void)
{
  return 1;
}

err_t snmpv3_get_username(char *username, u8_t index)
{
  if (index != 0) {
    return ERR_VAL;
  }
  strcpy(username, SNMP_USER);
  return ERR_OK;
}

err_t snmpv3_get_user_storagetype(const char *username,
                                  snmpv3_user_storagetype_t *storagetype)
{
  if (strcmp(username, SNMP_USER) != 0) {
    return ERR_VAL;
  }
  *storagetype = SNMP_V3_USER_STORAGETYPE_READONLY;
  return ERR_OK;
}

/* The localized keys, derived once.
 *
 * RFC 3414 s2.6 localization hashes a megabyte of the repeated passphrase, so
 * doing it per request costs a fifth of a second on this part -- measured: the
 * first working build answered in over 200 ms and the SHA-1 completely swamped
 * the cipher. Real agents localize once when the user is configured and keep
 * the result, which is both what RFC 3414 describes and what makes the
 * response time reflect the AES. */
static u8_t auth_key_cached[20];
static u8_t priv_key_cached[20];
static u8_t keys_ready;

static void derive_keys(void)
{
  const char *eid;
  u8_t eid_len;

  if (keys_ready) {
    return;
  }
  snmpv3_get_engine_id(&eid, &eid_len);
  snmpv3_password_to_key_sha((const u8_t *)SNMP_AUTH_PASS, strlen(SNMP_AUTH_PASS),
                             (const u8_t *)eid, eid_len, auth_key_cached);
  snmpv3_password_to_key_sha((const u8_t *)SNMP_PRIV_PASS, strlen(SNMP_PRIV_PASS),
                             (const u8_t *)eid, eid_len, priv_key_cached);
  keys_ready = 1;
}

err_t snmpv3_get_user(const char *username,
                      snmpv3_auth_algo_t *auth_algo, u8_t *auth_key,
                      snmpv3_priv_algo_t *priv_algo, u8_t *priv_key)
{
  if (strcmp(username, SNMP_USER) != 0) {
    return ERR_VAL;
  }
  derive_keys();

  if (auth_algo != NULL) {
    *auth_algo = SNMP_V3_AUTH_ALGO_SHA;
  }
  if (auth_key != NULL) {
    MEMCPY(auth_key, auth_key_cached, sizeof(auth_key_cached));
  }
  if (priv_algo != NULL) {
    *priv_algo = SNMP_V3_PRIV_ALGO_AES;
  }
  if (priv_key != NULL) {
    MEMCPY(priv_key, priv_key_cached, 16);
  }
  return ERR_OK;
}

/* ------------------------------------------------------------- agent --- */

void snmp_agent_init(void)
{
  static const struct snmp_mib *mibs[] = { &mib2 };

  snmp_mib2_set_sysdescr((const u8_t *)"lwIP SNMPv3 victim", NULL);
  snmp_mib2_set_syscontact_readonly((const u8_t *)"none", NULL);
  snmp_mib2_set_sysname_readonly((const u8_t *)"victim", NULL);
  snmp_mib2_set_syslocation_readonly((const u8_t *)"bench", NULL);

  derive_keys();               /* once, at configuration time */
  snmp_set_mibs(mibs, LWIP_ARRAYSIZE(mibs));
  snmp_init();
}

static void kv(const char *name, u32_t v)
{
  uart_puts(name); uart_puts("="); uart_putdec(v); uart_puts(" ");
}

void snmp_agent_poll(void)
{
  /* lwIP's SNMP agent is driven by the raw UDP callback, so there is nothing to
   * pump. What lives here is the console, which is diagnostics only and never
   * runs inside a measured exchange: the attacker is idle whenever a key is
   * pressed. "Q" dumps lwIP's own SNMP counters, which is how a rejected
   * request says *why* it was rejected. */
  int ch = uart_getchar_nb();
  if (ch < 0) { return; }
  if (ch == 'R' || ch == 'r') { NVIC_SystemReset(); }
  if (ch == 'Q' || ch == 'q')
  {
    uart_puts("snmp: ");
    kv("in", snmp_stats.inpkts);
    kv("out", snmp_stats.outpkts);
    kv("asnparse", snmp_stats.inasnparseerrs);
    kv("badver", snmp_stats.inbadversions);
    uart_puts(NEWLINE "v3 : ");
    kv("unsupseclevel", snmp_stats.unsupportedseclevels);
    kv("notintimewin", snmp_stats.notintimewindows);
    kv("unknownuser", snmp_stats.unknownusernames);
    kv("unknowneid", snmp_stats.unknownengineids);
    kv("wrongdigest", snmp_stats.wrongdigests);
    kv("decrypterr", snmp_stats.decryptionerrors);
    uart_puts(NEWLINE);
  }
}
