/* Debug-only: route lwIP's LWIP_DEBUGF to the console.
 *
 * Compiled only by `make LWIPDEBUG=1`. lwIP's default platform hook is
 *
 *     #define LWIP_PLATFORM_DIAG(x) do { printf x; } while (0)
 *
 * and printf goes nowhere here: under --specs=nosys.specs newlib has no working
 * _sbrk, so stdout never produces anything and every debug message is silently
 * dropped. That is why enabling SNMP_DEBUG and ALTCP_MBEDTLS_DEBUG earlier
 * produced an empty log and left the stall un-diagnosed.
 *
 * vsnprintf into a caller-supplied buffer needs no heap, so this works.
 */
#include <stdarg.h>
#include <stdio.h>

#include "main.h"

void lwip_diag(const char *fmt, ...)
{
  static char line[256];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  uart_puts(line);
}
