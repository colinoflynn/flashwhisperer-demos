/* Debug-only: route newlib printf (and so lwIP's LWIP_DEBUGF) to the console.
 *
 * Compiled only by `make LWIPDEBUG=1`. lwIP already reports every failure in
 * snmp_msg.c's outbound builder through LWIP_DEBUGF(SNMP_DEBUG, ...); the
 * default platform hook is printf, which under --specs=nosys.specs goes
 * nowhere. Supplying _write is enough to read lwIP's own diagnosis without
 * patching a single line of it.
 */
#include <sys/types.h>
#include "main.h"

int _write(int fd, const char *buf, int len)
{
  int i;
  (void)fd;
  for (i = 0; i < len; i++) {
    char c[2] = { buf[i], 0 };
    if (buf[i] == '\n') { uart_puts("\r"); }
    uart_puts(c);
  }
  return len;
}
