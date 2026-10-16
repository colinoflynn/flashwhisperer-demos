/* HTTPS victim: lwIP's own httpd over lwIP's own altcp_tls, on mbedTLS.
 *
 * An embedded web UI over TLS is one of the most ordinary things a
 * microcontroller does -- device configuration pages on industrial gear,
 * cameras, PLCs, gateways. Everything that runs here is vendor-shipped: ST's
 * HAL, ST's bundled lwIP (httpd, altcp_tls) and ST's bundled mbedTLS. This file
 * supplies what an application must supply: the server certificate, and the
 * content to serve.
 *
 * What the attack consumes: the TLS record protecting the response. Under a
 * CBC ciphersuite, C_i = E(K, P_i ^ C_(i-1)), so for any block of *known*
 * response bytes the attacker has the AES input and the AES output together --
 * a stronger reduction than the keystream (P ^ C) used by the OSCORE and
 * SNMPv3 demos, which give the output only.
 *
 * The response is therefore deliberately fixed and deliberately long enough to
 * span several whole AES blocks. That is not an attack aid: it is what any
 * static page is. A real device's status page is equally predictable to anyone
 * who has ever fetched it once.
 */
#include <string.h>

#include "lwip/apps/httpd.h"
#include "lwip/apps/fs.h"
#include "lwip/altcp_tls.h"
#include "lwip/stats.h"
#include "lwip/memp.h"
#include "mbedtls/memory_buffer_alloc.h"
#ifdef VICTIM_LWIP_DEBUG
#include "mbedtls/debug.h"
#endif

#include "victim_certs.h"
#include "main.h"
#include "https_server.h"

/* The served page. Fixed, and a whole number of AES blocks' worth of known
 * plaintext once the HTTP headers are included. */
static const char page_body[] =
  "<html><head><title>Device status</title></head><body>\r\n"
  "<h1>Device status</h1>\r\n"
  "<p>state: running</p>\r\n"
  "<p>uptime: nominal</p>\r\n"
  "<p>firmware: 1.0.0</p>\r\n"
  "</body></html>\r\n";

/* httpd sends file data verbatim when the data already contains the headers,
 * which is what makes the plaintext exactly predictable. Content-Length is
 * fixed because the body is. */
static const char page[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/html\r\n"
  "Content-Length: 166\r\n"
  "Connection: keep-alive\r\n"
  "\r\n"
  "<html><head><title>Device status</title></head><body>\r\n"
  "<h1>Device status</h1>\r\n"
  "<p>state: running</p>\r\n"
  "<p>uptime: nominal</p>\r\n"
  "<p>firmware: 1.0.0</p>\r\n"
  "</body></html>\r\n";

int fs_open_custom(struct fs_file *file, const char *name)
{
  LWIP_UNUSED_ARG(name);
  memset(file, 0, sizeof(*file));
  file->data  = page;
  file->len   = (int)(sizeof(page) - 1);
  file->index = file->len;
  file->flags = FS_FILE_FLAGS_HEADER_INCLUDED | FS_FILE_FLAGS_HEADER_PERSISTENT;
  return 1;
}

void fs_close_custom(struct fs_file *file)
{
  LWIP_UNUSED_ARG(file);
}

static unsigned char mbed_pool[24 * 1024];

void https_server_init(void)
{
  struct altcp_tls_config *conf;

  mbedtls_memory_buffer_alloc_init(mbed_pool, sizeof(mbed_pool));
#ifdef VICTIM_LWIP_DEBUG
  mbedtls_debug_set_threshold(3);
#endif

  conf = altcp_tls_create_config_server_privkey_cert(
           victim_privkey, sizeof(victim_privkey),
           NULL, 0,
           victim_cert, sizeof(victim_cert));
  if (conf == NULL) {
    uart_puts("TLS config FAILED\r\n");
    while (1) { }
  }
  httpd_inits(conf);
  uart_puts("https : ready on tcp/443 (lwIP httpd + altcp_tls + mbedTLS)\r\n");
  uart_puts("body  : "); uart_putdec((uint32_t)(sizeof(page_body) - 1));
  uart_puts(" bytes, response "); uart_putdec((uint32_t)(sizeof(page) - 1));
  uart_puts(" bytes\r\n");
}

/* Count of times the receive DMA was found suspended and restarted. */
uint32_t g_rx_resumes;

/* The STM32 Ethernet receive DMA *suspends itself* when it runs out of free
 * descriptors ("receive buffer unavailable"). It does not restart on its own:
 * the RBUS flag has to be cleared and a receive poll demand issued. ST's
 * ethernetif never does this, so a victim that blocks long enough to exhaust
 * the ring -- which a TLS record layer doing AES and HMAC per request easily
 * does -- goes permanently deaf, with its TCP connection still open and its
 * httpd still perfectly healthy. That is exactly the stall this demo hit:
 * httpd's own debug log ends on a completed request, with http_sent fired and
 * nothing wrong, simply never receiving again. */
static void eth_rx_watchdog(void)
{
  if (ETH->DMASR & ETH_DMASR_RBUS) {
    ETH->DMASR  = ETH_DMASR_RBUS;      /* rc_w1: clear the flag */
    ETH->DMARPDR = 0U;                 /* poll demand: resume the receive DMA */
    g_rx_resumes++;
  }
}

void https_server_poll(void)
{
  eth_rx_watchdog();

  /* Console: diagnostics only, and never inside a measured exchange. "Q"
   * reports lwIP's heap and pool usage, which is how a stack that runs out of
   * something mid-session says so. */
  int ch = uart_getchar_nb();
  if (ch < 0) { return; }
  if (ch == 'R' || ch == 'r') { NVIC_SystemReset(); }
  if (ch == 'Q' || ch == 'q') {
    uart_puts("mem used="); uart_putdec(lwip_stats.mem.used);
    uart_puts(" max="); uart_putdec(lwip_stats.mem.max);
    uart_puts(" err="); uart_putdec(lwip_stats.mem.err);
    uart_puts("\r\npbuf used="); uart_putdec(lwip_stats.memp[MEMP_PBUF_POOL]->used);
    uart_puts(" max="); uart_putdec(lwip_stats.memp[MEMP_PBUF_POOL]->max);
    uart_puts(" err="); uart_putdec(lwip_stats.memp[MEMP_PBUF_POOL]->err);
    uart_puts("\r\nip   recv="); uart_putdec(lwip_stats.ip.recv);
    uart_puts(" drop="); uart_putdec(lwip_stats.ip.drop);
    uart_puts(" chkerr="); uart_putdec(lwip_stats.ip.chkerr);
    uart_puts("\r\ntcp  recv="); uart_putdec(lwip_stats.tcp.recv);
    uart_puts(" drop="); uart_putdec(lwip_stats.tcp.drop);
    uart_puts(" err="); uart_putdec(lwip_stats.tcp.err);
    uart_puts(" xmit="); uart_putdec(lwip_stats.tcp.xmit);
    uart_puts("\r\nrx resumes="); uart_putdec(g_rx_resumes);
    uart_puts("\r\ntcp  used="); uart_putdec(lwip_stats.memp[MEMP_TCP_PCB]->used);
    uart_puts(" err="); uart_putdec(lwip_stats.memp[MEMP_TCP_PCB]->err);
    uart_puts("\r\n");
  }
}
