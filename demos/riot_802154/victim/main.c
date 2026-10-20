/*
 * A stock RIOT GNRC node. The shell is here so the capture host can read the
 * interface's link-local address and its EUI-64; nothing in this file touches
 * the cipher, the radio or the clock.
 *
 * The whole victim is this file, the Makefile beside it, and a generated
 * one-line key header. Everything that does the work -- 802.15.4 link
 * security, AES-CCM*, the software AES with its Te0 table in flash -- is
 * RIOT's own, at the pin the Makefile asserts.
 */
#include <stdio.h>

#include "msg.h"
#include "shell.h"

#define MAIN_QUEUE_SIZE (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void)
{
    /* gnrc_netif puts the netif's events here; without a queue the first
     * burst of replies is dropped rather than answered. */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("riot_802154_echo: stock RIOT GNRC, ieee802154_security enabled");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
