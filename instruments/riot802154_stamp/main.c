/* The instrument: a RIOT GNRC node that sends probes and timestamps the air.
 *
 * TIMER4 free-runs at 16 MHz and keeps counting while the core sleeps, which
 * the DWT cycle counter does not -- that is why the timestamp is not DWT. PPI
 * channel 18 routes RADIO->EVENTS_END straight to TIMER4->TASKS_CAPTURE[0], so
 * the instant is latched IN HARDWARE and the ISR only reads CC[0]; interrupt
 * scheduling jitter never reaches the number.
 */
#include <stdio.h>

#include "msg.h"
#include "shell.h"
#ifdef OTA_STAMP
#include "cpu.h"
#endif

static msg_t _main_queue[8];

int main(void)
{
    msg_init_queue(_main_queue, 8);
#ifdef OTA_STAMP
    /* TIMER4 runs at 16 MHz while the core sleeps between radio interrupts. */
    NRF_TIMER4->TASKS_STOP = 1;
    NRF_TIMER4->MODE = TIMER_MODE_MODE_Timer;
    NRF_TIMER4->BITMODE = TIMER_BITMODE_BITMODE_32Bit;
    NRF_TIMER4->PRESCALER = 0;
    NRF_TIMER4->TASKS_CLEAR = 1;
    NRF_TIMER4->TASKS_START = 1;
    /* Hardware-latch the exact radio END instant before ISR scheduling jitter. */
    NRF_PPI->CH[18].EEP = (uint32_t)&NRF_RADIO->EVENTS_END;
    NRF_PPI->CH[18].TEP = (uint32_t)&NRF_TIMER4->TASKS_CAPTURE[0];
    NRF_PPI->CHENSET = 1U << 18;
#endif
    puts("RIOT 802.15.4 OTA echo endpoint");
    puts("Use `ifconfig` to inspect the interface and `ping` for probes.");
    char line[SHELL_DEFAULT_BUFSIZE];
    shell_run(NULL, line, sizeof(line));
    return 0;
}
