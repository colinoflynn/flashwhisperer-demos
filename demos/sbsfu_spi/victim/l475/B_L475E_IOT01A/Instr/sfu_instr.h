/**
  ******************************************************************************
  * @file    sfu_instr.h
  * @brief   The victim times its own decrypt loop.  B-L475E-IOT01A.
  *
  * WHAT THIS MEASURES, AND WHY IT IS NOT THE SAME THING THE OTHER TWO PORTS
  * MEASURE
  * ----------------------------------------------------------------------------
  * On the SAM D21 and L152 rigs the observable is on the wire: chip-select
  * rise of chunk k's data read to chip-select fall of chunk k+1's status
  * poll, timed by a NUCLEO-F303RE clipped to the chip-select line
  * (results/bootloader_spi/PROTOCOL.md section 3).  Both delimiters are
  * edges the victim's own C produces, because on those boards chip-select is
  * a plain GPIO.
  *
  * ON THIS BOARD IT IS NOT.  The MX25R6435F sits on the QUADSPI peripheral,
  * so nCS is driven by the IP per command and the driver never writes it.
  * The envelope is still one per read and still visible to an attacker with
  * a probe, but the victim cannot produce the edge itself -- which is why
  * this rig starts from the other side and has the victim time the gap in
  * software:
  *
  *     SFU_INSTR_GapStart()   immediately after BSP_QSPI_Read() returns
  *     SFU_INSTR_GapEnd()     immediately before the next chunk's status
  *                            poll issues its command
  *
  * so one recorded interval spans one SE_Decrypt_Append (AES-128-CBC
  * decrypt of the chunk) plus one SE_AuthenticateFW_Append (SHA-256 update)
  * plus the fixed driver and dispatch overhead -- the same content as the
  * bus-side interval.
  *
  * WHAT THE SOFTWARE BRACKET EXCLUDES, which is the whole caveat of a
  * self-reported interval: an endpoint cannot report what happens after it
  * stops its own clock.
  *
  *   head  the QSPI IP raises nCS before HAL_QSPI_Receive returns, so the
  *         real interval starts EARLIER than GapStart by the HAL's
  *         wait-for-complete and clean-up path.
  *   tail  GapEnd fires before BSP_QSPI_GetStatus writes the command
  *         register, so the real interval ends LATER than GapEnd by the
  *         HAL's command setup plus the IP's own nCS assertion.
  *
  * Both are fixed instruction sequences with no dependence on the chunk's
  * contents, so they add a CONSTANT to every interval -- which a collision
  * attack scoring differences between intervals does not see.  That makes
  * this instrument an upper bound on what a bus-side attacker gets, not a
  * different attack: strictly less noise, the same signal, and therefore the
  * cheapest way to find out whether a probe on this board is worth wiring
  * up at all.  It is NOT a substitute for the bus-side capture, because the
  * claim "an attacker outside the package can do this" needs the outside
  * measurement.
  *
  * The host side is rigs/host/sbsfu_instr.py, which parses the dump below.
  ******************************************************************************
  */

#ifndef SFU_INSTR_H
#define SFU_INSTR_H

#include <stdint.h>

/* How many intervals one pass can record.  A 44 KB body at ST's shipped
 * 512-byte chunk is 88 of them; the same body at chunk 16 is 2 816, which is
 * the case this default has to cover.  Overflow is COUNTED AND REPORTED
 * rather than wrapped, because a silently wrapped buffer would attribute
 * every interval to the wrong block -- and getting the stream's phase wrong
 * is the failure that dates a capture to the wrong chunk
 * (results/bootloader_spi/samd21/README.md on the spare read). */
#ifndef SFU_INSTR_SLOTS
#define SFU_INSTR_SLOTS 3072U
#endif

extern uint32_t SFU_INSTR_gap[SFU_INSTR_SLOTS];
extern uint8_t  SFU_INSTR_polls[SFU_INSTR_SLOTS];
extern uint32_t SFU_INSTR_n;        /* intervals recorded */
extern uint32_t SFU_INSTR_drops;    /* intervals lost to a full buffer */
extern uint32_t SFU_INSTR_t0;       /* DWT at the last GapStart */
extern uint32_t SFU_INSTR_armed;    /* 0 until the first GapStart of a pass */
extern uint32_t SFU_INSTR_poll_n;   /* busy-poll retries in the current gap */
extern uint32_t SFU_INSTR_active;   /* 1 between PassBegin and PassEnd */

void SFU_INSTR_PassBegin(uint32_t chunk, uint32_t fw_size);
void SFU_INSTR_PassEnd(void);

/* Stop the clock as the read returns.  Deliberately tiny and deliberately
 * static inline: a call here would be a constant cost, but the point of
 * putting it in a header is that the patch to ST's Target/ file is one line
 * and reads as one. */
static inline void SFU_INSTR_GapStart(void)
{
  if (SFU_INSTR_active != 0U)
  {
    SFU_INSTR_poll_n = 0U;
    SFU_INSTR_armed = 1U;
    SFU_INSTR_t0 = DWT->CYCCNT;
  }
}

/* Count one turn of ST's `while (BSP_QSPI_GetStatus() != QSPI_OK)` BODY,
 * which runs only when the memory reported itself busy.
 *
 * So the normal value is ZERO: one status envelope, memory ready, straight
 * into the read.  An interval whose count is not zero contains a WHOLE
 * EXTRA chip-select envelope -- tens of microseconds against a signal a
 * cycle or two wide.  Recording the count per interval is what lets the
 * host drop those rather than average them in; the SAM D21 campaign found
 * its 64-byte SHA-256 phases the same way, by keeping the structure instead
 * of pooling it. */
static inline void SFU_INSTR_PollAgain(void)
{
  if (SFU_INSTR_poll_n < 255U)
  {
    SFU_INSTR_poll_n++;
  }
}

static inline void SFU_INSTR_GapEnd(void)
{
  uint32_t dt;

  if ((SFU_INSTR_active == 0U) || (SFU_INSTR_armed == 0U))
  {
    /* The first read of a pass has no predecessor, so there is no interval
     * to close.  This is also what keeps the stream's phase right: interval
     * k follows chunk k, and a capture whose first interval were credited to
     * chunk 0 would be off by one for its whole length. */
    return;
  }
  dt = DWT->CYCCNT - SFU_INSTR_t0;   /* unsigned wrap is the correct answer */
  if (SFU_INSTR_n < SFU_INSTR_SLOTS)
  {
    SFU_INSTR_gap[SFU_INSTR_n] = dt;
    SFU_INSTR_polls[SFU_INSTR_n] = (uint8_t)SFU_INSTR_poll_n;
    SFU_INSTR_n++;
  }
  else
  {
    SFU_INSTR_drops++;
  }
  SFU_INSTR_armed = 0U;
}

#endif /* SFU_INSTR_H */
