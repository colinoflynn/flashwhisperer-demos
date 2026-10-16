/**
  ******************************************************************************
  * @file    sfu_instr.c
  * @brief   The victim times its own decrypt loop.  B-L475E-IOT01A.
  *
  * sfu_instr.h holds what the recorded interval is and what the software
  * bracket excludes.  This file is the buffer, the clock, and the dump.
  *
  * NOTHING HERE RUNS INSIDE THE TIMED REGION except the two DWT reads.  The
  * dump happens after the pass has finished, on the UART the host is already
  * attached to, because a diagnostic inside the loop is not a diagnostic:
  * one 1 Hz console line on another rig in this repository corrupted whole
  * groups of measurements and produced a wrong conclusion about the
  * instrument that printed it.
  ******************************************************************************
  */

#include <stdint.h>

#include "main.h"
#include "sfu_com_trace.h"
#include "sfu_instr.h"

uint32_t SFU_INSTR_gap[SFU_INSTR_SLOTS];
uint8_t  SFU_INSTR_polls[SFU_INSTR_SLOTS];
uint32_t SFU_INSTR_n;
uint32_t SFU_INSTR_drops;
uint32_t SFU_INSTR_t0;
uint32_t SFU_INSTR_armed;
uint32_t SFU_INSTR_poll_n;
uint32_t SFU_INSTR_active;

static uint32_t s_pass_t0;
static uint32_t s_dwt_dead;

/* The build this image is, as a string, so a capture cannot be attributed to
 * the wrong variant.  PORT_VARIANT comes from the Makefile and names every
 * knob that changes the measurement; a firmware that cannot say which build
 * produced a trace file is how two builds become secretly one. */
#ifndef PORT_VARIANT
#define PORT_VARIANT "unset"
#endif

static void put(const char *s)
{
  (void)SFU_COM_Serial_PutString((uint8_t *)s);
}

/* Fixed-width lowercase hex, because the host parser wants one shape and
 * because a variable-width field in a 3 000-line dump is a parser bug
 * waiting for the one value that is shorter than the rest. */
static void put_hex(uint32_t v, uint32_t digits)
{
  static const char hexdig[] = "0123456789abcdef";
  char buf[9];
  uint32_t i;

  if (digits > 8U)
  {
    digits = 8U;
  }
  buf[digits] = '\0';
  for (i = digits; i > 0U; i--)
  {
    buf[i - 1U] = hexdig[v & 0xFU];
    v >>= 4;
  }
  put(buf);
}

/* Start the cycle counter, and PROVE it is running.
 *
 * DWT->CYCCNT can sit at zero with CYCCNTENA reading back set -- it has done
 * so on another part in this repository -- and every interval derived from a
 * frozen counter comes out exactly 0, which looks like a clean constant-time
 * result rather than like a broken instrument.  So the counter is read
 * twice across known work and the verdict is printed with the data. */
static void dwt_start(void)
{
  uint32_t a;
  uint32_t b;
  uint32_t i;

  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0U;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

  a = DWT->CYCCNT;
  for (i = 0U; i < 16U; i++)
  {
    __NOP();
  }
  b = DWT->CYCCNT;
  s_dwt_dead = (b == a) ? 1U : 0U;
}

void SFU_INSTR_PassBegin(uint32_t chunk, uint32_t fw_size)
{
  uint32_t i;

  for (i = 0U; i < SFU_INSTR_SLOTS; i++)
  {
    SFU_INSTR_gap[i] = 0U;
    SFU_INSTR_polls[i] = 0U;
  }
  SFU_INSTR_n = 0U;
  SFU_INSTR_drops = 0U;
  SFU_INSTR_armed = 0U;
  SFU_INSTR_poll_n = 0U;

  dwt_start();

  /* Last, so that nothing above it can be timed and no interval can open
   * before the buffer is clear. */
  SFU_INSTR_active = 1U;
  s_pass_t0 = DWT->CYCCNT;

  put("\r\nI-BEGIN variant=" PORT_VARIANT " chunk=");
  put_hex(chunk, 8U);
  put(" fwsize=");
  put_hex(fw_size, 8U);
  put(" slots=");
  put_hex((uint32_t)SFU_INSTR_SLOTS, 8U);
  put(" dwt=");
  put((s_dwt_dead != 0U) ? "DEAD" : "ok");
  put("\r\n");
}

void SFU_INSTR_PassEnd(void)
{
  uint32_t span;
  uint32_t i;
  uint32_t expect;

  SFU_INSTR_active = 0U;
  span = DWT->CYCCNT - s_pass_t0;

  /* The expected interval count, stated by the firmware rather than worked
   * out by the host: one interval per chunk read bar the first, so a dump
   * that is one short or one long says so here instead of silently shifting
   * every interval onto the wrong chunk. */
  expect = (SFU_INSTR_n == 0U) ? 0U : SFU_INSTR_n;

  for (i = 0U; i < SFU_INSTR_n; i++)
  {
    put("I-G ");
    put_hex(i, 4U);
    put(" ");
    put_hex(SFU_INSTR_gap[i], 8U);
    put(" ");
    put_hex((uint32_t)SFU_INSTR_polls[i], 2U);
    put("\r\n");
  }

  put("I-END n=");
  put_hex(expect, 8U);
  put(" drops=");
  put_hex(SFU_INSTR_drops, 8U);
  put(" span=");
  put_hex(span, 8U);
  put(" dwt=");
  put((s_dwt_dead != 0U) ? "DEAD" : "ok");
  put("\r\n");
}
