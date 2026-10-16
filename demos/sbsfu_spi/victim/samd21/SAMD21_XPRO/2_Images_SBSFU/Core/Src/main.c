/**
  ******************************************************************************
  * @file    main.c
  * @brief   SBSFU entry point, SAM D21 Xplained Pro.
  *
  * ST's main.c for the B-L475E-IOT01A is HAL_Init(), SystemClock_Config(),
  * then SFU_BOOT_RunSecureBootService().  This is the same three steps with
  * this part's clock configuration, and the comments below are ST's own
  * reasoning kept because it is still correct: everything before
  * SFU_BOOT_RunSecureBootService() runs with no security applied, and the
  * bootloader is what turns protections on.
  ******************************************************************************
  */
#include "main.h"
#include "sfu_boot.h"
#include "sfu_low_level.h"
#include "sfu_low_level_flash.h"
#include "sfu_low_level_security.h"
#include "sfu_fwimg_services.h"
#include "sfu_fwimg_regions.h"
#include "sfu_fwimg_internal.h"
#include "sfu_com_trace.h"
#include "samd21_xpro_spif.h"
#include "se_interface_bootloader.h"
#include <stdio.h>
#include "mbedtls/cipher.h"

/* ------------------------------------------------------------- pre-flight --
 * SFU_BOOT_Init() calls six initialisers in a row and returns a single
 * SFU_ERROR for any of them, and its banner TRACE comes AFTER the last one --
 * so on this port the first failing stage produced no output at all, just a
 * board rebooting every 600 ms.
 *
 * This runs the same initialisers first and names each result.  They are
 * idempotent init functions, so SFU_BOOT_Init re-running them costs nothing;
 * what it buys is knowing WHICH one fails before ST's trace exists.
 *
 * It is kept rather than deleted after the bring-up, because every future
 * board this port is moved to will fail one of exactly these six first.
 */
static void uart_str(const char *s)
{
  uint16_t n = 0U;

  while (s[n] != '\0')
  {
    n++;
  }
  (void)HAL_UART_Transmit((const uint8_t *)s, n, 1000U);
}

static void uart_u32(uint32_t v)
{
  static const char hex[] = "0123456789ABCDEF";
  char b[11];
  int i;

  b[0] = '0';
  b[1] = 'x';
  for (i = 0; i < 8; i++)
  {
    b[2 + i] = hex[(v >> (28 - 4 * i)) & 0xFU];
  }
  b[10] = '\0';
  uart_str(b);
}

static void step(const char *name, uint32_t status, uint32_t good)
{
  uart_str("\r\n[PORT]   ");
  uart_str(name);
  uart_str(" -> ");
  uart_u32(status);
  uart_str((status == good) ? "  ok" : "  FAIL");
}

static void port_preflight(void)
{
  uart_str("\r\n[PORT] pre-flight, the six SFU_BOOT_Init stages:");
  step("SFU_LL_Init            ", (uint32_t)SFU_LL_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_LL_FLASH_Init      ", (uint32_t)SFU_LL_FLASH_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_COM_Init           ", (uint32_t)SFU_COM_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_IMG_InitImageHandling", (uint32_t)SFU_IMG_InitImageHandling(),
       (uint32_t)SFU_IMG_INIT_OK);
  /* SE_Init is the first thing SFU_BOOT_Init does AFTER printing ST's
   * banner, so it is the one failure the banner does not help with -- and it
   * is the first call to cross the Secure Engine's absolute-address call
   * gate, which is the most port-specific thing in this entire build. */
  {
    SE_StatusTypeDef se_status = SE_KO;
    SE_ErrorStatus r = SE_Init(&se_status, SystemCoreClock);

    step("SE_Init                ", (uint32_t)r, (uint32_t)SE_SUCCESS);
    uart_str("   SE status=");
    uart_u32((uint32_t)se_status);
  }

  /* The two protection calls SFU_BOOT_SM_InstallNewUserFw makes BEFORE it
   * reaches SFU_IMG_TriggerImageInstallation.  Either failing sends the
   * state machine to SFU_STATE_HANDLE_CRITICAL_FAILURE, which prints
   * "Security issue : execution stopped !" and says nothing about which of
   * them it was -- and on this port the answer was neither obvious nor the
   * one guessed first. */
  step("CheckApplyStaticProt   ",
       (uint32_t)SFU_LL_SECU_CheckApplyStaticProtections(),
       (uint32_t)SFU_SUCCESS);
  step("CheckApplyRuntimeProt  ",
       (uint32_t)SFU_LL_SECU_CheckApplyRuntimeProtections(SFU_SECOND_CONFIGURATION),
       (uint32_t)SFU_SUCCESS);
  uart_str("   NVMCTRL.LOCK=");
  uart_u32(NVMCTRL->LOCK.reg);

  /* The five mbedTLS calls SE_CRYPTO_Decrypt_Init makes, run here one at a
   * time.
   *
   * ST's version sums their return codes into one `ret` and reports a single
   * SE_ERROR, so a failure there says "decryption could not be initialised"
   * and nothing else -- and with the decrypt loop never entered, the bus
   * shows zero reads and the trace says "Fw signature check error", which
   * points at the wrong thing entirely.  Running the same sequence with the
   * codes kept apart says which call, and mbedTLS's codes are specific. */
  {
    static const uint8_t k[16] = {0};
    static const uint8_t iv[16] = {0};
    mbedtls_cipher_context_t c;
    const mbedtls_cipher_info_t *info;
    int rc;

    mbedtls_cipher_init(&c);
    info = mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, 128,
                                           MBEDTLS_MODE_CBC);
    uart_str("\r\n[PORT]   cipher_info_from_values -> ");
    uart_u32((uint32_t)(uintptr_t)info);
    uart_str((info != NULL) ? "  ok" : "  NULL (AES-128-CBC not in the table)");

    rc = mbedtls_cipher_setup(&c, info);
    step("mbedtls_cipher_setup   ", (uint32_t)rc, 0U);
    rc = mbedtls_cipher_setkey(&c, k, 128, MBEDTLS_DECRYPT);
    step("mbedtls_cipher_setkey  ", (uint32_t)rc, 0U);
    rc = mbedtls_cipher_set_iv(&c, iv, 16);
    step("mbedtls_cipher_set_iv  ", (uint32_t)rc, 0U);
    rc = mbedtls_cipher_set_padding_mode(&c, MBEDTLS_PADDING_NONE);
    step("cipher_set_padding_none", (uint32_t)rc, 0U);
    rc = mbedtls_cipher_reset(&c);
    step("mbedtls_cipher_reset   ", (uint32_t)rc, 0U);
    mbedtls_cipher_free(&c);
  }
  uart_str("\r\n");
}

#ifdef PORT_DIRECT_INSTALL
/* Run ST's install path directly, without the state machine.
 *
 * WHY THIS EXISTS.  The oracle this whole demo is built to measure is the
 * loop inside VerifyFwSignatureBeforeDecrypt: read a chunk from the serial
 * flash, SE_Decrypt_Append it, hash it, repeat.  That loop is reached from
 * SFU_IMG_TriggerImageInstallation, which is public API.
 *
 * SBSFU's state machine currently stops before it with "Security issue :
 * execution stopped !", and chasing that through the machine is a separate
 * problem from measuring the cipher.  Calling the installer directly runs
 * the SAME ST code over the SAME image in the SAME serial flash, so the bus
 * traffic is the product's, not a mock-up of it.
 *
 * WHAT IT IS NOT.  It is not the shipped boot flow, and a measurement taken
 * through it must say so: the state machine's checks around the install are
 * skipped.  It is enabled only by -DPORT_DIRECT_INSTALL so it cannot end up
 * in a build that claims to be stock.
 *
 * ONE SHOT PER UPLOAD.  ST's installer erases the download slot when the
 * install fails (SFU_IMG_TriggerImageInstallation's tail), so each attempt
 * consumes the staged image and the next pass needs a fresh upload.
 */
static void port_direct_install(void)
{
  uint32_t reads_before = g_spif_reads;
  uint32_t polls_before = g_spif_status_polls;
  SFU_ErrorStatus r;

  /* CheckPendingInstallation FIRST.  TriggerImageInstallation's own comment
   * says fw_image_header_to_test "is already populated after
   * SFU_IMG_CheckPendingInstallation() call" -- it is a static that an
   * earlier state fills in.  Calling the installer without it leaves FwSize
   * at zero, so the decrypt loop's bound
   *     fw_index < FwSize + SFU_IMG_IMAGE_OFFSET
   * is false on the very first test, the loop body never runs, the bus sees
   * ZERO reads, and the tag check then reports "Fw signature check error" --
   * which points squarely at the crypto and has nothing to do with it. */
  {
    uint32_t dwl = 0U, resume = 0U, rollback = 0U;
    SFU_IMG_ImgInstallStateTypeDef st =
      SFU_IMG_CheckPendingInstallation(&dwl, &resume, &rollback);

    uart_str("\r\n[PORT] CheckPendingInstallation -> state ");
    uart_u32((uint32_t)st);
    uart_str("  dwl slot ");
    uart_u32(dwl);
  }

  /* THE PROBES BELOW ARE NOT FREE.  SE_Decrypt_Init and
   * SE_AuthenticateFW_Init put the Secure Engine into a running
   * decrypt/hash session, and nothing here calls the matching Finish.
   * ST's VerifyFwSignatureBeforeDecrypt then calls SE_Decrypt_Init AGAIN
   * on a context that is already live -- so running these diagnostics can
   * itself be why the thing they diagnose fails.  A measurement tool that
   * perturbs its subject has to be switchable, so this one is.  Build with
   * -DPORT_SE_PROBE to enable it. */
#ifdef PORT_SE_PROBE
  /* The two Secure Engine calls VerifyFwSignatureBeforeDecrypt makes before
   * its loop.  If either fails, the loop's guard
   *     (e_ret_status == SFU_SUCCESS) && (se_ret_status == SE_SUCCESS)
   * is false immediately, the bus sees no reads, and the only symptom is
   * "Fw signature check error" at the end.  ST reports one SE_ERROR for
   * both; run apart, they say which -- and with the real header, not a
   * synthetic one, because the header is an input to both. */
  {
    static SE_FwRawHeaderTypeDef hdr;
    SE_StatusTypeDef ses = SE_KO;
    SE_ErrorStatus e;

    if (SFU_LL_FLASH_Read((uint8_t *)&hdr, (uint8_t *)SlotStartAdd[SLOT_DWL_1],
                          sizeof(hdr)) == SFU_SUCCESS)
    {
      uart_str("\r\n[PORT] dwl header: magic=");
      uart_u32(((uint32_t)hdr.SFUMagic[0] << 24) | ((uint32_t)hdr.SFUMagic[1] << 16)
               | ((uint32_t)hdr.SFUMagic[2] << 8) | hdr.SFUMagic[3]);
      uart_str(" FwSize=");
      uart_u32(hdr.FwSize);
      uart_str(" FwVersion=");
      uart_u32((uint32_t)hdr.FwVersion);

      e = SE_Decrypt_Init(&ses, &hdr, SE_FW_IMAGE_COMPLETE);
      step("SE_Decrypt_Init        ", (uint32_t)e, (uint32_t)SE_SUCCESS);
      uart_str("   se_status=");
      uart_u32((uint32_t)ses);

      ses = SE_KO;
      e = SE_AuthenticateFW_Init(&ses, &hdr, SE_FW_IMAGE_COMPLETE);
      step("SE_AuthenticateFW_Init ", (uint32_t)e, (uint32_t)SE_SUCCESS);
      uart_str("   se_status=");
      uart_u32((uint32_t)ses);
      uart_str("\r\n");
    }
  }

  /* ONE ITERATION OF ST'S DECRYPT LOOP, run here.
   *
   * sfu_fwimg_no_swap.c's VerifyFwSignatureBeforeDecrypt is static, so it
   * cannot be called or broken into from outside.  Its body is six lines:
   * read a chunk with SFU_LL_FLASH_Read, SE_Decrypt_Append it,
   * SE_AuthenticateFW_Append the plaintext, advance.  Running exactly those
   * calls, in that order, with the same buffers and the same chunk size,
   * says whether the loop body works -- which is the question ST's single
   * SFU_ERROR does not answer.
   *
   * It is the same ST code either way: the flash driver, the Secure Engine
   * and the cipher are all ST's.  What is reproduced here is the four-call
   * sequence around them. */
  {
    static uint8_t enc[SFU_IMG_CHUNK_SIZE] __attribute__((aligned(8)));
    static uint8_t dec[SFU_IMG_CHUNK_SIZE] __attribute__((aligned(8)));
    static uint8_t aut[SFU_IMG_CHUNK_SIZE] __attribute__((aligned(8)));
    SE_StatusTypeDef ses = SE_KO;
    int32_t n_dec = (int32_t)SFU_IMG_CHUNK_SIZE;
    int32_t n_aut = (int32_t)SFU_IMG_CHUNK_SIZE;
    SFU_ErrorStatus fr;
    SE_ErrorStatus e;
    uint32_t before = g_spif_reads;

    fr = SFU_LL_FLASH_Read(enc,
                           (uint8_t *)(SlotStartAdd[SLOT_DWL_1] + SFU_IMG_IMAGE_OFFSET),
                           SFU_IMG_CHUNK_SIZE);
    step("SFU_LL_FLASH_Read chunk", (uint32_t)fr, (uint32_t)SFU_SUCCESS);
    uart_str("   reads+=");
    uart_u32(g_spif_reads - before);

    e = SE_Decrypt_Append(&ses, enc, (int32_t)SFU_IMG_CHUNK_SIZE, dec, &n_dec);
    step("SE_Decrypt_Append      ", (uint32_t)e, (uint32_t)SE_SUCCESS);
    uart_str("   out=");
    uart_u32((uint32_t)n_dec);

    e = SE_AuthenticateFW_Append(&ses, dec, (int32_t)SFU_IMG_CHUNK_SIZE, aut, &n_aut);
    step("SE_AuthenticateFW_Appnd", (uint32_t)e, (uint32_t)SE_SUCCESS);
    uart_str("\r\n");
  }

#endif /* PORT_SE_PROBE */

#ifdef PORT_ORACLE
  /* HANDSHAKE BEFORE THE PASS.
   *
   * The bus-side timer has a fixed-size buffer, and the YMODEM upload that
   * just finished wrote the whole image through the same chip select, so a
   * timer armed before the upload is full of the upload.  It has to be
   * armed in the gap between the upload and the install, and that gap is
   * otherwise a few microseconds wide.
   *
   * So the board stops here and says so.  The host arms the timer while
   * the board waits, then sends 'G'.  Nothing is timed across this wait:
   * it ends before SFU_IMG_TriggerImageInstallation is called, so the
   * first chip select of the pass is the first edge the timer sees.
   *
   * The prompt is a whole line with a distinctive tag because the host
   * matches on it.  Matching on a bare character is what made the YMODEM
   * sender once begin transferring into the middle of the words "System
   * Security Check".
   */
  {
    uint8_t ch = 0U;

    uart_str("\r\n[PORT] ORACLE1 ready -- arm the timer, then send G\r\n");
    do
    {
      (void)HAL_UART_Receive(&ch, 1U, HAL_MAX_DELAY);
    } while (ch != (uint8_t)'G');
    uart_str("[PORT] ORACLE1 go\r\n");
  }
#endif /* PORT_ORACLE */

  uart_str("\r\n[PORT] calling SFU_IMG_TriggerImageInstallation(SLOT_DWL_1)"
           " directly ...\r\n");
  r = SFU_IMG_TriggerImageInstallation(SLOT_DWL_1);
  uart_str("[PORT]   returned ");
  uart_u32((uint32_t)r);
  uart_str((r == SFU_SUCCESS) ? "  SUCCESS" : "  ERROR");
  uart_str("\r\n[PORT]   data reads during install = ");
  uart_u32(g_spif_reads - reads_before);
  uart_str("\r\n[PORT]   total bytes read          = ");
  uart_u32(g_spif_read_bytes);
#ifdef PORT_ORACLE
  /* The control from rigs/fw_f303_spitimer/WIRING.md section 5.  The bus
   * side counts chip-select envelopes; the target side counts driver
   * calls.  They are independent measurements of the same events, and a
   * capture where they disagree has lost edges or gained them -- which a
   * plausible-looking histogram of envelope widths will not tell you. */
  uart_str("\r\n[PORT] ORACLE1 done reads=");
  uart_u32(g_spif_reads - reads_before);
  uart_str(" polls=");
  uart_u32(g_spif_status_polls - polls_before);
  uart_str(" chunk=");
  uart_u32((uint32_t)SFU_IMG_CHUNK_SIZE);
#endif /* PORT_ORACLE */
  uart_str("\r\n");
}
#endif /* PORT_DIRECT_INSTALL */

int main(void)
{
  /* MCU configuration -------------------------------------------------------
   * This part is NOT secure -- no security mechanism is enabled yet.
   *
   * Order matters and is not ST's: HAL_ClockInit() must precede HAL_Init(),
   * because HAL_Init() programs SysTick's reload from SAMD21_CPU_HZ and would
   * otherwise size a 1 ms tick against a 1 MHz reset clock that is about to
   * become 48 MHz.  Every YMODEM timeout in the loader is derived from that
   * tick, so the failure would be a loader that times out 48x too early --
   * which reads as a broken serial link, not as a clock bug.
   */
  HAL_ClockInit();
  HAL_Init();

  /* A banner from the PORT's main(), before SBSFU's own trace exists.
   *
   * This is not decoration.  SBSFU brings its trace up inside
   * SFU_BOOT_RunSecureBootService(), so anything that goes wrong before that
   * point is silent -- and the first boot of this port was exactly that: a
   * hang in HAL_WDT_Init with no output, indistinguishable from a UART that
   * did not work.  Printing here separates "the image did not start" from
   * "the image started and stopped before SBSFU did".
   *
   * The watchdog state goes out with it, because HAL_WDT_Init is allowed to
   * give up (see its bounded waits) and a watchdog that silently failed to
   * arm is a protection the device does not have. */
  HAL_UART_Init(115200U);

  /* Unbuffer stdout.  newlib line-buffers by default, and SBSFU's TRACE
   * messages mostly do not end in a newline -- ST's own strings start with
   * "
" instead.  Buffered, the last thing the bootloader says before a
   * reset is the thing that never gets flushed, which is precisely the
   * message you need. */
  (void)setvbuf(stdout, NULL, _IONBF, 0);
  {
    static const char banner[] = "\r\n[PORT] SAMD21 SBSFU alive, clock up\r\n";

    (void)HAL_UART_Transmit((const uint8_t *)banner,
                            (uint16_t)(sizeof(banner) - 1U), 1000U);
  }
  /* Report a fault carried over from the PREVIOUS boot, then clear it.  The
   * record is in .noinit so it survives the reset the fault caused -- which
   * is the whole point, because a fault that reboots the part is exactly the
   * one a debugger cannot catch.  A 32-bit magic distinguishes it from
   * uninitialised SRAM on a cold start. */
  {
    extern volatile uint32_t g_fault[4];

    if (g_fault[0] == 0xFA017000UL)
    {
      uart_str("\r\n[PORT] *** FAULT on the previous boot: IPSR=");
      uart_u32(g_fault[1]);
      uart_str(" PC=");
      uart_u32(g_fault[2]);
      uart_str(" LR=");
      uart_u32(g_fault[3]);
      uart_str("\r\n");
      g_fault[0] = 0U;
    }
  }
  /* The PREVIOUS boot's bus traffic.  This is the target-side half of the
   * envelope count that rigs/fw_f303_spitimer/WIRING.md section 5 requires
   * before a capture is trusted -- a verify pass over S bytes at chunk K
   * must produce exactly ceil(S/K) data envelopes, and the F303's edge count
   * has to agree with this number.
   *
   * It also answers the question that comes first: whether
   * VerifyFwSignatureBeforeDecrypt ran at all.  SBSFU's trace says an
   * install failed; it does not say how far it got. */
  uart_str("\r\n[PORT] previous boot SPI traffic:");
  uart_str("\r\n[PORT]   data reads   = "); uart_u32(g_spif_reads);
  uart_str("\r\n[PORT]   bytes read   = "); uart_u32(g_spif_read_bytes);
  uart_str("\r\n[PORT]   status polls = "); uart_u32(g_spif_status_polls);
  uart_str("\r\n[PORT]   page writes  = "); uart_u32(g_spif_writes);
  uart_str("\r\n[PORT]   erases       = "); uart_u32(g_spif_erases);
  uart_str("\r\n[PORT]   read reject  = "); uart_u32(g_spif_reject);
  uart_str(" addr="); uart_u32(g_spif_reject_addr);
  uart_str(" size="); uart_u32(g_spif_reject_size);
  uart_str("\r\n");
  g_spif_reads = 0U;
  g_spif_read_bytes = 0U;
  g_spif_status_polls = 0U;
  g_spif_writes = 0U;
  g_spif_erases = 0U;

  uart_str("\r\n[PORT] watchdog status (0 = armed): ");
  uart_u32((uint32_t)HAL_WDT_Status());
  port_preflight();
#ifdef PORT_DIRECT_INSTALL
  port_direct_install();
#endif

  /* Board configuration -----------------------------------------------------
   * As the secure mode has not been entered yet, the BSP is not configured
   * here.  The bootloader configures it.  (ST's comment, and still true: the
   * serial flash is brought up by SFU_LL_FLASH_Init inside the boot service.)
   */

  /* Launch the bootloader ---------------------------------------------------
   * This is the beginning of the secure part.  The function below should not
   * return unless a critical failure is encountered.
   */
  {
    SFU_BOOT_InitErrorTypeDef e = SFU_BOOT_RunSecureBootService();

    /* Reaching here at all means a critical init failure, and ST's return
     * code says WHICH stage -- SE_Startup, the security IP configuration, or
     * SFU_BOOT_Init.  ST discards it (`(void)`), because on their board the
     * trace is already up by then and prints the reason.  Here the failure
     * can happen before SBSFU's trace exists, so the code is reported
     * directly.  Without this the only symptom is a board that reboots every
     * 600 ms and says nothing. */
    /* Order is sfu_boot.h's enum, not alphabetical:
       0 SECENG_INIT_FAIL, 1 SECIPS_CFG_FAIL, 2 INIT_FAIL, 3 INIT_ERROR. */
    static const char *const why[] = {
      "SECENG_INIT_FAIL (SE_Startup)",
      "SECIPS_CFG_FAIL (security IP config)",
      "INIT_FAIL (SFU_BOOT_Init)",
      "INIT_ERROR (unspecified)"
    };
    static const char pfx[] = "\r\n[PORT] secure boot service returned: ";
    const char *msg = ((uint32_t)e < 4U) ? why[(uint32_t)e] : "unknown";

    (void)HAL_UART_Transmit((const uint8_t *)pfx, (uint16_t)(sizeof(pfx) - 1U),
                            1000U);
    {
      uint16_t n = 0U;
      while (msg[n] != '\0')
      {
        n++;
      }
      (void)HAL_UART_Transmit((const uint8_t *)msg, n, 1000U);
    }
    {
      static const char nl[] = "\r\n";
      (void)HAL_UART_Transmit((const uint8_t *)nl, 2U, 1000U);
    }
    HAL_Delay(300U);
  }

  /* Security or SecureBoot initialisation failure.  Force a system reset. */
  SFU_BOOT_ForceReboot();

  return 0;
}
