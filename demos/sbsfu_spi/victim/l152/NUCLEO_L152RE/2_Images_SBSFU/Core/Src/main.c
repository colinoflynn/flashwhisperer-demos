/**
  ******************************************************************************
  * @file    main.c
  * @brief   SBSFU entry point, NUCLEO-L152RE.
  *
  * ST's main() is four calls: HAL_Init, SystemClock_Config, then
  * SFU_BOOT_RunSecureBootService, which does not return.  That shape is
  * kept exactly.  What this file adds is bracketed by -D switches so a
  * build that claims to be stock cannot contain any of it:
  *
  *   PORT_DIRECT_INSTALL   call ST's installer directly, bypassing the
  *                         boot state machine
  *   PORT_SE_PROBE         run one decrypt through ST's Secure Engine API
  *                         before the install, as a control for it
  *   PORT_ORACLE           stop and say so before the install, so the
  *                         bus-side timer can be armed in the gap
  *
  * With none of them defined this file compiles to ST's main() plus the
  * fault report, which earns its place on any build: a Secure Engine
  * security reset is deliberate and silent, and without the report a board
  * that rejects a pointer is indistinguishable from one that crashed.
  ******************************************************************************
  */
#include "main.h"
#include "sfu_boot.h"
#include "sfu_low_level.h"
#include "sfu_fwimg_services.h"
#ifdef PORT_DIRECT_INSTALL
/* Only the direct-install path needs these, and only it should pull them
 * in: sfu_fwimg_internal.h is SBSFU's private header and sfu_fwimg_regions.h
 * instantiates the slot tables.  A stock build has no business with
 * either. */
#include "sfu_fwimg_regions.h"
#include "sfu_fwimg_internal.h"
#include "sfu_low_level_flash.h"
#include "sfu_low_level_security.h"
#include "sfu_com_trace.h"
#endif /* PORT_DIRECT_INSTALL */
#include "l152_nucleo_spif.h"
#include "se_interface_bootloader.h"
#include "mapping_export.h"

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);

/* ------------------------------------------------------- fault reporting -- */

/* Written by se_low_level.c's security reset and by the fault handlers in
 * stm32l1xx_it.c, read here on the next boot.  `.noinit` so it survives the
 * reset that recorded it -- which is the whole point. */
__attribute__((section(".noinit"))) volatile uint32_t g_fault[4];

/* A minimal UART path for this file's own output.
 *
 * It goes through SFU_LL_UART_Transmit rather than printf, so the port
 * hooks below use the SAME serial path SBSFU's own trace uses and cannot
 * disagree with it about baud rate, pins or buffering.  No newlib, and
 * nothing that allocates. */
static void uart_str(const char *s)
{
  const char *p = s;
  uint16_t n = 0U;

  while (*p != '\0')
  {
    p++;
    n++;
  }
  (void)SFU_LL_UART_Transmit((uint8_t *)s, n, 1000U);
}

static void uart_u32(uint32_t v)
{
  static const char H[] = "0123456789abcdef";
  char buf[11];
  int i;

  buf[0] = '0';
  buf[1] = 'x';
  for (i = 0; i < 8; i++)
  {
    buf[2 + i] = H[(v >> (28 - 4 * i)) & 0xFU];
  }
  buf[10] = '\0';
  uart_str(buf);
}

/* Exported for the tracked patch on ST's se_callgate.c.
 *
 * The call gate's guards do not return an error when they fail, they call
 * NVIC_SystemReset -- ST's comment says that is mandatory, "to avoid any
 * attempt of attack by modifying the call stack (LR)".  It is the right
 * call for a product and it is opaque during bring-up: a guard that fires
 * is indistinguishable from a watchdog, and prints nothing.
 *
 * patches/0002 adds a line before each guard that says which one is about
 * to be tested and with what.  It is a bring-up switch, never on for a
 * capture: it prints inside the SE entry path. */
void PORT_Trace(const char *tag, uint32_t a, uint32_t b);
void PORT_Trace(const char *tag, uint32_t a, uint32_t b)
{
  uart_str("\r\n[GATE] ");
  uart_str(tag);
  uart_str(" ");
  uart_u32(a);
  uart_str(" ");
  uart_u32(b);
  uart_str("\r\n");
}

static void report_fault(void)
{
  if (g_fault[0] != 0xFA017000UL)
  {
    return;
  }
  uart_str("\r\n[PORT] previous boot ended in a recorded fault: reason ");
  uart_u32(g_fault[1]);
  uart_str(" addr ");
  uart_u32(g_fault[2]);
  uart_str(" len ");
  uart_u32(g_fault[3]);
  uart_str("\r\n");
  g_fault[0] = 0U;
}

/* --------------------------------------------------- the previous pass -- */

/* The bus counters live in .noinit so that an install which fails and
 * reboots still has something to show for itself.  They are printed BEFORE
 * being cleared, so what appears at the top of a boot is the PREVIOUS
 * boot's traffic.  On the SAM D21 this is what showed that the decrypt
 * loop had not run at all, which no amount of reading ST's trace would
 * have said. */
static void report_bus_counters(void)
{
  if (BSP_SPIF_CountersInit() == 0)
  {
    uart_str("\r\n[PORT] bus counters were uninitialised (cold start)\r\n");
    return;
  }
  uart_str("\r\n[PORT] previous boot: reads ");
  uart_u32(g_spif_reads);
  uart_str(" bytes ");
  uart_u32(g_spif_read_bytes);
  uart_str(" polls ");
  uart_u32(g_spif_status_polls);
  uart_str(" writes ");
  uart_u32(g_spif_writes);
  uart_str(" erases ");
  uart_u32(g_spif_erases);
  if (g_spif_reject != 0U)
  {
    uart_str("\r\n[PORT] last read REJECTED: code ");
    uart_u32(g_spif_reject);
    uart_str(" addr ");
    uart_u32(g_spif_reject_addr);
    uart_str(" size ");
    uart_u32(g_spif_reject_size);
  }
  uart_str("\r\n");

  g_spif_reads = 0U;
  g_spif_read_bytes = 0U;
  g_spif_status_polls = 0U;
  g_spif_writes = 0U;
  g_spif_erases = 0U;
  g_spif_reject = 0U;
}

/* ------------------------------------------------------ the direct path -- */

#ifdef PORT_DIRECT_INSTALL
static void step(const char *what, uint32_t got, uint32_t want)
{
  uart_str("\r\n[PORT]   ");
  uart_str(what);
  uart_str(" -> ");
  uart_u32(got);
  uart_str((got == want) ? "  ok" : "  UNEXPECTED");
}

/* The stages SFU_BOOT_Init runs, run by hand before the direct install.
 *
 * WITHOUT THIS THE DIRECT INSTALL TOUCHES AN UNINITIALISED WORLD, and the
 * first symptom is silence rather than an error.  port_direct_install is
 * called BEFORE SFU_BOOT_RunSecureBootService -- that is the whole point
 * of it -- so nothing has called SFU_LL_FLASH_Init, which is what calls
 * BSP_QSPI_Init.  The BSP's spif_ready is still 0, every read is rejected
 * before a byte moves, and SFU_IMG_CheckPendingInstallation goes looking
 * at an image it cannot read.  Measured: the pass printed nothing at all
 * and the bus counters for that boot read reads=0 bytes=0 polls=0, which
 * is what "the driver was never brought up" looks like from outside.
 *
 * FLOW_CONTROL_INIT MATTERS HERE TOO, and it is easy to miss because the
 * state machine normally does it.  SFU_LL_SECU_CheckApplyStaticProtections
 * now feeds ST's running XOR, and a step taken against an uninitialised
 * accumulator mismatches and calls SFU_EXCPT_Security_Error -- a reset,
 * with the same message a genuine attack would produce.
 */
static void port_preflight(void)
{
  uart_str("\r\n[PORT] pre-flight, the SFU_BOOT_Init stages:");

  step("SE_Startup             ", (uint32_t)SE_Startup(), (uint32_t)SE_SUCCESS);
  step("SFU_LL_Init            ", (uint32_t)SFU_LL_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_LL_FLASH_Init      ", (uint32_t)SFU_LL_FLASH_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_COM_Init           ", (uint32_t)SFU_COM_Init(), (uint32_t)SFU_SUCCESS);
  step("SFU_IMG_InitImageHandling", (uint32_t)SFU_IMG_InitImageHandling(),
       (uint32_t)SFU_IMG_INIT_OK);
  {
    SE_StatusTypeDef se_status = SE_KO;
    SE_ErrorStatus r = SE_Init(&se_status, SystemCoreClock);

    step("SE_Init                ", (uint32_t)r, (uint32_t)SE_SUCCESS);
    uart_str("   SE status=");
    uart_u32((uint32_t)se_status);
  }

  /* THE TWO PROTECTION CALLS ARE DELIBERATELY NOT MADE HERE.
   *
   * The SAM D21 port's preflight runs them, as the two things
   * SFU_BOOT_SM_InstallNewUserFw does before it reaches
   * SFU_IMG_TriggerImageInstallation, and on that port it is harmless --
   * because that port's security file never feeds ST's flow-control
   * accumulator at all.
   *
   * This one does.  Calling them here XORs WRP and DMA into
   * uFlowProtectValue, and SFU_BOOT_RunSecureBootService then runs its own
   * accounting over an accumulator that has already been advanced.  The
   * result is SFU_EXCPT_Security_Error inside the boot service before it
   * prints a single state -- measured: "Security issue : execution
   * stopped !" immediately after the direct install returned, every boot,
   * with the state machine never reaching DOWNLOAD and the loader never
   * coming up.
   *
   * The direct install does not need them.  What it needs is the world
   * initialised -- the flash driver above all -- and that is what the
   * stages above do.  Leaving the accumulator untouched lets the state
   * machine that runs afterwards audit its own work, which is the whole
   * point of it. */
  uart_str("\r\n");
}

/* Run ST's install path directly, without the state machine.
 *
 * WHY THIS EXISTS.  The oracle this demo is built to measure is the loop
 * inside VerifyFwSignatureBeforeDecrypt: read a chunk from the serial
 * flash, SE_Decrypt_Append it, hash it, repeat.  That loop is reached from
 * SFU_IMG_TriggerImageInstallation, which is public API.  Calling the
 * installer directly runs the SAME ST code over the SAME image in the SAME
 * serial flash, so the bus traffic is the product's and not a mock-up.
 *
 * WHAT IT IS NOT.  It is not the shipped boot flow, and a measurement
 * taken through it must say so: the state machine's checks around the
 * install are skipped.  It is enabled only by -DPORT_DIRECT_INSTALL so it
 * cannot end up in a build that claims to be stock.
 *
 * ONE SHOT PER UPLOAD.  ST's installer erases the download slot when the
 * install fails, so each attempt consumes the staged image and the next
 * pass needs a fresh upload.
 */
static void port_direct_install(void)
{
  uint32_t reads_before = g_spif_reads;
  uint32_t polls_before = g_spif_status_polls;
  SFU_ErrorStatus r;

  /* CheckPendingInstallation FIRST.  TriggerImageInstallation's own
   * comment says fw_image_header_to_test "is already populated after
   * SFU_IMG_CheckPendingInstallation() call" -- it is a static that an
   * earlier state fills in.  Calling the installer without it leaves
   * FwSize at zero, so the decrypt loop's bound
   *     fw_index < FwSize + SFU_IMG_IMAGE_OFFSET
   * is false on the very first test, the loop body never runs, the bus
   * sees ZERO reads, and the tag check then reports "Fw signature check
   * error" -- which points squarely at the crypto and has nothing to do
   * with it.  The SAM D21 port lost a day to exactly this. */
  {
    uint32_t dwl = 0U;
    uint32_t resume = 0U;
    uint32_t rollback = 0U;
    SFU_IMG_ImgInstallStateTypeDef st =
      SFU_IMG_CheckPendingInstallation(&dwl, &resume, &rollback);

    uart_str("\r\n[PORT] CheckPendingInstallation -> state ");
    uart_u32((uint32_t)st);
    uart_str("  dwl slot ");
    uart_u32(dwl);
    uart_str("\r\n");
  }

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
   * matches on it.  Matching on a bare character is what once made the
   * YMODEM sender begin transferring into the middle of the words "System
   * Security Check".
   */
  {
    uint8_t ch = 0U;

    uart_str("\r\n[PORT] ORACLE1 ready -- arm the timer, then send G\r\n");

    /* THE WATCHDOG HAS TO BE FED WHILE WAITING, and the first version did
     * not do it: the receive was a single HAL_MAX_DELAY call, so the
     * Secure Engine's IWDG -- started a few lines earlier by
     * CheckApplyRuntimeProtections -- reset the board about 28 s into the
     * wait.  Measured, RCC_CSR 0x34000000: IWDGRSTF with the software and
     * pin flags.  The symptom was a board that printed this prompt and
     * then rebooted, over and over, while the host was still arming.
     *
     * A short timeout with a refresh each time round turns the wait into
     * something the attacker can hold open indefinitely.  That is not a
     * weakening of the target: the pause is BEFORE the install starts and
     * outside everything that gets timed, and ST's own local loader
     * refreshes the same watchdog while it waits for a YMODEM packet. */
    do
    {
      ch = 0U;
      (void)SFU_LL_UART_Receive(&ch, 1U, 200U);
      (void)SFU_LL_SECU_IWDG_Refresh();
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

/* ------------------------------------------- symbols ST's split expects -- */

/* SE_CORE_Startup() calls __gcc_data_init() to initialise the Secure
 * Engine's .data and .bss.  In ST's design SECoreBin is a SEPARATE BINARY
 * with its own sections, which the SBSFU image's startup knows nothing
 * about, so somebody has to do it and SE_Startup is that somebody.
 *
 * THIS PORT LINKS ONE IMAGE.  There is one .data and one .bss, and ST's
 * Reset_Handler in startup_stm32l152xe.s has already copied and cleared
 * them before main() runs.  Running ST's version again would re-zero .bss
 * -- including anything SBSFU has set since boot -- at whatever point
 * SE_Startup happens to be called.  That is a memory-corruption bug that
 * would present as a random crypto failure.
 *
 * So it is a deliberate no-op, not a stub that is "good enough": on a
 * single image the work is already done, and doing it twice is worse than
 * not doing it at all. */
void __gcc_data_init(void);
void __gcc_data_init(void) { }

/* se_callgate.c hands the Secure Engine the core clock so that ST's
 * se_utils.c can run its own SysTick-free tick.  This port does not build
 * se_utils.c -- there is no isolation, so the SE shares the application's
 * tick, and building ST's copy would duplicate HAL_GetTick and HAL_Delay
 * (see the SE_SRC note in the Makefile).  se_callgate.c still calls this,
 * so it lives here and writes the one SystemCoreClock the HAL owns. */
void SE_SetSystemCoreClock(uint32_t uSystemCoreClock);
void SE_SetSystemCoreClock(uint32_t uSystemCoreClock)
{
  SystemCoreClock = uSystemCoreClock;
}

/* newlib's __libc_init_array, which ST's startup calls, ends by calling
 * _init.  That symbol normally comes from crti.o/crtn.o, which
 * -nostartfiles leaves out.  An empty definition is the standard
 * resolution and is correct here: there are no C++ static constructors
 * and no .init_array entries in a freestanding C bootloader, so there is
 * nothing for it to do.  Without it the link fails with "undefined
 * reference to `_init'" from deep inside libc_nano, which names nothing
 * in this project. */
void _init(void);
void _init(void) { }

/* ------------------------------------------------------------------ main -- */

int main(void)
{
  /* MCU Configuration--------------------------------------------------------*/
  /* This part is NOT secure (security mechanisms NOT enabled yet)            */
  /* Reset of all peripherals, Initializes the Flash interface and the Systick*/
  (void) HAL_Init();

  /* Configure the system clock */
  SystemClock_Config();

  /* ST's comment here reads: "As the secure mode has not been entered yet,
   * we do not configure BSP right now.  The BSP will be configured by the
   * bootloader."  That is still true.  What follows before the bootloader
   * is REPORTING ONLY -- it reads two .noinit records written by the
   * previous boot and prints them.  It touches no peripheral the
   * bootloader will configure, except the UART, which SFU_LL_UART_Init
   * makes idempotent. */
  (void)SFU_LL_UART_Init();

  /* BOOT TRACE.  Three facts, printed before anything else can reset:
   * how many times we have been here since SRAM was last cold, what the
   * reset-cause flags say, and whether the .noinit records survived.
   * A board that resets in a loop tells you nothing; a board that resets
   * in a loop while counting tells you whether SRAM is being wiped. */
  {
    static __attribute__((section(".noinit"))) volatile uint32_t boot_magic;
    static __attribute__((section(".noinit"))) volatile uint32_t boot_count;

    uint32_t was = boot_magic;

    if (boot_magic != 0xB007B007UL)
    {
      boot_magic = 0xB007B007UL;
      boot_count = 0U;
    }
    boot_count++;
    uart_str("\r\n[PORT] boot ");
    uart_u32(boot_count);
    uart_str(" RCC_CSR ");
    uart_u32(RCC->CSR);
    /* The RAW value the magic had on entry, and where it lives.  "Always
     * 1" could mean SRAM is wiped, or that something else is writing to
     * that address, and zero tells those apart from garbage. */
    uart_str(" magic@");
    uart_u32((uint32_t)(uintptr_t)&boot_magic);
    uart_str("=");
    uart_u32(was);
    uart_str("\r\n");
  }

  report_fault();
  report_bus_counters();

  /* THE REGION BOUNDS, AND THE STACK POINTER THAT IS ABOUT TO BE TESTED
   * AGAINST THEM.
   *
   * se_callgate.c:236 resets the part when SE_LL_Buffer_part_of_SE_ram
   * says the caller's status pointer lives in the Secure Engine's own
   * RAM, and that status pointer is a LOCAL -- so it is wherever the
   * stack is.  On the SAM D21 that cost a day: the stack was inside SE
   * RAM, every SE call failed the test, and the board reset before
   * anything printed.  mapping_sbsfu.ld puts the stack at the top of
   * SBSFU RAM here for exactly that reason, and this line is how that
   * claim gets checked rather than asserted. */
  {
    uint32_t sp_here = (uint32_t)(uintptr_t)&sp_here;

    uart_str("[PORT] SE RAM  ");
    uart_u32(SE_REGION_RAM_START);
    uart_str(" .. ");
    uart_u32(SE_REGION_RAM_END);
    uart_str("\r\n[PORT] SB RAM  ");
    uart_u32(SB_REGION_RAM_START);
    uart_str(" .. ");
    uart_u32(SB_REGION_RAM_END);
    uart_str("\r\n[PORT] SE ROM  ");
    uart_u32(SE_CODE_REGION_ROM_START);
    uart_str(" .. ");
    uart_u32(SE_CODE_REGION_ROM_END);
    uart_str("\r\n[PORT] callgate ");
    uart_u32(SE_CALLGATE_REGION_ROM_START);
    uart_str("  SP ");
    uart_u32(sp_here);
    uart_str("\r\n");
  }

#ifdef PORT_DIRECT_INSTALL
  port_preflight();
  port_direct_install();
#endif /* PORT_DIRECT_INSTALL */

  uart_str("[PORT] entering SFU_BOOT_RunSecureBootService\r\n");

  /* Launch the Bootloader----------------------------------------------------*/
  /*
   * This is the beginning of the secure part:
   * security mechanisms will be enabled.
   * The function below should not return (unless a critical failure is encountered).
   */
  (void)SFU_BOOT_RunSecureBootService(); /* no need to take care of the returned value as we reboot in all cases */

  /* Security or SecureBoot initialization failure. Force a System Reset */
  SFU_BOOT_ForceReboot();

  return 0;
}

/**
  * @brief  System Clock Configuration
  *         The system Clock is configured as follows:
  *            System Clock source            = PLL (HSI)
  *            SYSCLK(Hz)                     = 32000000
  *            HCLK(Hz)                       = 32000000
  *            AHB Prescaler                  = 1
  *            APB1 Prescaler                 = 1
  *            APB2 Prescaler                 = 1
  *            HSI Frequency(Hz)              = 16000000
  *            PLLMUL                         = 6
  *            PLLDIV                         = 3
  *            Voltage range                  = 1
  *            Flash Latency(WS)              = 1
  *
  * Copied from ST's own NUCLEO-L152RE example,
  * Projects/NUCLEO-L152RE/Examples/SPI/SPI_FullDuplex_ComPolling/Src/main.c
  * in STM32CubeL1 v1.10.6.
  *
  * THE ONE WAIT STATE IS THE EXPERIMENT, not a detail.  On this part
  * LATENCY is a single bit, and 32 MHz in voltage range 1 is the only
  * configuration where it is set -- research/targets/stm32l152.md has the
  * measurement.  A build that came up at 16 MHz with zero wait states
  * would be a different experiment wearing the same name, which is why
  * the bring-up image asserts the readback rather than the request.
  */
void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};

  RCC_OscInitStruct.OscillatorType      = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState            = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState        = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource       = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLMUL          = RCC_PLL_MUL6;
  RCC_OscInitStruct.PLL.PLLDIV          = RCC_PLL_DIV3;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    SFU_BOOT_ForceReboot();
  }

  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);
  while (__HAL_PWR_GET_FLAG(PWR_FLAG_VOS) != RESET) {}

  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource   = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider  = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
  {
    SFU_BOOT_ForceReboot();
  }

#ifdef SBSFU_FLASH_NO_PREFETCH
  /* PREFETCH=off.  RM0038 3.9.1 makes PRFTEN conditional on ACC64, and the
   * HAL's clock configuration leaves both on, so turning prefetch off is a
   * deliberate second step rather than an alternative first one.  The wait
   * state stays: it is not reachable to remove at this clock. */
  __HAL_FLASH_PREFETCH_BUFFER_DISABLE();
#endif /* SBSFU_FLASH_NO_PREFETCH */
}
