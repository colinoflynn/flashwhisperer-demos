/**
  ******************************************************************************
  * @file    l152_nucleo_spif.c
  * @brief   Serial NOR flash on SPI2 of a NUCLEO-L152RE.
  *
  * See l152_nucleo_spif.h for the wiring, and for why these functions carry
  * ST's BSP_QSPI_* names on a part that has no QSPI peripheral.
  *
  * IT IS BUILT ON ST'S HAL, NOT ON REGISTERS
  * -----------------------------------------
  * Every bus access goes through `HAL_SPI_TransmitReceive` from
  * STM32CubeL1's STM32L1xx_HAL_Driver, and every pin through `HAL_GPIO_*`.
  * That is slower than poking `SPI2->DR` directly and it is the right choice
  * twice over: it is what ST's own `stm32l475e_iot01_qspi.c` does with
  * `HAL_QSPI_*`, so the port stays a port; and an attack demonstrated
  * THROUGH the HAL is an attack on what integrators actually ship.  The HAL
  * call overhead lands outside the AES, in the same place on every block.
  *
  * The SAM D21 port next door had to hand-write its HAL because Microchip's
  * silicon has no ST driver.  This board is the control for that: same BSP
  * API, same bootloader above it, ST's genuine driver underneath.
  ******************************************************************************
  */
#include "l152_nucleo_spif.h"

#include "stm32l1xx_hal.h"

/* ------------------------------------------------------------------ pins -- */
#define SPIF_SCK_PORT     GPIOB
#define SPIF_SCK_PIN      GPIO_PIN_13
#define SPIF_MISO_PORT    GPIOB
#define SPIF_MISO_PIN     GPIO_PIN_14
#define SPIF_MOSI_PORT    GPIOB
#define SPIF_MOSI_PIN     GPIO_PIN_15
#define SPIF_CS_PORT      GPIOA
#define SPIF_CS_PIN       GPIO_PIN_8

/* -------------------------------------------------------- JEDEC commands -- */
#define CMD_READ_ARRAY_LF   0x03U   /* opcode + 24-bit address, no dummy byte  */
#define CMD_PAGE_PROGRAM    0x02U
#define CMD_BLOCK_ERASE_4K  0x20U
#define CMD_BLOCK_ERASE_64K 0xD8U
#define CMD_CHIP_ERASE      0x60U
#define CMD_WRITE_ENABLE    0x06U
#define CMD_READ_STATUS     0x05U
#define CMD_WRITE_STATUS    0x01U
#define CMD_READ_ID         0x9FU

#define STATUS_BUSY         0x01U   /* 1 = an internal operation is running    */
#define STATUS_WEL          0x02U   /* write enable latch                      */
/* Every opcode here carries a 24-bit address, so this is the ceiling on
 * what the driver will address however big the part is.  See BSP_QSPI_Init. */
#define SPIF_ADDR24_LIMIT   (16UL * 1024UL * 1024UL)

#define STATUS_BP_MASK      0x7CU   /* block protection + TB, all parts below  */

/* Erase and program are slow enough that a spin needs a bound.  These are
 * HAL_GetTick() milliseconds, which this driver may use because it runs
 * after HAL_Init -- unlike the SAM D21 BSP, which runs before any tick
 * source exists and counts loop iterations instead.
 *
 * AT25SF321B worst cases (datasheet table 10-1): chip erase 30 s, 64 KB
 * block erase 700 ms, 4 KB sector erase 250 ms, page program 3 ms.  The
 * limits below are those rounded up with room to spare, because a timeout
 * that fires early reports a working chip as broken. */
#define TMO_CHIP_ERASE_MS   (60000U)
#define TMO_BLOCK_ERASE_MS  (3000U)
#define TMO_PROGRAM_MS      (100U)
#define TMO_XFER_MS         (1000U)

/* ------------------------------------------------------------------ state -- */
static SPI_HandleTypeDef hspi_flash;
static uint8_t  spif_hw_up;              /* pins + peripheral ready */
static uint8_t  spif_clamped;            /* chip is bigger than 24 bits */
static uint8_t  spif_ready;              /* ...and a part we recognise  */
static uint32_t spif_size;               /* capacity in bytes, from the ID   */
static const char *spif_name = "none";

volatile uint32_t g_spif_jedec;

/* Bus-transaction counters.
 *
 * rigs/fw_f303_spitimer/WIRING.md section 5 makes "count the envelopes" a
 * precondition for trusting a capture: a verify pass over S bytes at chunk
 * K must produce exactly ceil(S/K) data envelopes, and anything else means
 * the capture dropped edges or the image is not the length the host thinks.
 * These are the target's side of that check.
 *
 * They also answer a question that comes first -- whether the decrypt loop
 * ran AT ALL.  On the SAM D21 that counter is what showed it was not, which
 * no amount of reading ST's trace output would have said.
 *
 * Data reads and status polls are counted apart because they are separate
 * envelopes on the wire and the classifier has to tell them apart:
 * SFU_LL_FLASH_EXT_Read polls BSP_QSPI_GetStatus before EVERY data read.
 *
 * `.noinit`, not `.bss`: SBSFU reboots when an install fails, and counters
 * cleared by the startup code on the way back in report zero every time. */
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reads;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_read_bytes;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_status_polls;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_writes;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_erases;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject_addr;
__attribute__((section(".noinit"))) volatile uint32_t g_spif_reject_size;

/* ...AND THEREFORE NOTHING ZEROES THEM ON A COLD START.
 *
 * That is the whole point of .noinit and it is also a trap, which the
 * first successful run of this BSP walked straight into: the totals line
 * read "reads 584059292, bytes 1577137621, status polls 3968888341" --
 * uninitialised SRAM, printed as a measurement, next to a row of PASSes.
 * The delta tests were fine because a difference of two garbage values is
 * still a difference; the absolute figures were noise wearing a label.
 *
 * A magic word, in .noinit beside them, separates "survived a reset" from
 * "never been set".  Power-on leaves SRAM arbitrary, so the magic is
 * almost certainly absent and the counters get zeroed; a warm reset
 * preserves it and they carry over, which is what SBSFU needs when an
 * install fails and reboots before main() can report. */
#define SPIF_CTR_MAGIC  0x53504946UL                        /* "SPIF" */
__attribute__((section(".noinit"))) static volatile uint32_t g_spif_magic;

/* Returns 1 if the counters CARRIED OVER from a previous boot, 0 if they
 * were just zeroed.  One function rather than an is-it-set predicate
 * beside an initialiser: a separate predicate can only be asked before
 * the initialiser runs, and a caller that asks afterwards gets "yes"
 * every time -- which is how a cold start would come to be reported as a
 * surviving pass. */
int BSP_SPIF_CountersInit(void)
{
  if (g_spif_magic == SPIF_CTR_MAGIC)
  {
    return 1;
  }
  g_spif_reads = 0U;
  g_spif_read_bytes = 0U;
  g_spif_status_polls = 0U;
  g_spif_writes = 0U;
  g_spif_erases = 0U;
  g_spif_reject = 0U;
  g_spif_reject_addr = 0U;
  g_spif_reject_size = 0U;
  g_spif_magic = SPIF_CTR_MAGIC;
  return 0;
}

static uint8_t spif_hw_init(void);

/* Let a pull resistor win against the pin's own capacitance before
 * reading it.  ~40 kOhm into a few tens of pF of pin plus flying lead is
 * well under a microsecond, but HAL_Delay's resolution is a millisecond
 * and a busy loop is the only thing with the right granularity here. */
static void spif_settle(void)
{
  volatile uint32_t n = 2000U;
  while (n-- != 0U) { __NOP(); }
}

/* ------------------------------------------------------------- primitives -- */

static inline void cs_low(void)
{
  HAL_GPIO_WritePin(SPIF_CS_PORT, SPIF_CS_PIN, GPIO_PIN_RESET);
}

static inline void cs_high(void)
{
  HAL_GPIO_WritePin(SPIF_CS_PORT, SPIF_CS_PIN, GPIO_PIN_SET);
}

/* One full-duplex burst.  Either pointer may be NULL: transmit-only sends
 * `tx` and drops what comes back, receive-only clocks out whatever happens
 * to be in `rx` and keeps what comes in -- which is exactly what ST's
 * HAL_SPI_Receive does internally on a 2-line master, so it is the HAL's
 * own idiom rather than a shortcut around it. */
static uint8_t xfer(const uint8_t *tx, uint8_t *rx, uint16_t n)
{
  HAL_StatusTypeDef st;

  if (tx != NULL && rx != NULL)
  {
    st = HAL_SPI_TransmitReceive(&hspi_flash, (uint8_t *)tx, rx, n,
                                 TMO_XFER_MS);
  }
  else if (tx != NULL)
  {
    st = HAL_SPI_Transmit(&hspi_flash, (uint8_t *)tx, n, TMO_XFER_MS);
  }
  else
  {
    st = HAL_SPI_Receive(&hspi_flash, rx, n, TMO_XFER_MS);
  }
  return (st == HAL_OK) ? QSPI_OK : QSPI_ERROR;
}

static uint8_t cmd_only(uint8_t op)
{
  uint8_t r;
  cs_low();
  r = xfer(&op, NULL, 1U);
  cs_high();
  return r;
}

static uint8_t read_sr1(uint8_t *sr1)
{
  uint8_t tx[2] = { CMD_READ_STATUS, 0xFFU };
  uint8_t rx[2] = { 0U, 0U };
  uint8_t r;

  cs_low();
  r = xfer(tx, rx, 2U);
  cs_high();
  *sr1 = rx[1];
  return r;
}

/* Wait for the internal operation to finish.  Every poll is its own
 * chip-select envelope and is counted as one, because that is what the
 * probe on the wire will see. */
static uint8_t wait_ready(uint32_t timeout_ms)
{
  uint32_t start = HAL_GetTick();
  uint8_t sr1;

  for (;;)
  {
    g_spif_status_polls++;
    if (read_sr1(&sr1) != QSPI_OK)
    {
      return QSPI_ERROR;
    }
    if ((sr1 & STATUS_BUSY) == 0U)
    {
      return QSPI_OK;
    }
    if ((HAL_GetTick() - start) > timeout_ms)
    {
      return QSPI_BUSY;
    }
  }
}

static uint8_t write_enable(void)
{
  uint8_t sr1;

  if (cmd_only(CMD_WRITE_ENABLE) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  /* Read the latch back rather than assuming it took.  A chip still busy
   * from a previous erase silently ignores WREN, and the program that
   * follows then does nothing and reports success -- which reaches the
   * bootloader as an image that authenticates against garbage. */
  if (read_sr1(&sr1) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  return ((sr1 & STATUS_WEL) != 0U) ? QSPI_OK : QSPI_ERROR;
}

/* ------------------------------------------------------------- the part -- */

/* Capacity from the JEDEC ID.
 *
 * TWO CONVENTIONS, AND MIXING THEM IS THE BUG THIS FUNCTION EXISTS TO AVOID.
 * Most vendors (Winbond, Macronix, GigaDevice, ISSI) put log2 of the size in
 * the third byte, so 0x16 means 4 MB.  Adesto/Atmel do not: an AT25SF321B
 * answers 1F 87 01, where 0x87 identifies the family-and-size and 0x01 is a
 * revision.  Reading 0x01 as a power of two gives 2 bytes.
 *
 * So Adesto IDs are looked up and everything else uses the power-of-two
 * rule, and an ID that matches neither returns 0 -- BSP_QSPI_Init then
 * fails, loudly, instead of running the bootloader against a guessed size. */
static uint32_t capacity_of(uint8_t mfr, uint8_t type, uint8_t cap,
                            const char **name)
{
  if (mfr == 0x1FU)                                   /* Adesto / Atmel */
  {
    switch ((uint16_t)((uint16_t)type << 8 | cap))
    {
      case 0x8701U: *name = "AT25SF321";   return 4UL * 1024UL * 1024UL;
      case 0x8601U: *name = "AT25SF161";   return 2UL * 1024UL * 1024UL;
      case 0x8901U: *name = "AT25SF128A";  return 16UL * 1024UL * 1024UL;
      /* The chip soldered to the SAM D21 Xplained Pro, so the same driver
       * can be pointed at that board's memory without a second table. */
      case 0x4501U: *name = "AT25DF081A";  return 1UL * 1024UL * 1024UL;
      default: break;
    }
    *name = "unknown Adesto";
    return 0UL;
  }

  if (cap >= 0x10U && cap <= 0x1AU)     /* 64 KB .. 64 MB, the usual rule */
  {
    switch (mfr)
    {
      case 0xEFU: *name = "Winbond";     break;
      case 0xC2U: *name = "Macronix";    break;
      case 0xC8U: *name = "GigaDevice";  break;
      case 0x9DU: *name = "ISSI";        break;
      case 0x20U: *name = "Micron";      break;
      default:    *name = "JEDEC serial NOR"; break;
    }
    return 1UL << cap;
  }

  *name = "unrecognised";
  return 0UL;
}

const char *BSP_SPIF_PartName(void)
{
  return spif_name;
}

int BSP_SPIF_SizeClamped(void)
{
  return (int)spif_clamped;
}

uint8_t BSP_SPIF_ReadId(uint8_t id[3])
{
  uint8_t tx[4] = { CMD_READ_ID, 0xFFU, 0xFFU, 0xFFU };
  uint8_t rx[4] = { 0U, 0U, 0U, 0U };
  uint8_t r;

  /* Bring the pins and the peripheral up if nobody has yet.  The header
   * promises this function works BEFORE BSP_QSPI_Init, because when the ID
   * is the thing that failed the caller still needs to see what came back
   * -- and the first draft did not keep that promise: called first, it hit
   * an unconfigured SPI_HandleTypeDef and HAL returned an error, so the
   * bring-up printed "SPI transfer failed" for a perfectly good bus. */
  if (spif_hw_init() != QSPI_OK)
  {
    return QSPI_ERROR;
  }

  cs_low();
  r = xfer(tx, rx, 4U);
  cs_high();
  id[0] = rx[1];
  id[1] = rx[2];
  id[2] = rx[3];
  return r;
}

uint8_t BSP_SPIF_ReadStatus(uint8_t *sr1)
{
  return read_sr1(sr1);
}

/* Bring-up only.  A flying-lead bus that fails at 8 MHz and works at
 * 125 kHz has a signal-integrity problem; one that fails at both does not,
 * and the two need completely different things done about them.  Nothing
 * in the bootloader path calls this -- the capture runs at one rate, and
 * that rate is part of what is being measured. */
uint8_t BSP_SPIF_SetBaudPrescaler(uint32_t prescaler)
{
  if (spif_hw_init() != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  hspi_flash.Init.BaudRatePrescaler = prescaler;
  return (HAL_SPI_Init(&hspi_flash) == HAL_OK) ? QSPI_OK : QSPI_ERROR;
}

/* ------------------------------------------------- is anything attached -- */

/* How many read-back polls a pin takes to be dragged up by its own
 * pull-up.  It is a capacitance measurement in disguise, and it answers a
 * question none of the other probes here can: IS THERE A WIRE ON THIS PIN.
 *
 * A bare header pin is a few picofarads of pad and trace.  Add a jumper
 * lead, a breakout board and a memory's input pin and it is several times
 * that.  Pulled up through the GPIO block's ~40 kOhm, the difference shows
 * as a handful of polls against a few dozen, each poll being a few
 * core cycles at 32 MHz.  It is a crude absolute measurement and a good RELATIVE one,
 * which is all that is wanted: the four bus lines are compared against a
 * neighbouring pin on the same connector that is known to have nothing on
 * it, so the trace and pad contribution cancels and what is left is the
 * harness.
 *
 * The unit is POLLS rather than DWT cycles ON PURPOSE.  The first
 * version timed it with DWT->CYCCNT and every pin read exactly 0,
 * INCLUDING the bare references -- a saturated instrument reporting a
 * confident wrong answer, which is the failure MEASURING_CHANNELS.md is
 * mostly about.  A poll count needs no debug hardware to be enabled and
 * cannot read zero unless the pin really was already high.
 *
 * The mode switch is a direct write to MODER, not HAL_GPIO_Init: the HAL
 * call is hundreds of cycles of struct walking and would swamp the thing
 * being measured.  The pull is set up beforehand, while the pin is still an
 * output, where PUPDR has no effect.
 *
 * Interrupts are off across the measurement.  SysTick at 1 kHz would
 * otherwise land inside roughly one reading in a thousand and turn it into
 * an outlier -- and the statistic taken is the MINIMUM over several tries,
 * which is exactly the statistic an outlier cannot spoil.
 */
static uint32_t rise_polls(GPIO_TypeDef *port, uint32_t pos)
{
  GPIO_InitTypeDef g = {0};
  uint32_t best = 0xFFFFFFFFUL;
  int k;

  g.Pin   = (uint16_t)(1UL << pos);
  g.Mode  = GPIO_MODE_OUTPUT_PP;
  g.Pull  = GPIO_PULLUP;
  g.Speed = GPIO_SPEED_HIGH;
  HAL_GPIO_Init(port, &g);

  for (k = 0; k < 8; k++)
  {
    uint32_t n = 0U;

    port->BSRR = (uint32_t)(1UL << pos) << 16;     /* drive it low      */
    spif_settle();

    __disable_irq();
    port->MODER &= ~(3UL << (2U * pos));           /* output -> input   */
    while (((port->IDR & (1UL << pos)) == 0U) && (n < 20000U))
    {
      n++;
    }
    port->MODER |= (1UL << (2U * pos));            /* input -> output   */
    __enable_irq();

    if (n >= 20000U)
    {
      return 0xFFFFFFFFUL;                         /* never came up     */
    }
    if (n < best)
    {
      best = n;
    }
  }

  /* Leave it as an input rather than an output: this function is called
   * on pins that may be driven from the other end, and handing one back
   * as a push-pull output would put two drivers on one wire. */
  g.Mode = GPIO_MODE_INPUT;
  g.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(port, &g);
  return best;
}

/* Six readings: the four bus lines, then two reference pins on the same
 * two connectors that are known to carry nothing.  PA9 is D8, next to
 * PA8/D7 on CN9; PB12 is CN10 pin 16, next to the SPI2 group.  Neither is
 * used by this port, so whatever they read is a bare pin on this board --
 * and a bus line that matches its reference has nothing on it either. */
void BSP_SPIF_ProbeLoad(uint32_t out[6])
{
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  (void)HAL_SPI_DeInit(&hspi_flash);
  spif_hw_up = 0U;
  spif_ready = 0U;

  out[0] = rise_polls(GPIOA, 8U);    /* CS   */
  out[1] = rise_polls(GPIOB, 13U);   /* SCK  */
  out[2] = rise_polls(GPIOB, 14U);   /* MISO */
  out[3] = rise_polls(GPIOB, 15U);   /* MOSI */
  out[4] = rise_polls(GPIOA, 9U);    /* bare reference on CN9  */
  out[5] = rise_polls(GPIOB, 12U);   /* bare reference on CN10 */

  (void)spif_hw_init();
}

/* --------------------------------------------- one pin, driven by hand -- */

/* Bring-up only: hand a single line over to the caller as a plain GPIO
 * output, so it can be driven slowly enough to find with a meter.
 *
 * At the bus rates this driver normally uses, a chip-select envelope is
 * microseconds wide and invisible to anything but a scope on the right
 * pin.  Someone tracing a lead needs the opposite: a level that sits still
 * long enough to measure, on one pin at a time, with the other three left
 * as inputs so nothing else on the harness is being driven while they
 * work.
 *
 * Index order matches BSP_SPIF_ProbeWiring's short matrix: 0 CS, 1 SCK,
 * 2 MISO, 3 MOSI.
 */
static GPIO_TypeDef *const PIN_PORT[4] = {
  SPIF_CS_PORT, SPIF_SCK_PORT, SPIF_MISO_PORT, SPIF_MOSI_PORT
};
static const uint16_t PIN_BIT[4] = {
  SPIF_CS_PIN, SPIF_SCK_PIN, SPIF_MISO_PIN, SPIF_MOSI_PIN
};

uint8_t BSP_SPIF_PinGpioMode(int idx)
{
  GPIO_InitTypeDef g = {0};
  int j;

  if (idx < 0 || idx > 3)
  {
    return QSPI_ERROR;
  }

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  /* The peripheral has to let go first, or the mode change fights it. */
  (void)HAL_SPI_DeInit(&hspi_flash);
  spif_hw_up = 0U;
  spif_ready = 0U;

  for (j = 0; j < 4; j++)
  {
    g.Pin   = PIN_BIT[j];
    g.Speed = GPIO_SPEED_HIGH;
    if (j == idx)
    {
      g.Mode = GPIO_MODE_OUTPUT_PP;
      g.Pull = GPIO_NOPULL;
    }
    else
    {
      /* Inputs, and specifically NOT pulled: while a lead is being traced
       * the other three should be doing nothing at all, so that a meter
       * on any of them reads the harness rather than this board. */
      g.Mode = GPIO_MODE_INPUT;
      g.Pull = GPIO_NOPULL;
    }
    HAL_GPIO_Init(PIN_PORT[j], &g);
  }
  return QSPI_OK;
}

void BSP_SPIF_PinWrite(int idx, int level)
{
  if (idx >= 0 && idx <= 3)
  {
    HAL_GPIO_WritePin(PIN_PORT[idx], PIN_BIT[idx],
                      level ? GPIO_PIN_SET : GPIO_PIN_RESET);
  }
}

void BSP_SPIF_PinRestore(void)
{
  (void)spif_hw_init();
}

/* Bit-banged JEDEC ID read, bring-up only, with the data pair optionally
 * SWAPPED.
 *
 * SI and SO crossed is the commonest mistake on a four-lead hook-up, and it
 * is invisible to every other test here: the memory sees its opcode on the
 * wrong pin, never replies, and PB14 floats -- which is exactly what a
 * missing ground or an unpowered chip looks like too.
 *
 * SPI2's alternate functions are fixed in silicon (PB14 is MISO, PB15 is
 * MOSI, and no AF setting exchanges them), so the only way to ask the
 * question is to drive all four lines as GPIO and clock the transaction by
 * hand.  Mode 0: data changes on the falling edge and is sampled on the
 * rising one.  Slow on purpose -- a few tens of kHz, so lead quality
 * cannot be what fails.
 */
uint8_t BSP_SPIF_BitbangId(uint8_t id[3], int swap_data)
{
  GPIO_TypeDef *out_port = swap_data ? SPIF_MISO_PORT : SPIF_MOSI_PORT;
  uint16_t      out_pin  = swap_data ? SPIF_MISO_PIN  : SPIF_MOSI_PIN;
  GPIO_TypeDef *in_port  = swap_data ? SPIF_MOSI_PORT : SPIF_MISO_PORT;
  uint16_t      in_pin   = swap_data ? SPIF_MOSI_PIN  : SPIF_MISO_PIN;
  GPIO_InitTypeDef g = {0};
  uint8_t out[4] = { CMD_READ_ID, 0U, 0U, 0U };
  uint8_t in[4]  = { 0U, 0U, 0U, 0U };
  int byte, bit;

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  (void)HAL_SPI_DeInit(&hspi_flash);
  spif_hw_up = 0U;
  spif_ready = 0U;

  g.Speed = GPIO_SPEED_HIGH;
  g.Mode  = GPIO_MODE_OUTPUT_PP;
  g.Pull  = GPIO_NOPULL;
  g.Pin   = SPIF_CS_PIN;   HAL_GPIO_Init(SPIF_CS_PORT, &g);
  g.Pin   = SPIF_SCK_PIN;  HAL_GPIO_Init(SPIF_SCK_PORT, &g);
  g.Pin   = out_pin;       HAL_GPIO_Init(out_port, &g);
  g.Mode  = GPIO_MODE_INPUT;
  g.Pull  = GPIO_PULLUP;
  g.Pin   = in_pin;        HAL_GPIO_Init(in_port, &g);

  HAL_GPIO_WritePin(SPIF_CS_PORT, SPIF_CS_PIN, GPIO_PIN_SET);
  HAL_GPIO_WritePin(SPIF_SCK_PORT, SPIF_SCK_PIN, GPIO_PIN_RESET);
  spif_settle();
  HAL_GPIO_WritePin(SPIF_CS_PORT, SPIF_CS_PIN, GPIO_PIN_RESET);
  spif_settle();

  for (byte = 0; byte < 4; byte++)
  {
    for (bit = 7; bit >= 0; bit--)
    {
      HAL_GPIO_WritePin(out_port, out_pin,
                        ((out[byte] >> bit) & 1U) ? GPIO_PIN_SET
                                                  : GPIO_PIN_RESET);
      spif_settle();
      HAL_GPIO_WritePin(SPIF_SCK_PORT, SPIF_SCK_PIN, GPIO_PIN_SET);
      spif_settle();
      in[byte] = (uint8_t)((in[byte] << 1) |
                 ((HAL_GPIO_ReadPin(in_port, in_pin) == GPIO_PIN_SET)
                  ? 1U : 0U));
      HAL_GPIO_WritePin(SPIF_SCK_PORT, SPIF_SCK_PIN, GPIO_PIN_RESET);
      spif_settle();
    }
  }

  HAL_GPIO_WritePin(SPIF_CS_PORT, SPIF_CS_PIN, GPIO_PIN_SET);
  id[0] = in[1];
  id[1] = in[2];
  id[2] = in[3];

  (void)spif_hw_init();
  return QSPI_OK;
}

/* Pin-level wiring probe, also bring-up only.
 *
 * Takes all four lines off the SPI peripheral and drives them one at a
 * time as GPIO, with the other three as inputs.  Two things come out that
 * a failed JEDEC read cannot distinguish on its own:
 *
 *   - whether MISO is FLOATING (nothing on the other end, or the memory
 *     unpowered) or actively HELD, by reading it under a pull-up and then
 *     under a pull-down.  A line that follows the pull is not connected to
 *     anything that drives;
 *   - whether two of the four are SHORTED, by driving exactly one low
 *     while the others sit under pull-ups.  Any input that follows is
 *     tied to the driven pin.  Only ever one driver at a time, so a short
 *     is found without two push-pull outputs fighting over it.
 *
 * Returns a bitmap: bit0 MISO floats high, bit1 MISO can be pulled low,
 * and bits 4..15 the short matrix, four bits per driven pin in the order
 * CS, SCK, MISO, MOSI.  The caller prints it; encoding it here keeps the
 * probe out of the driver's normal path.
 */
uint32_t BSP_SPIF_ProbeWiring(void)
{
  /* PIN_PORT / PIN_BIT, shared with BSP_SPIF_PinGpioMode above.  They were
   * duplicated here once; two copies of a pin order is two things to keep
   * in step, and the short matrix's meaning depends on that order. */
  GPIO_TypeDef *const *const port = PIN_PORT;
  const uint16_t *const pin = PIN_BIT;
  GPIO_InitTypeDef g = {0};
  uint32_t out = 0U;
  int i, j;

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  /* The peripheral must let go of the pins, or HAL_GPIO_Init's mode change
   * fights whatever SPI2 is doing with them. */
  (void)HAL_SPI_DeInit(&hspi_flash);
  spif_hw_up = 0U;
  spif_ready = 0U;

  /* Is MISO connected to anything that drives? */
  g.Mode = GPIO_MODE_INPUT;
  g.Speed = GPIO_SPEED_HIGH;
  g.Pin = SPIF_MISO_PIN;
  g.Pull = GPIO_PULLUP;
  HAL_GPIO_Init(SPIF_MISO_PORT, &g);
  spif_settle();
  if (HAL_GPIO_ReadPin(SPIF_MISO_PORT, SPIF_MISO_PIN) == GPIO_PIN_SET)
  {
    out |= 1U;
  }
  g.Pull = GPIO_PULLDOWN;
  HAL_GPIO_Init(SPIF_MISO_PORT, &g);
  spif_settle();
  if (HAL_GPIO_ReadPin(SPIF_MISO_PORT, SPIF_MISO_PIN) == GPIO_PIN_RESET)
  {
    out |= 2U;
  }

  /* Short matrix.  One pin driven low, the rest pulled up. */
  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 4; j++)
    {
      g.Pin   = pin[j];
      g.Speed = GPIO_SPEED_HIGH;
      if (j == i)
      {
        g.Mode = GPIO_MODE_OUTPUT_PP;
        g.Pull = GPIO_NOPULL;
      }
      else
      {
        g.Mode = GPIO_MODE_INPUT;
        g.Pull = GPIO_PULLUP;
      }
      HAL_GPIO_Init(port[j], &g);
    }
    HAL_GPIO_WritePin(port[i], pin[i], GPIO_PIN_RESET);
    spif_settle();
    for (j = 0; j < 4; j++)
    {
      if (j != i &&
          HAL_GPIO_ReadPin(port[j], pin[j]) == GPIO_PIN_RESET)
      {
        out |= 1UL << (4 + 4 * i + j);
      }
    }
    HAL_GPIO_WritePin(port[i], pin[i], GPIO_PIN_SET);
  }

  /* Leave the pins as the driver wants them.  A probe that returns the
   * board in a different state than it found it is a probe whose result
   * cannot be followed by a retry, and a retry is the whole point. */
  (void)spif_hw_init();
  return out;
}

/* ------------------------------------------------------------------ init -- */

/* Pins and peripheral only: everything that must be true before a byte can
 * move, and nothing that depends on which chip is on the other end.
 * Idempotent, because BSP_SPIF_ReadId may call it first and BSP_QSPI_Init
 * then calls it again. */
static uint8_t spif_hw_init(void)
{
  GPIO_InitTypeDef gpio = {0};

  if (spif_hw_up != 0U)
  {
    return QSPI_OK;
  }

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_SPI2_CLK_ENABLE();

  /* Chip-select FIRST and high, before the bus pins exist.  A CS that is
   * still an input when SCK starts moving leaves the memory latching clock
   * edges it should be ignoring, and the first transaction after reset then
   * reads shifted data -- intermittently, which is the worst way to find
   * out about it. */
  gpio.Pin   = SPIF_CS_PIN;
  gpio.Mode  = GPIO_MODE_OUTPUT_PP;
  gpio.Pull  = GPIO_NOPULL;
  gpio.Speed = GPIO_SPEED_HIGH;
  HAL_GPIO_Init(SPIF_CS_PORT, &gpio);
  cs_high();

  gpio.Pin       = SPIF_SCK_PIN | SPIF_MOSI_PIN;
  gpio.Mode      = GPIO_MODE_AF_PP;
  gpio.Pull      = GPIO_NOPULL;
  gpio.Speed     = GPIO_SPEED_HIGH;
  gpio.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(GPIOB, &gpio);

  /* MISO gets a PULL-UP, and it is a diagnostic decision rather than an
   * electrical necessity.  With no pull, an unconnected MISO floats and
   * reads as whatever the last edge left on it -- the first run of this
   * port read a JEDEC ID of 00 00 00 and the driver reported "MISO held
   * low", which is only one of the three things it could have meant.  With
   * a pull-up, nothing driving the line reads 0xFF and something driving
   * it low reads 0x00, so the two failures are distinguishable at a glance
   * instead of by getting a scope out.
   *
   * It costs nothing when the memory is present: a NOR flash drives SO
   * actively whenever it is selected, and a ~40 kOhm pull is far too weak
   * to fight it.  Shipped drivers do this for the same reason. */
  gpio.Pin       = SPIF_MISO_PIN;
  gpio.Mode      = GPIO_MODE_AF_PP;
  gpio.Pull      = GPIO_PULLUP;
  gpio.Speed     = GPIO_SPEED_HIGH;
  gpio.Alternate = GPIO_AF5_SPI2;
  HAL_GPIO_Init(GPIOB, &gpio);

  hspi_flash.Instance               = SPI2;
  hspi_flash.Init.Mode              = SPI_MODE_MASTER;
  hspi_flash.Init.Direction         = SPI_DIRECTION_2LINES;
  hspi_flash.Init.DataSize          = SPI_DATASIZE_8BIT;
  /* Mode 0.  Serial NOR accepts mode 0 and mode 3; mode 0 is what every
   * driver quoted in BOOTLOADER_SPI_ORACLE.md uses, and the idle level of
   * SCK is one of the things a probe on the wire sees. */
  hspi_flash.Init.CLKPolarity       = SPI_POLARITY_LOW;
  hspi_flash.Init.CLKPhase          = SPI_PHASE_1EDGE;
  /* Software NSS, and not by preference: /CS is on PA8, which is not an
   * NSS pin for SPI2 at all.  See the header. */
  hspi_flash.Init.NSS               = SPI_NSS_SOFT;
  /* PCLK1 / 4.  At the 32 MHz SYSCLK this port runs, that is 8 MHz -- well
   * inside the 03h read opcode's 55 MHz limit on an AT25SF321B, and the
   * same bus rate the SAM D21 rig measured at, so the two captures'
   * per-byte bus times are directly comparable. */
  hspi_flash.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_4;
  hspi_flash.Init.FirstBit          = SPI_FIRSTBIT_MSB;
  hspi_flash.Init.TIMode            = SPI_TIMODE_DISABLE;
  hspi_flash.Init.CRCCalculation    = SPI_CRCCALCULATION_DISABLE;
  hspi_flash.Init.CRCPolynomial     = 7U;

  if (HAL_SPI_Init(&hspi_flash) != HAL_OK)
  {
    return QSPI_ERROR;
  }
  spif_hw_up = 1U;
  return QSPI_OK;
}

uint8_t BSP_QSPI_Init(void)
{
  uint8_t id[3];
  uint8_t sr1;

  spif_ready = 0U;

  if (spif_hw_init() != QSPI_OK)
  {
    return QSPI_ERROR;
  }

  if (BSP_SPIF_ReadId(id) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  g_spif_jedec = ((uint32_t)id[0] << 16) | ((uint32_t)id[1] << 8) | id[2];
  spif_size = capacity_of(id[0], id[1], id[2], &spif_name);

  /* THE USABLE SIZE IS NOT ALWAYS THE CHIP'S SIZE.
   *
   * Every opcode this driver issues carries a 24-BIT address, which is
   * the universal serial-NOR convention and reaches 16 MB.  A W25Q256JV
   * is 32 MB, and the first part fitted to this rig that is: ask a
   * 3-byte-address read for 0x1000000 and the chip sees 0x000000 and
   * answers, cheerfully, with the wrong data.  No error, no status bit,
   * just the start of the array returned as though it were the middle.
   *
   * Reaching the upper half needs either the 4-byte opcodes (0x13, 0x12,
   * 0xDC) or EN4B, and this port needs neither: the download slot is
   * 384 KB at offset 0.  So the honest thing is to clamp what the driver
   * will ADMIT to having, so the bounds checks in Read and Write reject
   * an address they cannot actually reach instead of silently aliasing
   * it.  The true capacity stays in the part name and the JEDEC ID. */
  if (spif_size > SPIF_ADDR24_LIMIT)
  {
    spif_size = SPIF_ADDR24_LIMIT;
    spif_clamped = 1U;
  }
  else
  {
    spif_clamped = 0U;
  }

  /* An all-ones or all-zeros ID is not an unknown part, it is no part:
   * 0xFF is a floating MISO and 0x00 is a MISO held low, and both mean the
   * wiring, not the chip.  Distinguished here because the two failures are
   * fixed at different ends of the lead. */
  if (g_spif_jedec == 0x00FFFFFFUL)
  {
    spif_name = "no reply (MISO idle high)";
    return QSPI_ERROR;
  }
  if (g_spif_jedec == 0x00000000UL)
  {
    spif_name = "no reply (MISO held low)";
    return QSPI_ERROR;
  }
  if (spif_size == 0UL)
  {
    return QSPI_ERROR;
  }

  /* Clear block protection.  Every part in the table above powers up with
   * its BP bits in a vendor-chosen state, and on an AT25SF321B a protected
   * range accepts a program, sets no error bit, and changes nothing -- so
   * the staged image would read back as whatever was there before and the
   * bootloader would fail authentication for a reason that has nothing to
   * do with the bootloader.  Writing 0x00 to status register 1 clears BP
   * and TB on the Adesto and Winbond-style parts alike. */
  if (wait_ready(TMO_BLOCK_ERASE_MS) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  if (read_sr1(&sr1) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  if ((sr1 & STATUS_BP_MASK) != 0U)
  {
    uint8_t tx[2] = { CMD_WRITE_STATUS, 0x00U };

    if (write_enable() != QSPI_OK)
    {
      return QSPI_ERROR;
    }
    cs_low();
    (void)xfer(tx, NULL, 2U);
    cs_high();
    if (wait_ready(TMO_PROGRAM_MS) != QSPI_OK)
    {
      return QSPI_ERROR;
    }
    /* Read back: a status write can be refused outright by SRP0/WP, and a
     * driver that assumed it worked would fail much later and elsewhere. */
    if (read_sr1(&sr1) != QSPI_OK)
    {
      return QSPI_ERROR;
    }
    if ((sr1 & STATUS_BP_MASK) != 0U)
    {
      spif_name = "protected (check /WP)";
      return QSPI_ERROR;
    }
  }

  spif_ready = 1U;
  return QSPI_OK;
}

uint8_t BSP_QSPI_DeInit(void)
{
  spif_ready = 0U;
  spif_hw_up = 0U;
  cs_high();
  return (HAL_SPI_DeInit(&hspi_flash) == HAL_OK) ? QSPI_OK : QSPI_ERROR;
}

/* ------------------------------------------------------------------ read -- */

uint8_t BSP_QSPI_Read(uint8_t *pData, uint32_t ReadAddr, uint32_t Size)
{
  uint8_t hdr[4];
  uint8_t r;

  if (spif_ready == 0U)
  {
    g_spif_reject = 0x80000001UL;
    g_spif_reject_addr = ReadAddr;
    g_spif_reject_size = Size;
    return QSPI_ERROR;
  }
  if (pData == NULL || Size == 0U)
  {
    g_spif_reject = 0x80000002UL;
    g_spif_reject_addr = ReadAddr;
    g_spif_reject_size = Size;
    return QSPI_ERROR;
  }
  if (ReadAddr > spif_size || Size > spif_size - ReadAddr)
  {
    g_spif_reject = 0x80000004UL;
    g_spif_reject_addr = ReadAddr;
    g_spif_reject_size = Size;
    return QSPI_ERROR;
  }

  hdr[0] = CMD_READ_ARRAY_LF;
  hdr[1] = (uint8_t)(ReadAddr >> 16);
  hdr[2] = (uint8_t)(ReadAddr >> 8);
  hdr[3] = (uint8_t)(ReadAddr);

  /* ONE ENVELOPE.  CS falls here, the opcode and address go out, the whole
   * Size is clocked, and CS rises at the end -- no split, no hold across
   * calls.  The interval the F303 timer measures is the gap between this
   * envelope's rising edge and the next one's falling edge, and what
   * happens in that gap is the AES. */
  cs_low();
  r = xfer(hdr, NULL, 4U);
  if (r == QSPI_OK)
  {
    /* HAL_SPI_Receive clocks out whatever is in the caller's buffer.  That
     * is harmless for a NOR read -- the memory ignores SI during a data
     * phase -- and it is ST's own path, not a shortcut around it. */
    r = xfer(NULL, pData, (uint16_t)Size);
  }
  cs_high();

  if (r == QSPI_OK)
  {
    g_spif_reads++;
    g_spif_read_bytes += Size;
  }
  return r;
}

/* ----------------------------------------------------------------- write -- */

uint8_t BSP_QSPI_Write(uint8_t *pData, uint32_t WriteAddr, uint32_t Size)
{
  if (spif_ready == 0U || pData == NULL)
  {
    return QSPI_ERROR;
  }
  if (WriteAddr > spif_size || Size > spif_size - WriteAddr)
  {
    return QSPI_ERROR;
  }

  while (Size > 0U)
  {
    /* Split on the PAGE boundary, not into fixed 256-byte pieces.  A page
     * program that runs off the end of its page wraps to the START of the
     * same page instead of continuing -- so a fixed-size loop starting at
     * an unaligned address corrupts the beginning of every page it touches,
     * and the corruption surfaces hours later as an authentication
     * failure.  This is the one arithmetic bug an SPI NOR driver must not
     * have, and the bring-up image tests it explicitly. */
    uint32_t room = SPIF_PAGE_SIZE - (WriteAddr % SPIF_PAGE_SIZE);
    uint32_t n    = (Size < room) ? Size : room;
    uint8_t  hdr[4];
    uint8_t  r;

    if (write_enable() != QSPI_OK)
    {
      return QSPI_ERROR;
    }

    hdr[0] = CMD_PAGE_PROGRAM;
    hdr[1] = (uint8_t)(WriteAddr >> 16);
    hdr[2] = (uint8_t)(WriteAddr >> 8);
    hdr[3] = (uint8_t)(WriteAddr);

    cs_low();
    r = xfer(hdr, NULL, 4U);
    if (r == QSPI_OK)
    {
      r = xfer(pData, NULL, (uint16_t)n);
    }
    cs_high();
    if (r != QSPI_OK)
    {
      return r;
    }
    if (wait_ready(TMO_PROGRAM_MS) != QSPI_OK)
    {
      return QSPI_ERROR;
    }

    g_spif_writes++;
    WriteAddr += n;
    pData     += n;
    Size      -= n;
  }
  return QSPI_OK;
}

/* ----------------------------------------------------------------- erase -- */

static uint8_t erase_at(uint8_t op, uint32_t addr, uint32_t timeout_ms)
{
  uint8_t hdr[4];
  uint8_t r;

  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  if (write_enable() != QSPI_OK)
  {
    return QSPI_ERROR;
  }

  hdr[0] = op;
  hdr[1] = (uint8_t)(addr >> 16);
  hdr[2] = (uint8_t)(addr >> 8);
  hdr[3] = (uint8_t)(addr);

  cs_low();
  r = xfer(hdr, NULL, 4U);
  cs_high();
  if (r != QSPI_OK)
  {
    return r;
  }
  if (wait_ready(timeout_ms) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  g_spif_erases++;
  return QSPI_OK;
}

uint8_t BSP_QSPI_Erase_Block(uint32_t BlockAddress)
{
  return erase_at(CMD_BLOCK_ERASE_64K, BlockAddress, TMO_BLOCK_ERASE_MS);
}

/* ST's callers pass a BYTE ADDRESS here despite the parameter being named
 * `Sector`; stm32l475e_iot01_qspi.c does the same.  Kept as ST has it so
 * the seam stays one include. */
uint8_t BSP_QSPI_Erase_Sector(uint32_t Sector)
{
  return erase_at(CMD_BLOCK_ERASE_4K, Sector, TMO_BLOCK_ERASE_MS);
}

uint8_t BSP_QSPI_Erase_Chip(void)
{
  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  if (write_enable() != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  if (cmd_only(CMD_CHIP_ERASE) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  if (wait_ready(TMO_CHIP_ERASE_MS) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  g_spif_erases++;
  return QSPI_OK;
}

/* ------------------------------------------------------------------ misc -- */

uint8_t BSP_QSPI_GetStatus(void)
{
  uint8_t sr1;

  if (spif_ready == 0U)
  {
    return QSPI_ERROR;
  }
  g_spif_status_polls++;
  if (read_sr1(&sr1) != QSPI_OK)
  {
    return QSPI_ERROR;
  }
  return ((sr1 & STATUS_BUSY) != 0U) ? QSPI_BUSY : QSPI_OK;
}

uint8_t BSP_QSPI_GetInfo(QSPI_Info *pInfo)
{
  if (pInfo == NULL || spif_size == 0UL)
  {
    return QSPI_ERROR;
  }
  pInfo->FlashSize          = spif_size;
  pInfo->EraseSectorSize    = SPIF_SECTOR_SIZE;
  pInfo->EraseSectorsNumber = spif_size / SPIF_SECTOR_SIZE;
  pInfo->ProgPageSize       = SPIF_PAGE_SIZE;
  pInfo->ProgPagesNumber    = spif_size / SPIF_PAGE_SIZE;
  return QSPI_OK;
}

/* There is no memory-mapped window on a plain SPI master, and that is not a
 * gap in this driver -- it is the property that makes the board a target.
 * Returning NOT_SUPPORTED rather than omitting the symbol keeps a caller
 * that grows a dependency on it failing at run time with a code you can
 * read, instead of at link time with a mangled name. */
uint8_t BSP_QSPI_EnableMemoryMappedMode(void)
{
  return QSPI_NOT_SUPPORTED;
}
