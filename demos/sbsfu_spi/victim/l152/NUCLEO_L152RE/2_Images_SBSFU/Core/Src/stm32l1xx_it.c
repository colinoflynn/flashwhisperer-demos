/**
  ******************************************************************************
  * @file    stm32l1xx_it.c
  * @brief   Interrupt handlers, NUCLEO-L152RE.
  *
  * WHY NMI_Handler AND HardFault_Handler ARE HERE AND NOT IN
  * sfu_low_level_flash_int.c, WHICH IS WHERE ST PUTS THEM
  * -------------------------------------------------------------------------
  * On the L4 those two handlers belong to the flash driver, because
  * reading an ERASED double word raises a double-ECC-error NMI and ST's
  * SFU_LL_FLASH_INT_Read has to survive it mid-copy -- their handler
  * increments a counter the read loop polls.  The L1 has no ECC on its
  * program memory: an erased word reads 0xFFFFFFFF and raises nothing.
  *
  * So on this part the two handlers have no flash-specific job, and
  * putting them in the flash driver would imply a relationship that does
  * not exist.  They are declared in sfu_low_level_flash_int.h, because
  * this port keeps ST's interface identical, and defined here.
  *
  * WHAT THEY DO INSTEAD IS WORTH MORE THAN A SPIN LOOP.  A bootloader that
  * hard-faults and sits there is indistinguishable from one that hangs on
  * a peripheral, and during bring-up that difference is most of the
  * information.  Both handlers record to the same .noinit slot
  * se_low_level.c's security reset uses, then reset, so main() reports the
  * cause on the next boot.
  ******************************************************************************
  */
#include "main.h"
#include "sfu_low_level_flash_int.h"

extern volatile uint32_t g_fault[4];

#define FAULT_MAGIC       (0xFA017000UL)
#define FAULT_NMI         (0x4E4D4900UL)        /* "NMI"       */
#define FAULT_HARD        (0x48415244UL)        /* "HARD"      */

/* SAY IT ON THE WIRE, NOT ONLY IN SRAM.
 *
 * The .noinit record is the right mechanism for a fault that happens
 * during a capture, when nothing is reading the console.  It is the WRONG
 * mechanism while the port is still being brought up, because it assumes
 * the thing it is trying to diagnose did not also corrupt SRAM -- and a
 * wild write is one of the two most likely causes of an early fault.
 *
 * So a fault also prints, synchronously, straight to the UART data
 * register.  Not through the HAL: a fault handler must not depend on a
 * peripheral handle whose state it cannot trust, and HAL_UART_Transmit
 * takes a lock and a timeout that need SysTick.  This is a dozen stores
 * to USART2 with a spin on TXE, which works as long as the UART was
 * configured, and if it was not the handler still resets. */
static void fault_putc(char c)
{
  uint32_t spin = 200000U;

  while (((USART2->SR & USART_SR_TXE) == 0U) && (spin-- != 0U))
  {
  }
  USART2->DR = (uint16_t)c;
}

static void fault_hex(uint32_t v)
{
  static const char H[] = "0123456789abcdef";
  int i;

  for (i = 7; i >= 0; i--)
  {
    fault_putc(H[(v >> (4 * i)) & 0xFU]);
  }
}

static void fault_str(const char *s)
{
  while (*s != '\0')
  {
    fault_putc(*s++);
  }
}

/* THE STACKED FRAME, which is the only thing that says WHERE.
 *
 * On exception entry the core pushes r0, r1, r2, r3, r12, LR, PC, xPSR --
 * eight words -- so the faulting PC is frame[6] and the caller's LR is
 * frame[5].
 *
 * READING MSP INSIDE A C HANDLER DOES NOT GIVE THE FRAME, and the first
 * version of this file assumed it did.  By the time a C handler runs its
 * own prologue has pushed, and record_and_reset is a second call below
 * that, so MSP points past the frame: it printed pc=00000000 and
 * lr=fffffff9, and 0xfffffff9 is the EXC_RETURN value rather than
 * anything that was on the stack -- a giveaway that the offsets were
 * being applied to the wrong base.
 *
 * So each handler is NAKED and does nothing but pick the right stack
 * pointer -- MSP or PSP, per bit 2 of EXC_RETURN -- and tail-call into C
 * with it.  That is the standard idiom and the only one that survives
 * the compiler choosing its own prologue. */
static void record_and_reset(uint32_t kind, uint32_t a, uint32_t b,
                             const uint32_t *frame)
{
  g_fault[0] = FAULT_MAGIC;
  g_fault[1] = kind;
  g_fault[2] = a;
  g_fault[3] = b;
  __DSB();

  fault_str("\r\n[FAULT] kind=");
  fault_hex(kind);
  fault_str(" a=");
  fault_hex(a);
  fault_str(" b=");
  fault_hex(b);
  fault_str(" sp=");
  fault_hex(__get_MSP());

  if (frame != NULL)
  {
    fault_str(" pc=");
    fault_hex(frame[6]);
    fault_str(" lr=");
    fault_hex(frame[5]);
  }
  fault_str("\r\n");

  NVIC_SystemReset();
}

/* `tst lr, #4` reads bit 2 of EXC_RETURN, which says whether the frame
 * was pushed on the main stack or the process stack, and the IT block
 * picks the matching one into r0 -- the first argument of the C function
 * this tail-branches to.  Naked, so the compiler emits no prologue to
 * move the stack pointer before it is read. */
#define FAULT_ENTRY(name, body)                       \
  __attribute__((naked)) void name(void)              \
  {                                                   \
    __asm volatile("tst lr, #4    \n"                 \
                   "ite eq        \n"                 \
                   "mrseq r0, msp \n"                 \
                   "mrsne r0, psp \n"                 \
                   "b " #body "   \n");               \
  }

void fault_from_nmi(const uint32_t *frame);
void fault_from_nmi(const uint32_t *frame)
{
  record_and_reset(FAULT_NMI, 0U, 0U, frame);
}
FAULT_ENTRY(NMI_Handler, fault_from_nmi)

/* CFSR and HFSR together say what KIND of fault it was; the stacked PC
 * says where.  Both are needed: CFSR alone sent this port reading the
 * whole image for an undefined instruction. */
void fault_from_hard(const uint32_t *frame);
void fault_from_hard(const uint32_t *frame)
{
  record_and_reset(FAULT_HARD, SCB->CFSR, SCB->HFSR, frame);
}
FAULT_ENTRY(HardFault_Handler, fault_from_hard)

/* MemManage_Handler IS DELIBERATELY NOT HERE.
 *
 * sfu_low_level_security.h:299 does
 *     #define SFU_CALLBACK_MEMORYFAULT(void) MemManage_Handler(void)
 * and sfu_boot.c:1592 then defines SFU_CALLBACK_MEMORYFAULT, so ST's own
 * boot module owns this vector and routes it into
 * SFU_EXCPT_IrqExceptionHandler(SFU_EXCPT_MEMORY_FAULT).  That is the
 * right place for it -- a memory fault in SBSFU is a security event, not
 * a crash -- and defining it here as well is a duplicate symbol.
 *
 * Worth leaving the note rather than just the absence: the handler table
 * in startup_stm32l152xe.s has a weak MemManage_Handler, so omitting both
 * would link silently and send a memory fault to the default infinite
 * loop. */

void fault_from_bus(const uint32_t *frame);
void fault_from_bus(const uint32_t *frame)
{
  record_and_reset(FAULT_HARD, SCB->CFSR, SCB->BFAR, frame);
}
FAULT_ENTRY(BusFault_Handler, fault_from_bus)

void fault_from_usage(const uint32_t *frame);
void fault_from_usage(const uint32_t *frame)
{
  record_and_reset(FAULT_HARD, SCB->CFSR, 0U, frame);
}
FAULT_ENTRY(UsageFault_Handler, fault_from_usage)

/* Nothing in this bootloader issues SVC: there is no privilege boundary
 * to cross, which is the same reason se_low_level.h leaves the MPU
 * isolation off.  Reaching here means an unexpected instruction stream,
 * so it is recorded rather than ignored. */
void fault_from_svc(const uint32_t *frame);
void fault_from_svc(const uint32_t *frame)
{
  record_and_reset(FAULT_HARD, 0x53564300UL, 0U, frame);
}
FAULT_ENTRY(SVC_Handler, fault_from_svc)

void DebugMon_Handler(void)
{
}

void PendSV_Handler(void)
{
}

void SysTick_Handler(void)
{
  HAL_IncTick();
}
