/* ATSAMD21J18A startup for the SBSFU port bring-up image.
 *
 * Cortex-M0+ (ARMv6-M).  The table below IS the live exception table: the
 * SAM D21 boots with VTOR at 0x00000000, so these words are fetched out of
 * flash directly.  Sixteen system vectors then 28 peripheral vectors (EIC,
 * NVMCTRL, DMAC, USB, EVSYS, SERCOM0..5, TCC0..2, TC3..7, ADC, AC, DAC, PTC,
 * I2S).
 *
 * TWO DIFFERENCES FROM rigs/fw_samd21_aes/startup.c, WHICH THIS WAS COPIED
 * FROM, AND THE FIRST ONE COST A DEBUG SESSION
 * --------------------------------------------------------------------------
 * 1. THE SysTick SLOT POINTS AT SysTick_Handler, NOT AT Default_Handler.
 *    The AES rig runs interrupts-off throughout and installs no handler, so
 *    every slot there is the default spin and that is correct for it.  This
 *    image calls HAL_Init(), which calls SysTick_Config(), which ENABLES THE
 *    SysTick INTERRUPT -- and with the AES rig's table the first tick, 1 ms
 *    in, vectored straight into Default_Handler's `for(;;)`.  The symptom was
 *    a mailbox frozen at whatever step happened to be running when the
 *    millisecond elapsed, which looked exactly like the SPI driver hanging.
 *
 *    Copying a startup file between rigs is safe only while the two make the
 *    same assumption about interrupts.  These two do not.
 *
 * 2. THE FAULT HANDLERS RECORD RATHER THAN SPIN.  A bring-up image whose
 *    failure mode is an indistinguishable infinite loop makes every bug look
 *    like the same bug.  HardFault and any unexpected vector now write a
 *    marker, the exception number and the stacked PC into the mailbox's
 *    reserved tail, which the host prints -- so "hung in the SPI driver" and
 *    "took a fault in the SPI driver" stop being the same observation.
 */
#include <stdint.h>

extern uint32_t _etext, _sdata, _edata, _sbss, _ebss, _estack;
int  main(void);
void Reset_Handler(void);
void SysTick_Handler(void);

/* Mailbox tail.  main.c owns words 0..23; the linker reserves 0x80 bytes, so
 * 24..27 are free and are not cleared by main.c's init loop, which stops at
 * 32 -- see the note in main.c.  Kept in sync by the ASSERT in link.ld only
 * for the .bss boundary, not for this split, so: words 24..27 are FAULT ONLY. */
#define FAULT_MARK   (*(volatile uint32_t *)0x20000060UL)
#define FAULT_IPSR   (*(volatile uint32_t *)0x20000064UL)
#define FAULT_PC     (*(volatile uint32_t *)0x20000068UL)
#define FAULT_LR     (*(volatile uint32_t *)0x2000006CUL)

/* Every exception in this image is taken from thread mode on the main stack,
 * so the stacked frame is at MSP: {R0,R1,R2,R3,R12,LR,PC,xPSR}, PC at +24. */
__attribute__((used)) void Fault_Record(void)
{
    uint32_t msp;
    __asm volatile("mrs %0, msp" : "=r"(msp));
    FAULT_MARK = 0xFA017000UL;
    __asm volatile("mrs %0, ipsr" : "=r"(FAULT_IPSR));
    FAULT_PC = *(volatile uint32_t *)(msp + 24U);
    FAULT_LR = *(volatile uint32_t *)(msp + 20U);
    for (;;) {}
}

static void Default_Handler(void) { Fault_Record(); }

/* SysTick is weak here so samd21_hal.c's definition wins at link time; if the
 * HAL is ever built out, an enabled SysTick still lands somewhere that says
 * so instead of running off into the peripheral vectors. */
__attribute__((weak)) void SysTick_Handler(void) { Fault_Record(); }

__attribute__((section(".vectors"), used))
void (* const vectors[])(void) = {
    (void (*)(void))&_estack,   /* 0x00: initial SP     */
    Reset_Handler,              /* 0x04: reset          */
    Default_Handler,            /* NMI                  */
    Default_Handler,            /* HardFault            */
    0, 0, 0, 0, 0, 0, 0,
    Default_Handler,            /* SVC                  */
    0, 0,
    Default_Handler,            /* PendSV               */
    SysTick_Handler,            /* SysTick              */
    /* SAM D21 peripheral interrupts 0..27 */
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
};

void Reset_Handler(void)
{
    uint32_t *s = &_etext, *d = &_sdata;
    while (d < &_edata) *d++ = *s++;
    for (d = &_sbss; d < &_ebss; ) *d++ = 0;
    FAULT_MARK = 0;
    main();
    for (;;) {}
}
