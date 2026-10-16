/* Minimal Cortex-M4 startup for the STM32F303RET6 (NUCLEO-F303RE).
 *
 * Deliberately does NOT include a CMSIS device header, for the reason
 * rigs/fw_f303_aes/startup.c gives: rigs/cmsis/ carries stm32f303xc.h but no
 * stm32f303xe.h, and building with -DSTM32F303xC would compile -- the
 * peripherals are laid out the same -- while putting the wrong part number
 * in a build whose whole premise is which die it is.  The handful of
 * registers used here are declared by hand.
 *
 * No interrupt handler is installed beyond the faults.  The capture path is
 * timer + DMA with no interrupt at all, which is the point: an ISR's entry
 * jitter is the same order as the signal being measured.
 */
#include <stdint.h>

#define REG32(a) (*(volatile uint32_t *)(a))
#define SCB_VTOR  REG32(0xE000ED08u)

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
int main(void);

void Reset_Handler(void)
{
    uint32_t *src = &_sidata, *dst = &_sdata;

    while (dst < &_edata) *dst++ = *src++;           /* .data from flash */
    for (dst = &_sbss; dst < &_ebss; ) *dst++ = 0;   /* zero .bss        */

    SCB_VTOR = 0x08000000u;
    __asm volatile ("dsb; isb");
    main();
    for (;;) {}
}

void Default_Handler(void) { for (;;) {} }

__attribute__((section(".isr_vector"), used))
void (* const g_vectors[16])(void) = {
    (void (*)(void))(&_estack),   /* 0  initial SP  */
    Reset_Handler,                /* 1  reset       */
    Default_Handler,              /* 2  NMI         */
    Default_Handler,              /* 3  HardFault   */
    Default_Handler,              /* 4  MemManage   */
    Default_Handler,              /* 5  BusFault    */
    Default_Handler,              /* 6  UsageFault  */
    0, 0, 0, 0,                   /* 7-10 reserved  */
    Default_Handler,              /* 11 SVCall      */
    Default_Handler,              /* 12 DebugMon    */
    0,                            /* 13 reserved    */
    Default_Handler,              /* 14 PendSV      */
    Default_Handler,              /* 15 SysTick     */
};
