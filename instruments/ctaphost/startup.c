/* Minimal Cortex-M4 startup for STM32F429ZI (classic memory map). */
#include <stdint.h>
#include "stm32f4xx.h"

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
int main(void);

void Reset_Handler(void) {
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;           /* copy .data from flash */
    for (dst = &_sbss; dst < &_ebss; ) *dst++ = 0;   /* zero .bss */
    SCB->VTOR = 0x08000000u;
    SCB->CPACR |= (0xFu << 20);                       /* enable FPU (CP10/CP11) */
    __asm volatile ("dsb; isb");
    main();
    for (;;) {}
}

void Default_Handler(void) { for (;;) {} }

__attribute__((section(".isr_vector"), used))
void (* const g_vectors[64])(void) = {
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
