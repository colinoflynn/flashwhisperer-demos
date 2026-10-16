/**
  ******************************************************************************
  * @file    stm32l1xx_it.h
  * @brief   Interrupt handler declarations, NUCLEO-L152RE.
  *
  * The L152's counterpart of ST's 2_Images_SBSFU/Core/Inc/stm32l4xx_it.h.
  * sfu_boot.c includes it by family name, which is the one place in ST's
  * SBSFU sources that cannot be ported by configuration -- see
  * patches/0001-sfu_boot-l1-it-header.patch.
  ******************************************************************************
  */
#ifndef STM32L1xx_IT_H
#define STM32L1xx_IT_H

#ifdef __cplusplus
extern "C" {
#endif

void NMI_Handler(void);
void HardFault_Handler(void);
void MemManage_Handler(void);
void BusFault_Handler(void);
void UsageFault_Handler(void);
void SVC_Handler(void);
void DebugMon_Handler(void);
void PendSV_Handler(void);
void SysTick_Handler(void);

#ifdef __cplusplus
}
#endif

#endif /* STM32L1xx_IT_H */
