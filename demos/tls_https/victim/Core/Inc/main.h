/**
  ******************************************************************************
  * @file    main.h
  * @brief   Header for main.c -- OSCORE flash-timing victim (NUCLEO-F429ZI).
  ******************************************************************************
  * Derived from STM32CubeF4
  * Projects/STM32F429ZI-Nucleo/Applications/LwIP/LwIP_HTTP_Server_Netconn_RTOS.
  * Copyright (c) 2017 STMicroelectronics. Licensed under the terms in the
  * LICENSE file of that software component.
  ******************************************************************************
  */
#ifndef __MAIN_H
#define __MAIN_H

#include "stm32f4xx_hal.h"

/* Static addressing on the direct attacker<->victim link.
   192.168.7.10/24 victim, 192.168.7.20 attacker. */
#define IP_ADDR0   ((uint8_t)192U)
#define IP_ADDR1   ((uint8_t)168U)
#define IP_ADDR2   ((uint8_t)7U)
#define IP_ADDR3   ((uint8_t)10U)

#define NETMASK_ADDR0   ((uint8_t)255U)
#define NETMASK_ADDR1   ((uint8_t)255U)
#define NETMASK_ADDR2   ((uint8_t)255U)
#define NETMASK_ADDR3   ((uint8_t)0U)

#define GW_ADDR0   ((uint8_t)192U)
#define GW_ADDR1   ((uint8_t)168U)
#define GW_ADDR2   ((uint8_t)7U)
#define GW_ADDR3   ((uint8_t)1U)

/* MAC address comes from stm32f4xx_hal_conf.h (ETH_MAC_ADDR0..5). */

void uart_puts(const char *s);
void uart_puthex32(uint32_t v);
void uart_putdec(uint32_t v);
int  uart_getchar_nb(void);

#endif /* __MAIN_H */
