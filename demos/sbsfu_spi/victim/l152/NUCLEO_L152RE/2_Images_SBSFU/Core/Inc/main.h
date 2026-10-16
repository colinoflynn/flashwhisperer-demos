/**
  ******************************************************************************
  * @file    main.h
  * @brief   NUCLEO-L152RE.
  *
  * ST's copy is four includes.  Two of them are this board's, and that is
  * the whole difference:
  *
  *     stm32l4xx_hal.h       -> stm32l1xx_hal.h       (ST's, other family)
  *     stm32l475e_iot01.h    -> dropped               (their board BSP)
  *
  * ST's board BSP is dropped rather than replaced because the only thing
  * anything in this tree uses it for is the user button, which app_hw.h
  * handles directly here.  Pulling in STM32L1xx_Nucleo for one GPIO read
  * would add a second BSP with its own LED and COM abstractions that
  * nothing calls.
  ******************************************************************************
  */
#ifndef MAIN_H
#define MAIN_H

/* Includes ------------------------------------------------------------------*/
#include "stm32l1xx_hal.h"
#include "app_sfu.h"
#include "app_hw.h"

#endif /* MAIN_H */
