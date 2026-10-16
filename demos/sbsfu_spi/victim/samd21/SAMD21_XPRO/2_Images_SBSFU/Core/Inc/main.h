/**
  ******************************************************************************
  * @file    main.h
  * @brief   SAM D21 Xplained Pro.
  *
  * ST's version of this file, for the B-L475E-IOT01A, is four includes:
  *
  *     #include "stm32l4xx_hal.h"
  *     #include "stm32l475e_iot01.h"
  *     #include "app_sfu.h"
  *     #include "app_hw.h"
  *
  * The last two are unchanged here.  The first two are the vendor HAL and the
  * vendor board support, and this port substitutes its own -- which is the
  * entire STM32 dependency of the SBSFU application layer, expressed in two
  * lines.  Everything that made porting look large turned out to live behind
  * these.
  ******************************************************************************
  */
#ifndef MAIN_H
#define MAIN_H

#include <stddef.h>          /* NULL: ST's sources get it from Cube's
                               header chain, which this port replaces */
#include "samd21.h"
#include "samd21_hal.h"
#include "app_sfu.h"
#include "app_hw.h"

/* The Cube spellings ST's sources expect -- UNUSED, assert_param,
 * HAL_MAX_DELAY, __weak -- in one place, because se_low_level.h needs them
 * too and reaches them by a different include chain. */
#include "samd21_cube_compat.h"

/* sfu_boot.c defines the Cube HAL tamper callback
 *     void SFU_CALLBACK_ANTITAMPER(RTC_HandleTypeDef *hrtc)
 * and immediately UNUSED()s its argument.  The type has to exist for the
 * file to compile; it does not have to be complete, and deliberately is not.
 *
 * An INCOMPLETE type is the honest declaration here.  A fabricated struct
 * with plausible STM32 fields would compile identically and would suggest
 * this port has an RTC handle to pass -- it has neither an RTC in the STM32
 * sense nor a tamper input, SFU_TAMPER_PROTECT_ENABLE is off, and nothing
 * ever calls this callback.  Leaving the type incomplete means any future
 * code that tries to dereference one fails to compile, which is the correct
 * outcome. */
typedef struct RTC_HandleTypeDef_does_not_exist_on_this_part RTC_HandleTypeDef;

#endif /* MAIN_H */
