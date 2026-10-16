/**
  ******************************************************************************
  * @file    samd21_cube_compat.h
  * @brief   The STM32Cube spellings ST's sources use that are Cube
  *          conveniences rather than STM32 features.
  *
  * These live in one header, included by both main.h and se_low_level.h,
  * because ST's files reach them through different include chains:
  * sfu_boot.c gets there via main.h, se_crypto_bootloader.c only ever
  * includes se_low_level.h.  Defining them twice would work until the two
  * copies disagreed -- and a UNUSED() that expands differently in two
  * translation units is the kind of difference that shows up as a link
  * error at best.
  *
  * Each of these is a macro in STM32Cube too.  None of them is a port
  * decision; they are spellings.
  ******************************************************************************
  */
#ifndef SAMD21_CUBE_COMPAT_H
#define SAMD21_CUBE_COMPAT_H

/* Cube's "argument deliberately ignored". */
#ifndef UNUSED
#define UNUSED(X) (void)(X)
#endif

/* Cube compiles this away unless USE_FULL_ASSERT is defined.  Nothing in
   this port defines it. */
#ifndef assert_param
#define assert_param(expr) ((void)0U)
#endif

/* Cube's "wait forever" sentinel, same value. */
#ifndef HAL_MAX_DELAY
#define HAL_MAX_DELAY  (0xFFFFFFFFU)
#endif

/* Cube spells __attribute__((weak)) this way. */
#ifndef __weak
#define __weak   __attribute__((weak))
#endif

#endif /* SAMD21_CUBE_COMPAT_H */
