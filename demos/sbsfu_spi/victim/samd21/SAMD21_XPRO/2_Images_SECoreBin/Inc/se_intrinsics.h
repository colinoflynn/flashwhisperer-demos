/**
  ******************************************************************************
  * @file    se_intrinsics.h
  * @brief   Port copy of ST's Secure Engine intrinsics, with one change:
  *          get_LR() under GCC.
  ******************************************************************************
  *
  * THIS FILE SHADOWS ST's Middlewares/ST/STM32_Secure_Engine/Core/
  * se_intrinsics.h.  stage_headers.sh puts this copy into build/inc, which
  * the compile line searches BEFORE the middleware directory, so every
  * staged Secure Engine source picks this one up.  ST's file is not
  * modified; ./diff_vs_stock.sh reports the difference.
  *
  * WHAT CHANGED AND WHY
  * --------------------
  * ST's GCC branch reads the live link register:
  *
  *     static inline uint32_t get_LR(void)
  *     {
  *       register uint32_t result;
  *       __asm volatile("MOV %0, LR\n" : "=r"(result));
  *       return (result);
  *     }
  *
  * and __IS_SFU_RESERVED() -- the check every se_interface_bootloader.c
  * entry point runs first -- calls it TWICE:
  *
  *     if ((get_LR()) < SB_REGION_ROM_START) { return SE_ERROR; }
  *     if ((get_LR()) > SB_REGION_ROM_END)   { return SE_ERROR; }
  *
  * That is only correct while LR still holds the caller's return address.
  * Nothing in the C makes the compiler keep it there: the asm has no input
  * or clobber tying it to function entry, get_LR is `static inline` and not
  * `always_inline`, and at -O2 GCC is free to schedule the MOV anywhere in
  * the function -- including after LR has been reused.  It then reads
  * whatever is in LR at that moment, compares a junk value against the
  * SBSFU ROM window, and returns SE_ERROR.
  *
  * On this port that is not hypothetical.  With arm-none-eabi-gcc at -O2 for
  * Cortex-M0+, SE_Decrypt_Append rejected every call from ST's own verify
  * loop -- SFU_IMG_TriggerImageInstallation printed "Fw signature check
  * error" -- while the identical call from main() went through.  The
  * observed LR at the check was 0x20000c48, an SRAM address, which no
  * caller can ever have.  Adding a printf to the wrapper made it work, by
  * changing register allocation; that is the signature of the bug, not a
  * fix.
  *
  * The replacement is __builtin_return_address(0), which is GCC's supported
  * way to ask this question and is computed at function entry regardless of
  * optimisation.  It is a MACRO, not an inline function, deliberately: as an
  * inline function it would answer for get_LR's own frame whenever the
  * compiler chose not to inline it, which is the same class of bug with a
  * quieter failure.  Bit 0 is set (Thumb); the range test is unaffected,
  * since an odd address inside [SB_REGION_ROM_START, SB_REGION_ROM_END] is
  * still inside it.
  *
  * The security property is preserved, and arguably restored: the check is
  * meant to refuse callers outside the SBSFU region, and before this it was
  * refusing callers inside it, at the compiler's discretion.
  *
  * NOT CHANGED HERE: se_callgate.c does the same thing with its own inline
  * asm rather than through get_LR ("register unsigned lr asm(\"lr\")"), for
  * IS_CALLER_SE_IF().  That copy has the same fragility.  It has not
  * misbehaved on this build and it is in a .c file rather than a header, so
  * it is left alone and recorded here instead of fixed silently -- see
  * research/targets/samd21j18a.md.
  *
  ******************************************************************************
  */

#ifndef SE_INTRINSICS_H
#define SE_INTRINSICS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if   defined (__CC_ARM) || defined(__ARMCC_VERSION) || defined (__GNUC__)
#define __root __attribute__((used))
#endif /* __CC_ARM || __ARMCC_VERSION || __GNUC__ */

#if defined(__CC_ARM)
#define __get_SP __current_sp
#elif defined(__GNUC__)
static inline uint32_t __get_SP(void)
{
  register uint32_t sp __asm("sp");
  return sp;
}
#endif /* __CC_ARM */

#if defined(__CC_ARM)
#define get_LR __return_address
#elif defined(__ICCARM__)
#define get_LR __get_LR
#elif defined(__ARMCC_VERSION)
__attribute__((always_inline)) static inline uint32_t get_LR(void)
{
  register uint32_t result;
  __asm volatile("MOV %0, LR" : "=r"(result));
  return result;
}
#elif defined(__GNUC__)
/* See the header comment.  A macro, so it always expands in the caller. */
#define get_LR() ((uint32_t)(uintptr_t)__builtin_return_address(0))
#endif /* __CC_ARM */

#if defined(__ICCARM__)
extern void *__vector_table;
#define SeVectorsTable __vector_table
#elif defined(__CC_ARM) || defined(__ARMCC_VERSION)
extern void *__Vectors;
#define SeVectorsTable __Vectors
#elif defined(__GNUC__)
extern void *g_pfnVectors[];
#define SeVectorsTable g_pfnVectors
#endif /* __ICCARM__ */

#ifdef __cplusplus
}
#endif

#endif /* SE_INTRINSICS_H */
