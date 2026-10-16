/**
  ******************************************************************************
  * @file    app_hw.h
  * @brief   Board-specific hooks, SAM D21 Xplained Pro.
  *
  * ST's version of this file is two macros wrapping its BSP's push-button
  * calls.  SBSFU uses BUTTON_PUSHED() in sfu_boot.c to decide whether to
  * enter the local loader instead of booting the installed image -- the
  * "hold the button at reset to force an update" behaviour.
  *
  * The SAM D21 Xplained Pro has SW0 on PA15, active low with an external
  * pull-up (user guide Table 4-5).  It is read directly here rather than
  * through a BSP layer, because a BSP whose only customer is one macro is
  * ceremony.
  ******************************************************************************
  */
#ifndef APP_HW_H
#define APP_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#include "samd21.h"

/* SW0, PA15, active low.  PORT group 0 = PORTA. */
#define APP_HW_SW0_PIN        15U

/* INEN so the input buffer is live, PULLEN plus OUT high for the internal
 * pull-up.  The board fits an external pull-up too; enabling the internal one
 * costs nothing and makes the read defined if that resistor is ever depopulated
 * on a later board revision. */
#define BUTTON_INIT()                                                      \
  do {                                                                     \
    PORT->Group[0].DIRCLR.reg  = (1UL << APP_HW_SW0_PIN);                  \
    PORT->Group[0].OUTSET.reg  = (1UL << APP_HW_SW0_PIN);                  \
    PORT->Group[0].PINCFG[APP_HW_SW0_PIN].reg =                            \
      (uint8_t)(PORT_PINCFG_INEN | PORT_PINCFG_PULLEN);                    \
  } while (0)

#define BUTTON_PUSHED()                                                    \
  ((PORT->Group[0].IN.reg & (1UL << APP_HW_SW0_PIN)) == 0UL)

/* ---------------------------------------------------------------- LED ----
 * SBSFU blinks a status LED: solid off on a normal boot, blinking at
 * SFU_STOP_NO_FW_BLINK_DELAY when there is no valid firmware and no local
 * loader.  It calls BSP_LED_Init / BSP_LED_Toggle / BSP_LED_Off with
 * SFU_STATUS_LED, which app_sfu.h defines as LED_GREEN.
 *
 * SAM D21 Xplained Pro: LED0 on PB30, ACTIVE LOW (user guide Table 4-6 --
 * EXT3 pin 5 is PB30, "Onboard LED0").  The active-low sense is why On and
 * Off look inverted below; getting it backwards would make a board with no
 * valid firmware look like a board that booted cleanly, which is the one
 * status distinction this LED exists to make.
 */
#define LED_GREEN             (0U)     /* the only LED; ST's name for it    */
#define APP_HW_LED0_PIN       (30U)    /* PB30, PORT group 1                */
#define APP_HW_LED0_GROUP     (1U)

#define BSP_LED_Init(led)                                                  \
  ((void)(led),                                                            \
   PORT->Group[APP_HW_LED0_GROUP].OUTSET.reg = (1UL << APP_HW_LED0_PIN),   \
   PORT->Group[APP_HW_LED0_GROUP].PINCFG[APP_HW_LED0_PIN].reg = 0U,        \
   PORT->Group[APP_HW_LED0_GROUP].DIRSET.reg = (1UL << APP_HW_LED0_PIN),   \
   0)

#define BSP_LED_On(led)                                                    \
  ((void)(led),                                                            \
   PORT->Group[APP_HW_LED0_GROUP].OUTCLR.reg = (1UL << APP_HW_LED0_PIN), 0)

#define BSP_LED_Off(led)                                                   \
  ((void)(led),                                                            \
   PORT->Group[APP_HW_LED0_GROUP].OUTSET.reg = (1UL << APP_HW_LED0_PIN), 0)

#define BSP_LED_Toggle(led)                                                \
  ((void)(led),                                                            \
   PORT->Group[APP_HW_LED0_GROUP].OUTTGL.reg = (1UL << APP_HW_LED0_PIN), 0)

#ifdef __cplusplus
}
#endif

#endif /* APP_HW_H */
