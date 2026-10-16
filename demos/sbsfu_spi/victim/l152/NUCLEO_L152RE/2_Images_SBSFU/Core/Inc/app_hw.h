/**
  ******************************************************************************
  * @file    app_hw.h
  * @brief   Board hooks, NUCLEO-L152RE.
  *
  * ST's version calls their board BSP's BSP_PB_Init / BSP_PB_GetState.  This
  * port reads the pin directly instead, so that STM32L1xx_Nucleo -- a whole
  * second BSP, with LED and COM abstractions nothing here calls -- does not
  * have to be built for one GPIO read.
  *
  * B1 on a NUCLEO-64 is PC13, and it is ACTIVE LOW: UM1724 wires it to
  * ground through SB17 with a pull-up to VDD, so a push reads 0.  That
  * matches the sense of ST's BUTTON_PUSHED, which also compares against
  * GPIO_PIN_RESET, so sfu_boot.c's use of it is unchanged.
  *
  * WHAT SBSFU DOES WITH IT: the local loader is entered when the button is
  * held at boot (sfu_boot.c).  That is the path a firmware image is staged
  * over, so it is the one the attacker's own tooling uses too -- worth
  * knowing when reading a capture, because a run that began with the
  * button held took a different route into the same decrypt loop.
  ******************************************************************************
  */
#ifndef APP_HW_H
#define APP_HW_H

#ifdef __cplusplus
extern "C" {
#endif

#define BUTTON_GPIO_PORT      GPIOC
#define BUTTON_GPIO_PIN       GPIO_PIN_13

/* THE STATUS LED.
 *
 * sfu_boot.c and sfu_com_loader.c call BSP_LED_Init / BSP_LED_Toggle /
 * BSP_LED_Off with SFU_STATUS_LED, which app_sfu.h defines as LED_GREEN --
 * a constant from ST's board BSP.  Rather than build STM32L1xx_Nucleo for
 * four calls, the four are macros here.
 *
 * LD2 on a NUCLEO-64 is PA5, active high, and it is the board's only user
 * LED, so LED_GREEN is the only value these ever receive; the parameter is
 * accepted and ignored so ST's call sites compile unchanged.
 *
 * THIS MATTERS FOR A CAPTURE, in one specific way worth writing down.  The
 * local loader TOGGLES this LED while waiting for a YMODEM packet
 * (sfu_com_loader.c:247).  PA5 is also Arduino D13 and is a GPIO write in
 * the middle of the download loop -- not in the decrypt loop, which is
 * what is timed, so it does not touch the measurement.  If a later
 * experiment moves the status LED onto a pin the probe watches, that
 * stops being true. */
#define LED_GREEN             (0U)     /* the only LED; ST's name for it */
#define LED_GPIO_PORT         GPIOA
#define LED_GPIO_PIN          GPIO_PIN_5

/* `static inline` functions rather than macros, and that is forced rather
 * than preferred.  ST's call sites read `(void) BSP_LED_Init(LED_GREEN);`
 * -- the result is cast, so the name has to be an EXPRESSION.  The SAM D21
 * port used a comma expression because its pin setup is three register
 * writes; HAL_GPIO_Init needs a GPIO_InitTypeDef to fill in first, which a
 * comma expression cannot declare.  A do/while block is a statement and
 * fails on the cast with "expected expression before 'do'".
 *
 * They return uint8_t 0 for the same reason: ST's BSP returns a status and
 * the call sites discard it. */
static inline uint8_t BSP_LED_Init(uint32_t led)
{
  GPIO_InitTypeDef l_init;

  (void)led;
  __HAL_RCC_GPIOA_CLK_ENABLE();
  l_init.Pin   = LED_GPIO_PIN;
  l_init.Mode  = GPIO_MODE_OUTPUT_PP;
  l_init.Pull  = GPIO_NOPULL;
  l_init.Speed = GPIO_SPEED_LOW;
  HAL_GPIO_Init(LED_GPIO_PORT, &l_init);
  return 0U;
}

static inline uint8_t BSP_LED_On(uint32_t led)
{
  (void)led;
  HAL_GPIO_WritePin(LED_GPIO_PORT, LED_GPIO_PIN, GPIO_PIN_SET);
  return 0U;
}

static inline uint8_t BSP_LED_Off(uint32_t led)
{
  (void)led;
  HAL_GPIO_WritePin(LED_GPIO_PORT, LED_GPIO_PIN, GPIO_PIN_RESET);
  return 0U;
}

static inline uint8_t BSP_LED_Toggle(uint32_t led)
{
  (void)led;
  HAL_GPIO_TogglePin(LED_GPIO_PORT, LED_GPIO_PIN);
  return 0U;
}

/* Exported macros -----------------------------------------------------------*/
#define BUTTON_INIT()                                                     \
  do {                                                                    \
    GPIO_InitTypeDef b_init;                                              \
    __HAL_RCC_GPIOC_CLK_ENABLE();                                         \
    b_init.Pin   = BUTTON_GPIO_PIN;                                       \
    b_init.Mode  = GPIO_MODE_INPUT;                                       \
    b_init.Pull  = GPIO_PULLUP;                                           \
    b_init.Speed = GPIO_SPEED_LOW;                                        \
    HAL_GPIO_Init(BUTTON_GPIO_PORT, &b_init);                             \
  } while (0)

#define BUTTON_PUSHED()                                                   \
  ((uint32_t)HAL_GPIO_ReadPin(BUTTON_GPIO_PORT, BUTTON_GPIO_PIN) ==       \
   (uint32_t)GPIO_PIN_RESET)

#ifdef __cplusplus
}
#endif

#endif /* APP_HW_H */
