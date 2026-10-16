/**
  ******************************************************************************
  * @file    main.c
  * @brief   OSCORE (CoAP/RFC 8613) server on NUCLEO-F429ZI -- the VICTIM of the
  *          flash T-table timing attack demonstrated in demo/oscore/.
  ******************************************************************************
  * Structure, clock tree, ETH/LwIP bring-up and HAL usage are taken verbatim
  * from STM32CubeF4's
  *   Projects/STM32F429ZI-Nucleo/Applications/LwIP/LwIP_HTTP_Server_Netconn_RTOS
  * with the single change that LwIP runs in its NO_SYS=1 raw-API mode (the
  * STM32CubeMX default when FreeRTOS is not selected) instead of under FreeRTOS.
  * Copyright (c) 2017 STMicroelectronics -- see that component's LICENSE file.
  *
  * Everything security-relevant is off-the-shelf and left at its default:
  *   - OSCORE:  uoscore-uedhoc (eriptic), AES-CCM-16-64-128 + HKDF-SHA-256,
  *              the RFC 8613 Appendix C.1 security context.
  *   - AES:     TinyCrypt (the AES MCUboot/Zephyr link), 256 B flash S-box.
  *   - Flash:   FLASH->ACR left at the value HAL_Init()/SystemClock_Config()
  *              produce for 180 MHz -- 5 wait states, prefetch + I-cache +
  *              D-cache enabled. That is the chip default, not a weakening.
  ******************************************************************************
  */
#include "main.h"
#include <string.h>
#include "ethernetif.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"
#include "snmp_agent.h"

struct netif gnetif;                       /* network interface structure */
static UART_HandleTypeDef huart3;          /* ST-LINK VCP, 115200 8N1 */

static void SystemClock_Config(void);
static void Netif_Config(void);
static void Console_Config(void);

int main(void)
{
  /* STM32F4xx HAL library initialization */
  HAL_Init();

  /* Configure the system clock to 180 MHz */
  SystemClock_Config();

#ifdef VICTIM_WAITSTATES
  /* Amplify the channel for feasibility tests, without changing anything else.
   * The collision channel is a flash miss/hit penalty, so its size scales with
   * the wait-state count: more wait states, bigger dip, fewer traces needed.
   * Running with MORE wait states than the clock requires is always safe (just
   * slower), so this is a legitimate knob for asking "does this path work at
   * all" before committing to a long capture at the realistic setting.
   *
   * RM0090 s3.5.1: the caches must be RESET, not merely disabled, when
   * reconfiguring -- ICRST/DCRST are writable only while the cache is off.
   * Skipping that leaves stale lines alive across the change, which silently
   * invalidated a 24-cell matrix in this project once already. */
  {
    uint32_t v = (FLASH->ACR & ~0x0Fu) | ((uint32_t)(VICTIM_WAITSTATES) & 0x0Fu);
    FLASH->ACR = v & ~(0x200u | 0x400u);          /* caches off, keep latency */
    for (volatile int q = 0; q < 10; q++) {}
    FLASH->ACR |= (0x800u | 0x1000u);             /* ICRST | DCRST */
    for (volatile int q = 0; q < 10; q++) {}
    FLASH->ACR &= ~(0x800u | 0x1000u);
    for (volatile int q = 0; q < 10; q++) {}
    FLASH->ACR = v;
    (void)FLASH->ACR;
  }
#endif

  Console_Config();
  uart_puts("\r\n\r\n=== snmpv3-victim (NUCLEO-F429ZI) ===\r\n");
  uart_puts("SYSCLK  = "); uart_putdec(HAL_RCC_GetHCLKFreq()); uart_puts(" Hz\r\n");
  uart_puts("FLASH_ACR = 0x"); uart_puthex32(FLASH->ACR); uart_puts("\r\n");

  /* SAY WHICH BUILD THIS IS, AT RUNTIME.
   *
   * The Makefile prints the AES table addresses when it links, which is the
   * right place to catch a link-time accident but tells you nothing about the
   * image a board is actually RUNNING -- and a drag-drop flash to the ST-LINK
   * volume silently does nothing often enough on this bench that "I copied it"
   * is not evidence. The S-box's offset within a 16-byte flash line moves the
   * attack's trace cost by 2-4x (research/FINDINGS_LEDGER.md), so a capture
   * attributed to the wrong build is worse than no capture.
   *
   * It cannot print FSb's address directly: mbedTLS declares the table static,
   * so it has internal linkage and nothing outside aes.c can take its address
   * -- and patching vendored SDK source is exactly what this demo must not do,
   * since "compiled as they ship" is the claim being made. So the Makefile
   * stamps the pad it built with, and the chain runs: the link-time print says
   * which address that pad put FSb at, and this says which pad is executing.
   * Both halves are needed; neither alone identifies a running board. */
  uart_puts("RODATA_PAD = "); uart_putdec(BUILD_RODATA_PAD);
  uart_puts("  (see the build's own AES table print for the FSb address)\r\n");

  /* Initialize the LwIP stack (NO_SYS=1) */
  lwip_init();
  Netif_Config();

  /* Off-the-shelf OSCORE/CoAP endpoint */
  snmp_agent_init();

  for (;;)
  {
    /* Read a received packet from the Ethernet buffers and send it to the
       lwIP stack for handling. Interrupt-driven: RxPktPending is set by
       HAL_ETH_RxCpltCallback. */
    if (RxPktPending)
    {
      ethernetif_input(&gnetif);
    }

    /* Handle timeouts and the (slow) link-state / erratum housekeeping. */
    sys_check_timeouts();

    {
      static uint32_t last_link = 0;
      uint32_t now = HAL_GetTick();
      if ((now - last_link) >= 100U)
      {
        last_link = now;
        ethernet_link_check_state(&gnetif);
        ethernetif_rmii_watchdog();
      }
    }

    snmp_agent_poll();
  }
}

/**
  * @brief  Configures the network interface (static IP on the direct link).
  */
static void Netif_Config(void)
{
  ip4_addr_t ipaddr, netmask, gw;

  IP4_ADDR(&ipaddr,  IP_ADDR0,      IP_ADDR1,      IP_ADDR2,      IP_ADDR3);
  IP4_ADDR(&netmask, NETMASK_ADDR0, NETMASK_ADDR1, NETMASK_ADDR2, NETMASK_ADDR3);
  IP4_ADDR(&gw,      GW_ADDR0,      GW_ADDR1,      GW_ADDR2,      GW_ADDR3);

  netif_add(&gnetif, &ipaddr, &netmask, &gw, NULL, &ethernetif_init, &netif_input);
  netif_set_default(&gnetif);

  if (netif_is_link_up(&gnetif))
  {
    netif_set_up(&gnetif);
  }
  else
  {
    netif_set_down(&gnetif);
  }
}

/**
  * @brief  System Clock Configuration -- verbatim from the ST LwIP example.
  *         HSE (8 MHz, ST-LINK MCO bypass) -> PLL -> 180 MHz, 5 flash WS.
  */
static void SystemClock_Config(void)
{
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;

  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 360;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) { while (1) {} }

  if (HAL_PWREx_EnableOverDrive() != HAL_OK) { while (1) {} }

  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1  | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK) { while (1) {} }
}

/* --------------------------------------------------------------------------
 * ST-LINK VCP console (USART3, PD8/PD9 -- the Nucleo-144 wiring).
 * Status/telemetry only; it is never used inside a timed region.
 * ----------------------------------------------------------------------- */
static void Console_Config(void)
{
  GPIO_InitTypeDef g = {0};

  __HAL_RCC_GPIOD_CLK_ENABLE();
  __HAL_RCC_USART3_CLK_ENABLE();

  g.Pin = GPIO_PIN_8 | GPIO_PIN_9;
  g.Mode = GPIO_MODE_AF_PP;
  g.Pull = GPIO_PULLUP;
  g.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  g.Alternate = GPIO_AF7_USART3;
  HAL_GPIO_Init(GPIOD, &g);

  huart3.Instance = USART3;
  huart3.Init.BaudRate = 115200;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  HAL_UART_Init(&huart3);
}

void uart_puts(const char *s)
{
  HAL_UART_Transmit(&huart3, (uint8_t *)s, (uint16_t)strlen(s), 1000);
}

int uart_getchar_nb(void)
{
  if (USART3->SR & USART_SR_RXNE) { return (int)(USART3->DR & 0xFF); }
  return -1;
}

void uart_puthex32(uint32_t v)
{
  static const char HEX[] = "0123456789abcdef";
  char b[9];
  int i;
  for (i = 0; i < 8; i++) { b[i] = HEX[(v >> (28 - 4 * i)) & 0xF]; }
  b[8] = 0;
  uart_puts(b);
}

void uart_putdec(uint32_t v)
{
  char b[12];
  int n = 0;
  if (!v) { uart_puts("0"); return; }
  while (v) { b[n++] = (char)('0' + v % 10); v /= 10; }
  {
    char o[12];
    int i;
    for (i = 0; i < n; i++) { o[i] = b[n - 1 - i]; }
    o[n] = 0;
    uart_puts(o);
  }
}

#ifdef  USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
  (void)file; (void)line;
  while (1) {}
}
#endif
