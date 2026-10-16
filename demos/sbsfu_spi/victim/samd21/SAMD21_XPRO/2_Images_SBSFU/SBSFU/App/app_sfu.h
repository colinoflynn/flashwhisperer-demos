/**
  ******************************************************************************
  * @file    app_sfu.h
  * @author  MCD Application Team
  * @brief   This file contains the configuration of SBSFU application.
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2017 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file in
  * the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef APP_SFU_H
#define APP_SFU_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "se_crypto_config.h"

/* Exported constants --------------------------------------------------------*/
/**
  * Use this define to choose the type of Firmware Image Programming you want to use.
  * This version supports only 2 modes:
  *
  * SFU_ENCRYPTED_IMAGE: Encrypted Firmware Image
  *       The image is received in encrypted format.
  *       The image must be decrypted to be installed:
  *         this is done according to the selected crypto scheme,
  *         see @ref SECBOOT_CRYPTO_SCHEME in the SE_CoreBin part.
  *
  * SFU_CLEAR_IMAGE: Clear Firmware Image
  *       The image is received in clear format.
  *       No decrypt operation is needed before installing the image:
  *         the selected crypto scheme must be compatible with this choice,
  *         see @ref SECBOOT_CRYPTO_SCHEME in the SE_CoreBin part.
  *
  *
  */
#if  SECBOOT_CRYPTO_SCHEME == SECBOOT_ECCDSA_WITHOUT_ENCRYPT_SHA256
#define SFU_IMAGE_PROGRAMMING_TYPE SFU_CLEAR_IMAGE
#else
#define SFU_IMAGE_PROGRAMMING_TYPE SFU_ENCRYPTED_IMAGE
#endif /* SECBOOT_CRYPTO_SCHEME */

#define SFU_ENCRYPTED_IMAGE (0U) /*!< The Firmware Image to be installed is downloaded in ENCRYPTED format */
#define SFU_CLEAR_IMAGE     (1U) /*!< The Firmware Image to be installed is downloaded in CLEAR format */

#define SFU_DEBUG_MODE               /*!< Comment this define to optimize memory footprint (debug mode removed)
                                          No more print on terminal during SBSFU execution */

/* SAM D21 PORT: UNCOMMENTED.  ST ships this off.  On a board where the
   install path fails, the non-verbose trace says only
   "Security issue : execution stopped !" -- which does not say whether
   the header signature, the decrypt pass or the tag check rejected the
   image, and those are three different bugs.  It is a documented
   debug switch and costs only flash.

   BUT IT MUST BE OFF FOR A CAPTURE, and that is not a footprint argument.
   Two of the verbose traces sit INSIDE the decrypt loop, and a trace line
   is ~100 characters at 115200 baud, i.e. about 9 ms of polled UART
   transmission in the middle of an interval whose whole signal is one
   microsecond wide.  It showed up immediately: the first two inter-chunk
   gaps of every capture were 16 ms against a 111.5 us median, from the
   two "[VFY] iter" lines that print for the opening iterations.

   Passing -DPORT_NO_VERBOSE (VERBOSE=0 in the Makefile, which the oracle
   build sets) removes them.  It changes no logic -- every one of those
   traces is a print -- but a build that says it measured the loop must
   not have been printing inside it. */
#ifndef PORT_NO_VERBOSE
#define SFU_VERBOSE_DEBUG_MODE   /*!< Uncomment this define when in verbose Debug mode.
                                          this switch activates more debug prints in the console (FSM state info...) */
#endif /* PORT_NO_VERBOSE */


/*#define SFU_FWIMG_BLOCK_ON_ABNORMAL_ERRORS_MODE*/  /*!< You may uncomment this define when running development tests.
                                                          When this switch is activated, the FWIMG part of SB_SFU will
                                                          block when an abnormal error is encountered */

#if defined(SFU_VERBOSE_DEBUG_MODE) && !defined(SFU_DEBUG_MODE)
#error You cannot activate SFU_VERBOSE_DEBUG_MODE without activating SFU_DEBUG_MODE too.
#endif /* SFU_VERBOSE_DEBUG_MODE && !SFU_DEBUG_MODE */

#if defined(SFU_FWIMG_BLOCK_ON_ABNORMAL_ERRORS_MODE) && !defined(SFU_DEBUG_MODE)
#error SFU_FWIMG_BLOCK_ON_ABNORMAL_ERRORS_MODE is meant to be used in DEBUG mode
#endif /* SFU_FWIMG_BLOCK_ON_ABNORMAL_ERRORS_MODE && !SFU_DEBUG_MODE */

/*#define SFU_TEST_PROTECTION*/       /*!< Auto-test of protections : WRP, PCROP, MPU, FWALL.
                                           Automatically executed @startup */
#if defined(SFU_TEST_PROTECTION)
#undef SFU_DEBUG_MODE                 /*!< Remove definition to optimize memory footprint (debug mode removed) */
#endif /* SFU_TEST_PROTECTION */

/**
  * SB_SFU status LED.
  * The constants below define the LED to be used and the LED blinking frequency to identify some situations.
  * This is useful when no log is enabled.
  *
  * \li The LED blinks every see @ref SFU_COM_YMODEM_DOWNLOAD_TIMEOUT seconds when a local download is waited.
  * \li For the other situations, please check the other defines below.
  */
#define SFU_STATUS_LED (LED_GREEN)            /*!< LED to be used to provide the SB_SFU status to the end-user */
#define SFU_STOP_NO_FW_BLINK_DELAY     (100U) /*!< Blinks every 100ms when no valid firmware is available and the local
                                                   loader feature is disabled - see @ref SECBOOT_USE_LOCAL_LOADER */
#define SFU_INCORRECT_OB_BLINK_DELAY   (250U) /*!< Blinks every 250ms when an Option Bytes issue is detected */


/**
  * Optional Features Software Configuration
  */
#if !defined(SFU_TEST_PROTECTION)
#define SECBOOT_LOADER SECBOOT_USE_LOCAL_LOADER    /*!< Loader selection inside SBSFU : local/standalone/none */
#else
#define SECBOOT_LOADER SECBOOT_USE_NO_LOADER       /*!< No loader usage forced when SFU_TEST_PROTECTION is set */
#endif /* SFU_TEST_PROTECTION */

#define SECBOOT_USE_LOCAL_LOADER              (1U) /*!< local loader feature integrated into SBSFU (YMODEM over UART) */
#define SECBOOT_USE_STANDALONE_LOADER         (2U) /*!< standalone loader : see specific loader project  */
#define SECBOOT_USE_NO_LOADER                 (3U) /*!< no loader capability at SBSFU stage */

/* Uncomment the define below if you want to use minicom with Linux */
/* #define MINICOM_YMODEM */                       /*!< YMODEM protocol handled by MINICOM (Linux): 128 bytes packets */

#if defined(MINICOM_YMODEM)
/* Minicom does not accept the debug prints during the YMODEM session */
#undef SFU_X509_VERBOSE_DEBUG_MODE
#undef SFU_VERBOSE_DEBUG_MODE
#endif /* MINICOM_YMODEM */

/* Swap installation process cannot be configured for this example : the FW downloaded in dwl slot
   must remain encrypted after installation */
#define SFU_NO_SWAP                                /*!< FW upgrade installation process without swap area */

/* Multi-images configuration :
   - Max : 3 Active images and 3 Download area
   - Not necessary same configuration between SFU_NB_MAX_ACTIVE_IMAGE and SFU_NB_MAX_DWL_AREA
   - Active slot identified with SFU magic (1,2,3) information from header
   - Do not forget to add keys for each image in SE_Corebin/Binary folder
   - Master slot : image started in priority if valid
   - FW image valid all feature authorized from master slot
*/
/* SAM D21 PORT: ONE image, not ST's two.  mapping_fwimg.ld configures
   SLOT_ACTIVE_1 and SLOT_DWL_1 and leaves 2 and 3 at zero -- there is not
   enough internal flash on a 256 KB part for two 128 KB active slots
   alongside an 80 KB bootloader.  Leaving the count at 2 does not just
   waste code: se_crypto_bootloader.c then references SE_ReadKey_2 and
   SE_ReadKey_2_Pub, which gen_keys.sh does not emit, so the mismatch
   surfaces as an undefined symbol rather than as a runtime surprise. */
#define SFU_NB_MAX_ACTIVE_IMAGE 1U                        /*!< 1 active image managed */
#define SFU_NB_MAX_DWL_AREA     1U                        /*!< 1 dwl area managed */
#define MASTER_SLOT             SLOT_ACTIVE_1             /*!< SLOT_ACTIVE_1 identified as master slot */


/* The define below allows disabling all security IPs at once.
 *
 * Enabled: all security IPs (WRP, watchdog...) are disabled.
 * Disabled: the security IPs can be used (if their specific compiler switches are enabled too).
 *
 */

/*#define SECBOOT_DISABLE_SECURITY_IPS*/  /*!< Disable all security IPs at once when activated */

#if !defined(SECBOOT_DISABLE_SECURITY_IPS)

/* Uncomment the following defines when in Release mode.
   In debug mode it can be better to disable some of the following protection
   for a better Debug experience (WRP, RDP, IWDG, DAP, etc.) */

/* SAM D21 PORT.  Four of ST's protections are commented out below because the
   hardware they configure does not exist on this part, and two more because
   applying them would fuse off the debug port this demo measures through.
   sfu_low_level_security.c holds the protection-by-protection table and
   #error's if any of the unavailable ones is re-enabled, so this block cannot
   drift out of agreement with what the code actually does. */
#define SFU_WRP_PROTECT_ENABLE     /*!< SAM D21: NVMCTRL region LOCK bits, applied
                                        every boot.  NOT the BOOTPROT fuse -- see
                                        apply_wrp() for why that is left alone. */
/* #define SFU_RDP_PROTECT_ENABLE */
                                   /*!< SAM D21: this is the DSU security bit, which
                                        also disables SWD.  Every measurement this
                                        demo exists to take is made over SWD, and the
                                        board would be recoverable only by chip
                                        erase.  It does not affect the timing channel:
                                        readout protection does not slow the cipher
                                        down and is not on the attacker's path. */
/* #define SFU_FWALL_PROTECT_ENABLE */
                                   /*!< SAM D21: no firewall peripheral exists. */
/* #define SFU_TAMPER_PROTECT_ENABLE */
                                   /*!< SAM D21 Xplained Pro: no tamper input. */
/* #define SFU_DAP_PROTECT_ENABLE */
                                   /*!< SAM D21: the same fuse as RDP above. */
#define SFU_DMA_PROTECT_ENABLE     /*!< SAM D21: the DMAC is disabled at reset and
                                        this bootloader never enables it; the write
                                        makes that explicit. */
#define SFU_IWDG_PROTECT_ENABLE    /*!< WARNING:
                                        1. Be Careful if enabling this protection. IWDG will be active also after
                                           switching to UserApp: a refresh is needed.
                                        2. The IWDG reload in the SB_SFU code will have to be tuned depending on your
                                           platform (flash size...)*/
/* #define SFU_MPU_PROTECT_ENABLE */
                                   /*!< SAM D21: NO MPU IS FITTED.  Measured, not
                                        assumed -- MPU_TYPE at 0xE000ED90 reads 0,
                                        agreeing with samd21j18a.h:223
                                        (__MPU_PRESENT 0).  Secure Engine isolation
                                        is therefore unavailable on this part and
                                        the call gate is an ordinary function call;
                                        mapping_sbsfu.ld says what the SE regions
                                        still mean. */
#if 0                              /*!< ST's original text, kept for reference:
                                        MPU protection:
                                        Enables/Disables the MPU protection.
                                        If Secure Engine isolation is ensured by MPU (see SFU_ISOLATE_SE_WITH_MPU in
                                        SE_CoreBin\Inc\se_low_level.h), then this switch also enables/disables it, in
                                        addition to the overall MPU protection. */
#define SFU_MPU_USERAPP_ACTIVATION /*!< MPU protection during UserApp execution : Only active slot(s) considered as an
                                        executable area */
#endif /* 0 -- SAM D21 has no MPU */


/*#define SFU_FINAL_SECURE_LOCK_ENABLE */   /*!< WARNING: Should be enabled at the end of product development and test
                                                 steps.
                                                 When enabling this lock, Static protections cannot be modified any more
                                                 and Debug is finally disabled. */

#if defined(SFU_FINAL_SECURE_LOCK_ENABLE)
#define SFU_PROTECT_RDP_LEVEL  (OB_RDP_LEVEL_2)  /*!< RDP level2 for product on the field. Final OB lock, Debug
                                                      completely disabled, OB update no more possible  */


#else
#define SFU_PROTECT_RDP_LEVEL  (OB_RDP_LEVEL_1)  /*!< RDP level is set as 1 for debugging purposes. A product on the
                                                      field should set it as Level2 */
#endif /* SFU_FINAL_SECURE_LOCK_ENABLE */

#endif /* !SECBOOT_DISABLE_SECURITY_IPS */

/**
  * The define below (SECBOOT_OB_DEV_MODE) determines if the OPTION BYTES should be handled in Development mode or not.
  * This define is taken into account only if RDP level 2 is not set.
  * If RDP level 2 is set no modification can be done anyway.
  *
  * Enabled: Option Bytes Development Mode enabled.
  *          SB_SFU uses a "check and apply" strategy when checking the Option Bytes configuration.
  *          If an OB is not set though it should be then this setting is automatically corrected.
  *          This applies only as long as RDP level 2 is not set.
  *
  * Disabled: Option Bytes Development Mode disabled.
  *           In this mode the Option Bytes are supposed to be already configured properly when the software starts for
              the first time.
  *           SB_SFU checks the Option Bytes configuration but does not correct it.
  *           If a problem is detected an error message is reported and the execution stops.
  */
#define SECBOOT_OB_DEV_MODE


#define SFU_IWDG_TIMEOUT  ((uint32_t) 6) /*!< IWDG timeout in seconds (the max. value that can be set here depends on
                                              the prescaler settings: IWDG_PRESCALER_XXX. ) */


/**
  * Application Configuration
  *
  */
#define SFU_FW_VERSION_START_NUM (1U)    /*!< The very first version number a Firmware can have
                                              You can also define an upper bound here if you plan to use it */

#define SFU_FW_VERSION_INIT_NUM (1U)     /*!< The version number accepted when the header is not valid (either because
                                              no FW installed or due to an attack attempt). Could be different from
                                              SFU_FW_VERSION_START_NUM */

/**
  * Features compatibility control
  */
#if defined(SFU_NO_SWAP) && defined(ENABLE_IMAGE_STATE_HANDLING)
#warning "ENABLE_IMAGE_STATE_HANDLING not compatible with SFU_NO_SWAP process"
#endif


#ifdef __cplusplus
}
#endif

#endif /* APP_SFU_H */

