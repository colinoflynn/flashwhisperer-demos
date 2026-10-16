/**
  ******************************************************************************
  * @file    syscalls.c
  * @brief   newlib retarget, SAM D21 Xplained Pro.
  *
  * SBSFU's TRACE macro is `(void) printf` (sfu_trace.h:48), so every message
  * the bootloader prints goes through newlib, and newlib reaches the outside
  * world through _write().  Linking --specs=nosys.specs supplies a _write
  * that returns -1 and discards everything.
  *
  * That is exactly what happened on this port's first working boot: all six
  * of SBSFU's init stages passed, the state machine ran, and the board said
  * NOTHING -- because ST's entire diagnostic output was going into nosys's
  * bit bucket.  The port's own banner, which calls HAL_UART_Transmit
  * directly, printed fine, which made it look like the UART was working and
  * SBSFU was silent.  Both halves of that were true and the conclusion was
  * still wrong.
  *
  * ST does the same retarget in
  * 2_Images_SBSFU/STM32CubeIDE/Application/Core/syscalls.c; this is the SAM
  * D21's version of it.
  ******************************************************************************
  */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "samd21_hal.h"

/** Everything written to stdout or stderr goes to the EDBG virtual COM port.
  * fd is ignored beyond that: a bootloader has no file system, and sending
  * stderr somewhere else would only hide errors. */
int _write(int file, char *ptr, int len)
{
  (void)file;

  if ((ptr == 0) || (len <= 0))
  {
    return 0;
  }
  (void)HAL_UART_Transmit((const uint8_t *)ptr, (uint16_t)len, 1000U);
  return len;
}

int _read(int file, char *ptr, int len)
{
  /* Nothing reads through stdio.  The YMODEM loader uses
     SFU_LL_UART_Receive directly, because it needs per-call timeouts that
     stdio cannot express. */
  (void)file;
  (void)ptr;
  (void)len;
  return 0;
}

int _close(int file)
{
  (void)file;
  return -1;
}

int _fstat(int file, struct stat *st)
{
  (void)file;
  st->st_mode = S_IFCHR;
  return 0;
}

int _isatty(int file)
{
  (void)file;
  return 1;
}

int _lseek(int file, int ptr, int dir)
{
  (void)file;
  (void)ptr;
  (void)dir;
  return 0;
}

void _exit(int status)
{
  (void)status;
  for (;;)
  {
  }
}

int _kill(int pid, int sig)
{
  (void)pid;
  (void)sig;
  errno = EINVAL;
  return -1;
}

int _getpid(void)
{
  return 1;
}
