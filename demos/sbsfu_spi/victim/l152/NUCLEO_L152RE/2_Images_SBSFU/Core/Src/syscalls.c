/**
  ******************************************************************************
  * @file    syscalls.c
  * @brief   newlib retarget, NUCLEO-L152RE.
  *
  * SBSFU's TRACE macro is `(void) printf` (sfu_trace.h:48), so every message
  * the bootloader prints goes through newlib, and newlib reaches the outside
  * world through _write().  Linking --specs=nosys.specs supplies a _write
  * that returns -1 and discards everything.
  *
  * That is exactly what this port's first working boot looked like: the
  * state machine ran, the YMODEM loader came up and started polling with
  * 'C', and the board printed no text at all -- because ST's entire
  * diagnostic output was going into nosys's bit bucket.  The port's own
  * banner, which calls SFU_LL_UART_Transmit directly, printed fine, which
  * made it look like the UART was working and SBSFU was simply silent.
  * Both halves of that were true and the conclusion was still wrong.
  *
  * It is not only cosmetic.  The YMODEM sender keys on ST's prompt string
  * -- "File> Transfer> YMODEM> Send" -- rather than on a bare 'C', because
  * 'C' is ordinary ASCII that also appears in the boot banner and a sender
  * watching for the byte alone starts transmitting into the middle of a
  * message.  With printf discarded the prompt never arrives and no image
  * can be staged at all.
  *
  * ST does the same retarget in
  * 2_Images_SBSFU/STM32CubeIDE/Application/Core/syscalls.c; this is the
  * L152's version of it, routed through the same UART the port's own
  * output uses so the two cannot disagree about baud or pins.
  ******************************************************************************
  */
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "main.h"
#include "sfu_low_level.h"

/** Everything written to stdout or stderr goes to the ST-LINK virtual COM
  * port.  fd is ignored beyond that: a bootloader has no file system, and
  * sending stderr somewhere else would only hide errors. */
int _write(int file, char *ptr, int len)
{
  (void)file;

  if ((ptr == NULL) || (len <= 0))
  {
    return 0;
  }
  (void)SFU_LL_UART_Transmit((uint8_t *)ptr, (uint16_t)len, 1000U);
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
