/* Assert that SFU_IMG_CHUNK_SIZE really is what the Makefile's CHUNK says,
 * AS ST'S SOURCES RESOLVE IT.
 *
 * `make chunkcheck` copies this file into $(BUILD)/src/ -- the staging
 * directory ST's own .c files are compiled from -- and syntax-checks it
 * there.  The location is the entire point.  A quoted #include searches the
 * including file's own directory before any -I, so a probe compiled anywhere
 * else would resolve sfu_fwimg_internal.h differently from the way
 * sfu_fwimg_no_swap.c does, pass, and prove nothing.
 *
 * This exists because the build was wrong in exactly that way: ST's sources
 * were compiled in ST's own App/ directory, their `#include
 * "sfu_fwimg_internal.h"` found ST's copy sitting next to them, and this
 * port's copy -- the one that makes the chunk size configurable -- was never
 * read.  CHUNK=64 and CHUNK=512 produced byte-identical objects while the
 * build reported success.  The chunk size is the single most important
 * number in this demo; it is not something to take on trust from a
 * -D on a command line.
 */
/* The include prelude is sfu_fwimg_no_swap.c's, lines 24-33, verbatim and in
 * the same order.  Matching it is not tidiness: sfu_fwimg_internal.h depends
 * on types from several of these, and more importantly the probe is only
 * meaningful if it reaches sfu_fwimg_internal.h by the same route the real
 * file does. */
#include <string.h>
#include "main.h"
#include "sfu_fsm_states.h"
#include "sfu_error.h"
#include "sfu_low_level_flash_int.h"
#include "sfu_low_level_security.h"
#include "se_interface_bootloader.h"
#include "sfu_fwimg_regions.h"
#include "sfu_fwimg_services.h"
#include "sfu_fwimg_internal.h"

#ifndef CHUNK_EXPECTED
#error "chunkprobe.c must be compiled with -DCHUNK_EXPECTED=<n>; use `make chunkcheck`"
#endif

_Static_assert(SFU_IMG_CHUNK_SIZE == CHUNK_EXPECTED,
               "SFU_IMG_CHUNK_SIZE is not CHUNK -- the override header was "
               "not the one ST's sources saw.  Check the include search "
               "order and the staging rule in the Makefile.");

/* A chunk that is not a whole number of AES blocks would silently truncate
 * the last block of every read.  ST's own comment on SFU_IMG_CHUNK_SIZE
 * requires 16-byte alignment for exactly this reason; the Makefile checks it
 * too, and checking twice costs nothing. */
_Static_assert((SFU_IMG_CHUNK_SIZE % 16U) == 0U,
               "SFU_IMG_CHUNK_SIZE must be a multiple of the AES block size");
