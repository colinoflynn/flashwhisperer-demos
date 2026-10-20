/*
 * OPTIONAL. Time RIOT's link-security call on the victim itself.
 *
 * Not part of the attack: the capture host never reads this and the demo's
 * vector was taken from a build without it. See OPTIONAL_DWT_PATCH.md.
 *
 * Add to the Makefile:
 *     SRC += optional_dwt/crypto_stamp.c
 *     LINKFLAGS += -Wl,--wrap=ieee802154_sec_encrypt_frame
 *
 * It adds no AES calls and prints nothing on the send path. The campaign's
 * own version of this file also carried a 64-repeat amplifier; that is
 * deliberately NOT here, because an amplified victim is a different
 * experiment and must never be quoted as this one.
 */
/* Measure the RIOT link-security call without printing on its send path. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cpu.h"
#include "net/ieee802154_security.h"
#include "shell.h"

#define CRYPTO_CAPACITY 512

typedef struct {
    uint32_t frame_counter;
    uint32_t cycles;
    uint16_t payload_size;
    int result;
} crypto_stamp_t;

static volatile crypto_stamp_t _crypto[CRYPTO_CAPACITY];
static volatile unsigned _crypto_count;

extern int __real_ieee802154_sec_encrypt_frame(ieee802154_sec_context_t *ctx,
                                                const uint8_t *header,
                                                uint8_t *header_size,
                                                uint8_t *payload,
                                                uint16_t payload_size,
                                                uint8_t *mic,
                                                uint8_t *mic_size,
                                                const uint8_t *src_address);

int __wrap_ieee802154_sec_encrypt_frame(ieee802154_sec_context_t *ctx,
                                        const uint8_t *header,
                                        uint8_t *header_size,
                                        uint8_t *payload,
                                        uint16_t payload_size,
                                        uint8_t *mic,
                                        uint8_t *mic_size,
                                        const uint8_t *src_address)
{
    uint32_t counter = ctx->frame_counter;
    uint32_t start = DWT->CYCCNT;
    int result = __real_ieee802154_sec_encrypt_frame(ctx, header, header_size,
                                                       payload, payload_size, mic,
                                                       mic_size, src_address);
    uint32_t cycles = DWT->CYCCNT - start;
    unsigned i = _crypto_count;
    if (i < CRYPTO_CAPACITY) {
        _crypto[i].frame_counter = counter;
        _crypto[i].cycles = cycles;
        _crypto[i].payload_size = payload_size;
        _crypto[i].result = result;
        _crypto_count = i + 1;
    }
    return result;
}

static int _cryptodump(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "clear") == 0) {
        _crypto_count = 0;
        puts("crypto cleared");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "dump") == 0) {
        unsigned count = _crypto_count;
        printf("crypto count=%u freq=64000000\n", count);
        for (unsigned i = 0; i < count; i++) {
            printf("%u,%" PRIu32 ",%" PRIu32 ",%u,%d\n", i,
                   _crypto[i].frame_counter, _crypto[i].cycles,
                   _crypto[i].payload_size, _crypto[i].result);
        }
        return 0;
    }
    puts("usage: cryptodump clear|dump");
    return 1;
}

SHELL_COMMAND(cryptodump, "clear/dump link-security call cycles", _cryptodump);
